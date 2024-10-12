/*
** Copyright (c) 2024 Intuitibits LLC
** Author: Adrian Granados <adrian@intuitibits.com>
*/

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define VERSION "2.1.2"

#define NL80211_GENL_FAMILY_NAME "nl80211"
#define NL80211_GENL_GROUP_NAME "scan"

#define MAX_PACKET_SIZE 2048

#define MAX_FREQS 100

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

struct trigger_results {
  int done;
  int aborted;
};

static const uint8_t packet_header[] = {
    // Radiotap header
    0x00, 0x00, 0x0f, 0x00, 0x2a, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0xff,
    // 802.11 frame header
    0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
    // 802.11 beacon header
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
#define PACKET_HEADER_LEN sizeof(packet_header)

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
                         void *arg) {
  int *ret = arg;
  *ret = err->error;
  return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg) {
  int *ret = arg;
  *ret = 0;
  return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg) {
  int *ret = arg;
  *ret = 0;
  return NL_STOP;
}

static int no_seq_check(struct nl_msg *msg, void *arg) { return NL_OK; }

static int callback_trigger(struct nl_msg *msg, void *arg) {

  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct trigger_results *results = arg;

  if (gnlh->cmd == NL80211_CMD_SCAN_ABORTED) {
    results->done = 1;
    results->aborted = 1;
  } else if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS) {
    results->done = 1;
    results->aborted = 0;
  } // else probably an uninteresting multicast message.

  return NL_SKIP;
}

static int callback_dump(struct nl_msg *msg, void *arg) {

  // Called by the kernel for each network found.
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  pcap_dumper_t *dumper = arg;
  static struct pcap_pkthdr header;
  static u_char packet[MAX_PACKET_SIZE];
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct nlattr *bss[NL80211_BSS_MAX + 1];
  static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
      [NL80211_BSS_TSF] = {.type = NLA_U64},
      [NL80211_BSS_FREQUENCY] = {.type = NLA_U32},
      [NL80211_BSS_BSSID] = {},
      [NL80211_BSS_BEACON_INTERVAL] = {.type = NLA_U16},
      [NL80211_BSS_CAPABILITY] = {.type = NLA_U16},
      [NL80211_BSS_SIGNAL_MBM] = {.type = NLA_U32},
      [NL80211_BSS_STATUS] = {.type = NLA_U32},
      [NL80211_BSS_INFORMATION_ELEMENTS] = {},
  };

  // Parse and error check.
  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);
  if (!tb[NL80211_ATTR_BSS]) {
    return NL_SKIP;
  }

  if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS],
                       bss_policy)) {
    return NL_SKIP;
  }

  if (!bss[NL80211_BSS_BSSID])
    return NL_SKIP;
  if (!bss[NL80211_BSS_INFORMATION_ELEMENTS])
    return NL_SKIP;

  // Prepare packet with radiotap and beacon headers.
  memcpy(packet, packet_header, PACKET_HEADER_LEN);

  // Channel frequency
  uint16_t freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
  packet[10] = freq & 0xFF;
  packet[11] = (freq >> 8) & 0xFF;

  // Channel flags
  uint16_t channel_flags = 0x0000;
  if (freq >= 2412 && freq <= 2484) {
    channel_flags = 0x0480;
  } else if (freq >= 5180 && freq < 5885) {
    channel_flags = 0x0140;
  } else if (freq >= 5955 && freq <= 7115) {
    channel_flags = 0x0040;
  }

  packet[12] = channel_flags & 0xFF;
  packet[13] = (channel_flags >> 8) & 0xFF;

  // RSSI
  int rssi = (int)nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]) / 100;
  packet[14] = rssi & 0xFF;

  // Transmitter address and BSSID
  u_char *bssid = nla_data(bss[NL80211_BSS_BSSID]);
  memcpy(&packet[25], bssid, nla_len(bss[NL80211_BSS_BSSID]));
  memcpy(&packet[31], bssid, nla_len(bss[NL80211_BSS_BSSID]));

  // Beacon TSF
  uint64_t beacon_tsf = nla_get_u64(bss[NL80211_BSS_TSF]);
  for (int i = 0; i < 8; i++) {
    packet[39 + i] = (beacon_tsf >> (i * 8)) & 0xFF;
  }

  // Beacon interval
  uint16_t beacon_int = nla_get_u16(bss[NL80211_BSS_BEACON_INTERVAL]);
  packet[47] = beacon_int & 0xFF;
  packet[48] = (beacon_int >> 8) & 0xFF;

  // Beacon capability
  uint16_t beacon_cap = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);
  packet[49] = beacon_cap & 0xFF;
  packet[50] = (beacon_cap >> 8) & 0xFF;

  // IEs
  u_char *ie_data = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
  int ie_data_len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
  int payload_len = min(ie_data_len, MAX_PACKET_SIZE - PACKET_HEADER_LEN);
  memcpy(packet + PACKET_HEADER_LEN, ie_data, payload_len);

  // Update pcap header with final length values.
  header.caplen = PACKET_HEADER_LEN + payload_len;
  header.len = PACKET_HEADER_LEN + ie_data_len;
  gettimeofday(&(header.ts), NULL);

  // Write packet out.
  pcap_dump((u_char *)dumper, &header, (u_char *)packet);

  return NL_SKIP;
}

int do_scan_trigger(struct nl_sock *socket, int if_index, int genl_id, int passive, int freqs[], int num_freqs) {

  // Starts the scan and waits for it to finish.
  // Does not return until the scan is done or has been aborted.
  struct trigger_results results = {.done = 0, .aborted = 0};
  struct nl_msg *msg;
  struct nl_cb *cb;

  int err;
  int ret;
  int mcid = genl_ctrl_resolve_grp(socket, NL80211_GENL_FAMILY_NAME,
                                   NL80211_GENL_GROUP_NAME);
  nl_socket_add_membership(socket, mcid);

  // Allocate the message and callback handler.
  msg = nlmsg_alloc();
  if (!msg) {
    fprintf(stderr, "nl80211: failed to allocate netlink message\n");
    return -ENOMEM;
  }

  cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!cb) {
    fprintf(stderr, "nl80211: failed to allocate netlink callback\n");
    nlmsg_free(msg);
    return -ENOMEM;
  }

  // Setup the message and callback handlers.
  genlmsg_put(msg, 0, 0, genl_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);

  // Configure desired interface.
  nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);

  // Configure active or passive scan.
  // If passive, omit NL80211_ATTR_SCAN_SSIDS, otherwise, set a NULL SSID.
  if (!passive) {
    struct nlattr *ssids_attr = nla_nest_start(msg, NL80211_ATTR_SCAN_SSIDS);
    nla_put(msg, 1, 0, NULL); // NULL SSID
    nla_nest_end(msg, ssids_attr);
  }

  // Configure scan frequencies (MHz).
  if (num_freqs > 0) {
    struct nlattr *freq_attr = nla_nest_start(msg, NL80211_ATTR_SCAN_FREQUENCIES);
    for (int i = 0; i < num_freqs; i++) {
      nla_put_u32(msg, i + 1, freqs[i]);
    }
    nla_nest_end(msg, freq_attr);
  }

  // Configure callbacks.
  nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, callback_trigger, &results);
  nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
  nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
  nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);

  // Send NL80211_CMD_TRIGGER_SCAN to start the scan.
  // The kernel may reply with NL80211_CMD_NEW_SCAN_RESULTS on success or
  // NL80211_CMD_SCAN_ABORTED if another scan was started by another process.
  err = 1;
  ret = nl_send_auto(socket, msg); // Send the message.

  while (err > 0)
    ret = nl_recvmsgs(
        socket,
        cb); // First wait for ack_handler(). This helps with basic errors.
  if (ret < 0) {
    fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(-ret), err);
    return err;
  }

  while (!results.done)
    nl_recvmsgs(socket, cb);
  if (results.aborted) {
    fprintf(stderr, "nl80211: scan aborted\n");
  }

  // Cleanup
  nlmsg_free(msg);
  nl_cb_put(cb);
  nl_socket_drop_membership(socket, mcid);
  return 0;
}

void print_usage(const char *program_name)
{
  printf("Usage: %s [-c count] [-f frequency-list] [-p] [-h] [--version] <interface> <filename>\n", program_name);
  printf("Options:\n");
  printf("  -c, --count         Exit after the specified number of scans\n");
  printf("  -f, --frequency     Comma-separated list of frequencies in MHz to scan\n");
  printf("  -p, --passive       Use passive scan mode\n");
  printf("  -h, --help          Display this help message\n");
  printf("  --version           Show version\n");
}

int main(int argc, char *argv[]) {

  struct nl_sock *socket;
  int opt, err;
  char *endptr;
  pcap_t *handle;
  pcap_dumper_t *dumper = NULL;
  int linktype = DLT_IEEE802_11_RADIO;
  int snaplen = 65535;

  int version_flag = 0;
  int use_passive = 0;
  char* frequency_list = NULL;
  int freqs[MAX_FREQS];
  int count = 0;

  struct option long_options[] = {
    {"count", required_argument, 0, 'c'},
    {"frequency", required_argument, 0, 'f'},
    {"passive", no_argument, 0, 'p'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, &version_flag, 1},
    {0, 0, 0, 0}
  };

  while ((opt = getopt_long(argc, argv, "c:f:ph", long_options, NULL)) != -1) {
    switch (opt) {
      case 'c':
        errno = 0;
        count = strtol(optarg, &endptr, 10);
        if (errno != 0 || *endptr != '\0') {
          fprintf(stderr, "invalid count: %s\n", optarg);
          exit(EXIT_FAILURE);
        }
        break;
      case 'f':
        frequency_list = optarg;
        break;
      case 'p':
        use_passive = 1;
        break;
      case 'h':
          // Display help message
          print_usage(basename(argv[0]));
          exit(EXIT_SUCCESS);
          break;
      case '?':
        // Handle unknown or missing options
        print_usage(basename(argv[0]));
        exit(EXIT_FAILURE);
        break;
    }
  }

  if (version_flag) {
    printf("%s version %s\n", basename(argv[0]), VERSION);
    exit(EXIT_SUCCESS);
  }

  // Process frequency list argument
  int num_freqs = 0;
  if (frequency_list) {
    char *token = strtok(frequency_list, ",");
    while (token != NULL) {

      if (num_freqs >= MAX_FREQS) {
        fprintf(stderr, "max number of frequencies is: %d\n", MAX_FREQS);
        exit(EXIT_FAILURE);
      }

      int freq = strtol(token, &endptr, 10);
      if (errno != 0 || *endptr != '\0') {
        fprintf(stderr, "invalid frequency: %s\n", token);
        exit(EXIT_FAILURE);
      }

      freqs[num_freqs++] = freq;
      token = strtok(NULL, ",");
    }
  }

  // Process interface and filename arguments
  if (optind + 2 != argc) {
    print_usage(basename(argv[0]));
    exit(EXIT_FAILURE);
  }

  int if_index = if_nametoindex(argv[optind]);
  char *file = argv[optind + 1];

  socket = nl_socket_alloc();
  if (!socket) {
    fprintf(stderr, "nl80211: %s (%d)\n", strerror(errno), errno);
    return -1;
  }

  err = genl_connect(socket);
  if (err < 0) {
    fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(err), err);
    nl_socket_free(socket);
    return -1;
  }

  int genl_id = genl_ctrl_resolve(socket, NL80211_GENL_FAMILY_NAME);
  if (genl_id < 0) {
    fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(genl_id), genl_id);
    nl_socket_free(socket);
    return -1;
  }

  // Create pcap handle
  handle = pcap_open_dead(linktype, snaplen);
  if (!handle) {
    fprintf(stderr, "libpcap: error creating pcap handle\n");
    nl_socket_free(socket);
    return -1;
  }

  int n = 0;
  while ((count == 0) || (n < count)) {

    // Trigger scan and wait for it to finish
    int err = do_scan_trigger(socket, if_index, genl_id, use_passive, freqs, num_freqs);

    if (err != 0) {
      // Errors -16 (-EBUSY), -25 (-ENOTTY), or -33 (-EDOM)
      // can happen for various reasons when doing a scan
      // but we can simply retry.
      if (err == -EBUSY || err == -ENOTTY || err == -EDOM) {
        sleep(2);
        continue;
      }

      // Other errors are not expected, so we quit.
      return err;
    }

    // Open pcap file if needed if first scan is successful.
    if (dumper == NULL) {
      if (strcmp(file, "-") == 0) {
        dumper = pcap_dump_fopen(handle, stdout);
      } else {
        dumper = pcap_dump_open(handle, file);
      }

      if (!dumper) {
        fprintf(stderr, "libpcap: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        nl_socket_free(socket);
        return -1;
      }
    }

    // Dump networks found into file.
    struct nl_msg *msg = nlmsg_alloc();
    genlmsg_put(msg, 0, 0, genl_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, callback_dump,
                        dumper);
    int ret = nl_send_auto(socket, msg);
    ret = nl_recvmsgs_default(socket);
    nlmsg_free(msg);

    if (ret < 0) {
      fprintf(stderr, "warning: %s (%d)\n", nl_geterror(-ret), ret);
    }

    pcap_dump_flush(dumper);
    n++;
  }

  pcap_dump_close(dumper);
  pcap_close(handle);

  return 0;
}
