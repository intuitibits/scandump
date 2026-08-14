/*
** Copyright (c) 2024 Intuitibits LLC
** Author: Adrian Granados <adrian@intuitibits.com>
*/

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <pcap.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define VERSION "2.1.5"

#define NL80211_GENL_FAMILY_NAME "nl80211"
#define NL80211_GENL_GROUP_NAME "scan"

#define MAX_PACKET_SIZE 2048

#define MAX_FREQS 100

// How long to wait for a netlink message before giving up, so a driver that
// never reports scan completion can't hang us indefinitely.
#define NL_RECV_TIMEOUT_SEC 30

// Consecutive transient trigger failures tolerated before giving up
// (2 seconds apart, so roughly a minute of retrying).
#define MAX_TRANSIENT_RETRIES 30

// Length of a BSSID (an 802.11 MAC address), in bytes.
#define SCANDUMP_BSSID_LEN 6

// Generous sane bounds for a center frequency in MHz: comfortably covers
// 2.4/5/6 GHz and 802.11ad (~60 GHz) while rejecting garbage and overflow.
#define SCANDUMP_MIN_FREQ_MHZ 1
#define SCANDUMP_MAX_FREQ_MHZ 100000

// Bounded strtol: parses `str` as a base-10 integer and stores it in `*out`.
// Rejects empty input, trailing garbage, strtol overflow, and values outside
// [min_val, max_val]. Returns 0 on success, -1 on failure. Prints nothing;
// the caller reports the error with the context it has.
static int parse_long_strict(const char *str, long min_val, long max_val,
                             long *out) {

  if (str == NULL || out == NULL || *str == '\0') {
    return -1;
  }

  char *endptr = NULL;
  errno = 0;
  long value = strtol(str, &endptr, 10);
  if (errno != 0 || endptr == str || *endptr != '\0') {
    return -1;
  }

  if (value < min_val || value > max_val) {
    return -1;
  }

  *out = value;
  return 0;
}

// Parses a comma-separated list of frequencies in MHz into `freqs`, rejecting
// invalid, out-of-range and duplicate entries as well as lists longer than
// `max_freqs`. Mutates `list` in place (strtok_r semantics). On success
// returns 0 and stores the number of parsed frequencies in `*num_freqs_out`;
// on failure prints a diagnostic to stderr and returns -1.
static int parse_frequency_list(char *list, int *freqs, int max_freqs,
                                int *num_freqs_out) {

  if (list == NULL || freqs == NULL || num_freqs_out == NULL ||
      max_freqs <= 0) {
    return -1;
  }

  int num_freqs = 0;
  char *saveptr = NULL;
  *num_freqs_out = 0;

  for (char *token = strtok_r(list, ",", &saveptr); token != NULL;
       token = strtok_r(NULL, ",", &saveptr)) {

    long freq;
    if (parse_long_strict(token, SCANDUMP_MIN_FREQ_MHZ, SCANDUMP_MAX_FREQ_MHZ,
                          &freq) < 0) {
      fprintf(stderr, "invalid frequency: %s\n", token);
      return -1;
    }

    if (num_freqs >= max_freqs) {
      fprintf(stderr, "max number of frequencies is: %d\n", max_freqs);
      return -1;
    }

    for (int i = 0; i < num_freqs; i++) {
      if (freqs[i] == (int)freq) {
        fprintf(stderr, "duplicate frequency: %s\n", token);
        return -1;
      }
    }

    freqs[num_freqs++] = (int)freq;
  }

  if (num_freqs == 0) {
    fprintf(stderr, "empty frequency list\n");
    return -1;
  }

  *num_freqs_out = num_freqs;
  return 0;
}

// Radiotap channel flags for a given center frequency (MHz). Returns 0 for
// frequencies outside the known 2.4/5/6 GHz ranges.
static uint16_t channel_flags_for_frequency(uint32_t freq_mhz) {

  if (freq_mhz >= 2412 && freq_mhz <= 2484) {
    return 0x0480;
  } else if (freq_mhz >= 5180 && freq_mhz < 5885) {
    return 0x0140;
  } else if (freq_mhz >= 5955 && freq_mhz <= 7115) {
    return 0x0040;
  }

  return 0x0000;
}

// Clamps an already-divided dBm value into the range representable by the
// radiotap signed 8-bit signal field.
static int8_t clamp_rssi_dbm(long dbm) {

  if (dbm < INT8_MIN) {
    return INT8_MIN;
  }
  if (dbm > INT8_MAX) {
    return INT8_MAX;
  }

  return (int8_t)dbm;
}

// How many bytes of an `ie_len`-byte information element blob fit after a
// `header_len`-byte packet header in a `max_packet_size`-byte buffer. Returns
// 0 (rather than underflowing) if the header does not fit at all.
static size_t compute_ie_payload_len(size_t ie_len, size_t max_packet_size,
                                     size_t header_len) {

  if (header_len >= max_packet_size) {
    return 0;
  }

  size_t available = max_packet_size - header_len;
  return ie_len < available ? ie_len : available;
}

struct trigger_results {
  int done;
  int aborted;
};

// Set from SIGINT/SIGTERM to request a clean shutdown.
static volatile sig_atomic_t g_stop = 0;

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

static void handle_stop_signal(int signum) {
  (void)signum;
  g_stop = 1;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
                         void *arg) {
  (void)nla;
  int *ret = arg;
  *ret = err->error;
  return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg) {
  (void)msg;
  int *ret = arg;
  *ret = 0;
  return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg) {
  (void)msg;
  int *ret = arg;
  *ret = 0;
  return NL_STOP;
}

static int no_seq_check(struct nl_msg *msg, void *arg) {
  (void)msg;
  (void)arg;
  return NL_OK;
}

// Waits until the netlink socket has a message to read. Returns 0 when it is
// readable, -ETIMEDOUT if the wait expired, -ECANCELED if a stop signal was
// received, or -errno on an unexpected poll() failure. Signals other than
// SIGINT/SIGTERM simply restart the wait.
static int nl_wait_readable(struct nl_sock *sk, int timeout_sec) {

  struct pollfd pfd = {.fd = nl_socket_get_fd(sk), .events = POLLIN};

  for (;;) {
    if (g_stop) {
      return -ECANCELED;
    }

    int pret = poll(&pfd, 1, timeout_sec * 1000);
    if (pret > 0) {
      return 0;
    }
    if (pret == 0) {
      return -ETIMEDOUT;
    }
    if (errno == EINTR) {
      // poll() is not restarted by SA_RESTART; loop back so a stop signal is
      // noticed and any other signal just resumes waiting.
      continue;
    }

    return -errno;
  }
}

static void report_recv_error(int err) {

  if (err == -ETIMEDOUT) {
    fprintf(stderr, "nl80211: timed out after %d seconds waiting for a reply\n",
            NL_RECV_TIMEOUT_SEC);
  } else if (err != -ECANCELED) {
    fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(err), err);
  }
}

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
      [NL80211_BSS_BSSID] = {.type = NLA_UNSPEC},
      [NL80211_BSS_BEACON_INTERVAL] = {.type = NLA_U16},
      [NL80211_BSS_CAPABILITY] = {.type = NLA_U16},
      [NL80211_BSS_SIGNAL_MBM] = {.type = NLA_U32},
      [NL80211_BSS_STATUS] = {.type = NLA_U32},
      [NL80211_BSS_INFORMATION_ELEMENTS] = {.type = NLA_UNSPEC},
  };

  // Parse and error check.
  if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                genlmsg_attrlen(gnlh, 0), NULL) < 0) {
    return NL_SKIP;
  }

  if (!tb[NL80211_ATTR_BSS]) {
    return NL_SKIP;
  }

  if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS],
                       bss_policy)) {
    return NL_SKIP;
  }

  if (!bss[NL80211_BSS_BSSID] ||
      !bss[NL80211_BSS_FREQUENCY] ||
      !bss[NL80211_BSS_SIGNAL_MBM] ||
      !bss[NL80211_BSS_TSF] ||
      !bss[NL80211_BSS_BEACON_INTERVAL] ||
      !bss[NL80211_BSS_CAPABILITY] ||
      !bss[NL80211_BSS_INFORMATION_ELEMENTS])
  {
    return NL_SKIP;
  }

  // The BSSID attribute is unspecified/unvalidated by the parse policy above,
  // so its length has to be checked before it is copied into the packet.
  if (nla_len(bss[NL80211_BSS_BSSID]) != SCANDUMP_BSSID_LEN) {
    return NL_SKIP;
  }

  int ie_data_len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
  if (ie_data_len < 0) {
    return NL_SKIP;
  }

  // Prepare packet with radiotap and beacon headers.
  memcpy(packet, packet_header, PACKET_HEADER_LEN);

  // Channel frequency
  uint32_t freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
  packet[10] = freq & 0xFF;
  packet[11] = (freq >> 8) & 0xFF;

  // Channel flags
  uint16_t channel_flags = channel_flags_for_frequency(freq);
  packet[12] = channel_flags & 0xFF;
  packet[13] = (channel_flags >> 8) & 0xFF;

  // RSSI
  int32_t signal_mbm = (int32_t)nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
  packet[14] = (u_char)clamp_rssi_dbm(signal_mbm / 100);

  // Transmitter address and BSSID
  u_char *bssid = nla_data(bss[NL80211_BSS_BSSID]);
  memcpy(&packet[25], bssid, SCANDUMP_BSSID_LEN);
  memcpy(&packet[31], bssid, SCANDUMP_BSSID_LEN);

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
  size_t payload_len = compute_ie_payload_len((size_t)ie_data_len,
                                              MAX_PACKET_SIZE,
                                              PACKET_HEADER_LEN);
  memcpy(packet + PACKET_HEADER_LEN, ie_data, payload_len);

  // Update pcap header with final length values.
  header.caplen = (bpf_u_int32)(PACKET_HEADER_LEN + payload_len);
  header.len = (bpf_u_int32)(PACKET_HEADER_LEN + (size_t)ie_data_len);
  gettimeofday(&(header.ts), NULL);

  // Write packet out.
  pcap_dump((u_char *)dumper, &header, (u_char *)packet);

  return NL_SKIP;
}

static int do_scan_trigger(struct nl_sock *sk, int if_index, int genl_id,
                           int passive, int freqs[], int num_freqs) {

  // Starts the scan and waits for it to finish.
  // Does not return until the scan is done, has been aborted, has failed,
  // has timed out, or a stop signal was received.
  struct trigger_results results = {.done = 0, .aborted = 0};
  struct nl_msg *msg = NULL;
  struct nl_cb *cb = NULL;
  struct nlattr *nest = NULL;
  int mcid = 0;
  int joined = 0;
  int err = 0;
  int ret = 0;

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

  // Setup the message. This is done before joining the scan multicast group
  // so that a failure here needs no membership cleanup.
  if (!genlmsg_put(msg, 0, 0, genl_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0)) {
    fprintf(stderr, "nl80211: failed to build scan request\n");
    ret = -ENOMEM;
    goto cleanup;
  }

  // Configure desired interface.
  ret = nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
  if (ret < 0) {
    fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(ret), ret);
    goto cleanup;
  }

  // Configure active or passive scan.
  // If passive, omit NL80211_ATTR_SCAN_SSIDS, otherwise, set a NULL SSID.
  if (!passive) {
    nest = nla_nest_start(msg, NL80211_ATTR_SCAN_SSIDS);
    if (!nest) {
      fprintf(stderr, "nl80211: failed to build scan request\n");
      ret = -ENOMEM;
      goto cleanup;
    }
    ret = nla_put(msg, 1, 0, NULL); // NULL SSID
    if (ret < 0) {
      fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(ret), ret);
      goto cleanup;
    }
    nla_nest_end(msg, nest);
  }

  // Configure scan frequencies (MHz).
  if (num_freqs > 0) {
    nest = nla_nest_start(msg, NL80211_ATTR_SCAN_FREQUENCIES);
    if (!nest) {
      fprintf(stderr, "nl80211: failed to build scan request\n");
      ret = -ENOMEM;
      goto cleanup;
    }
    for (int i = 0; i < num_freqs; i++) {
      ret = nla_put_u32(msg, i + 1, freqs[i]);
      if (ret < 0) {
        fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(ret), ret);
        goto cleanup;
      }
    }
    nla_nest_end(msg, nest);
  }

  // Join the multicast group the scan completion event is delivered on.
  mcid = genl_ctrl_resolve_grp(sk, NL80211_GENL_FAMILY_NAME,
                               NL80211_GENL_GROUP_NAME);
  if (mcid < 0) {
    fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(mcid), mcid);
    ret = mcid;
    goto cleanup;
  }

  ret = nl_socket_add_membership(sk, mcid);
  if (ret < 0) {
    fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(ret), ret);
    goto cleanup;
  }
  joined = 1;

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
  ret = nl_send_auto(sk, msg); // Send the message.
  if (ret < 0) {
    fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(ret), ret);
    goto cleanup;
  }

  // First wait for ack_handler()/error_handler(). This helps with basic errors.
  while (err > 0) {
    ret = nl_wait_readable(sk, NL_RECV_TIMEOUT_SEC);
    if (ret < 0) {
      report_recv_error(ret);
      goto cleanup;
    }

    ret = nl_recvmsgs(sk, cb);
    if (ret < 0) {
      fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(ret), ret);
      goto cleanup;
    }
  }

  // The kernel's verdict on the trigger request is in err, set by
  // error_handler(); the loop above only establishes that a reply arrived.
  // Check err explicitly rather than relying on nl_recvmsgs()'s return value:
  // waiting for scan results after a NACK (e.g. -EBUSY when another process
  // is already scanning) would wait forever, since no scan was started.
  if (err < 0) {
    fprintf(stderr, "nl80211: %s (%d)\n", strerror(-err), err);
    ret = err;
    goto cleanup;
  }

  // Then wait for the scan to complete or be aborted.
  while (!results.done) {
    ret = nl_wait_readable(sk, NL_RECV_TIMEOUT_SEC);
    if (ret < 0) {
      report_recv_error(ret);
      goto cleanup;
    }

    ret = nl_recvmsgs(sk, cb);
    if (ret < 0) {
      fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(ret), ret);
      goto cleanup;
    }
  }

  if (results.aborted) {
    fprintf(stderr, "nl80211: scan aborted\n");
  }

  ret = 0;

cleanup:
  nlmsg_free(msg);
  nl_cb_put(cb);
  if (joined) {
    nl_socket_drop_membership(sk, mcid);
  }

  return ret;
}

static void print_usage(const char *program_name)
{
  printf("Usage: %s [-c count] [-f frequency-list] [-p] [-h] [--version] <interface> <filename>\n", program_name);
  printf("Options:\n");
  printf("  -c, --count         Exit after the specified number of scans\n");
  printf("  -f, --frequency     Comma-separated list of frequencies in MHz to scan\n");
  printf("  -p, --passive       Use passive scan mode\n");
  printf("  -h, --help          Display this help message\n");
  printf("  --version           Show version\n");
}

// Opens the output file for writing, refusing to follow a symlink at the
// final path component and keeping the scan results owner-readable only.
static FILE *open_output_file(const char *file) {

  int fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
  if (fd < 0) {
    fprintf(stderr, "%s: %s\n", file, strerror(errno));
    return NULL;
  }

  FILE *fp = fdopen(fd, "w");
  if (!fp) {
    fprintf(stderr, "%s: %s\n", file, strerror(errno));
    close(fd);
    return NULL;
  }

  return fp;
}

int main(int argc, char *argv[]) {

  struct nl_sock *sk = NULL;
  int opt, err;
  pcap_t *handle = NULL;
  pcap_dumper_t *dumper = NULL;
  int linktype = DLT_IEEE802_11_RADIO;
  int snaplen = 65535;
  int exit_code = 0;

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
      case 'c': {
        long value;
        if (parse_long_strict(optarg, 0, INT_MAX, &value) < 0) {
          fprintf(stderr, "invalid count: %s\n", optarg);
          exit(EXIT_FAILURE);
        }
        count = (int)value;
        break;
      }
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
  if (frequency_list &&
      parse_frequency_list(frequency_list, freqs, MAX_FREQS, &num_freqs) < 0) {
    exit(EXIT_FAILURE);
  }

  // Process interface and filename arguments
  if (optind + 2 != argc) {
    print_usage(basename(argv[0]));
    exit(EXIT_FAILURE);
  }

  errno = 0;
  int if_index = (int)if_nametoindex(argv[optind]);
  if (if_index == 0) {
    fprintf(stderr, "%s: %s\n", argv[optind],
            errno != 0 ? strerror(errno) : "no such interface");
    exit(EXIT_FAILURE);
  }

  char *file = argv[optind + 1];
  int to_stdout = (strcmp(file, "-") == 0);

  // Handle Ctrl-C and SIGTERM so a scan in progress can be interrupted and
  // the output file closed cleanly.
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_stop_signal;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGINT, &sa, NULL) < 0 || sigaction(SIGTERM, &sa, NULL) < 0) {
    fprintf(stderr, "sigaction: %s\n", strerror(errno));
    return -1;
  }

  sk = nl_socket_alloc();
  if (!sk) {
    fprintf(stderr, "nl80211: %s (%d)\n", strerror(errno), errno);
    return -1;
  }

  err = genl_connect(sk);
  if (err < 0) {
    fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(err), err);
    exit_code = -1;
    goto cleanup;
  }

  int genl_id = genl_ctrl_resolve(sk, NL80211_GENL_FAMILY_NAME);
  if (genl_id < 0) {
    fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(genl_id), genl_id);
    exit_code = -1;
    goto cleanup;
  }

  // Create pcap handle
  handle = pcap_open_dead(linktype, snaplen);
  if (!handle) {
    fprintf(stderr, "libpcap: error creating pcap handle\n");
    exit_code = -1;
    goto cleanup;
  }

  int n = 0;
  int transient_retries = 0;
  while (((count == 0) || (n < count)) && !g_stop) {

    // Trigger scan and wait for it to finish
    int trigger_err = do_scan_trigger(sk, if_index, genl_id, use_passive,
                                      freqs, num_freqs);

    if (g_stop) {
      break;
    }

    if (trigger_err != 0) {
      // Errors -16 (-EBUSY), -25 (-ENOTTY), or -33 (-EDOM)
      // can happen for various reasons when doing a scan
      // but we can simply retry. So can a timeout waiting for the kernel.
      if (trigger_err == -EBUSY || trigger_err == -ENOTTY ||
          trigger_err == -EDOM || trigger_err == -ETIMEDOUT) {
        if (++transient_retries > MAX_TRANSIENT_RETRIES) {
          fprintf(stderr,
                  "nl80211: giving up after %d consecutive transient errors\n",
                  MAX_TRANSIENT_RETRIES);
          exit_code = -1;
          goto cleanup;
        }
        sleep(2);
        if (g_stop) {
          break;
        }
        continue;
      }

      // Other errors are not expected, so we quit.
      exit_code = trigger_err;
      goto cleanup;
    }

    transient_retries = 0;

    // Open pcap file if needed if first scan is successful.
    if (dumper == NULL) {
      if (to_stdout) {
        dumper = pcap_dump_fopen(handle, stdout);
      } else {
        FILE *fp = open_output_file(file);
        if (!fp) {
          exit_code = -1;
          goto cleanup;
        }
        // On failure libpcap closes the stream itself, so it must not be
        // closed here; the process exits right away in that case anyway.
        dumper = pcap_dump_fopen(handle, fp);
      }

      if (!dumper) {
        fprintf(stderr, "libpcap: %s\n", pcap_geterr(handle));
        exit_code = -1;
        goto cleanup;
      }
    }

    // Dump networks found into file.
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
      fprintf(stderr, "nl80211: failed to allocate netlink message\n");
      exit_code = -1;
      goto cleanup;
    }

    if (!genlmsg_put(msg, 0, 0, genl_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN,
                     0)) {
      fprintf(stderr, "nl80211: failed to build scan results request\n");
      nlmsg_free(msg);
      exit_code = -1;
      goto cleanup;
    }

    int ret = nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    if (ret < 0) {
      fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(ret), ret);
      nlmsg_free(msg);
      exit_code = -1;
      goto cleanup;
    }

    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, callback_dump, dumper);
    ret = nl_send_auto(sk, msg);
    if (ret < 0) {
      fprintf(stderr, "warning: %s (%d)\n", nl_geterror(ret), ret);
    } else {
      ret = nl_wait_readable(sk, NL_RECV_TIMEOUT_SEC);
      if (ret < 0) {
        report_recv_error(ret);
      } else {
        ret = nl_recvmsgs_default(sk);
        if (ret < 0) {
          fprintf(stderr, "warning: %s (%d)\n", nl_geterror(ret), ret);
        }
      }
    }
    nlmsg_free(msg);

    // Only flush when streaming to stdout, where a consumer is waiting for
    // the data; file output is flushed by pcap_dump_close().
    if (to_stdout) {
      pcap_dump_flush(dumper);
    }

    n++;
  }

cleanup:
  if (dumper) {
    pcap_dump_close(dumper);
  }
  if (handle) {
    pcap_close(handle);
  }
  if (sk) {
    nl_socket_free(sk);
  }

  return exit_code;
}
