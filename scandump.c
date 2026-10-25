/*
** Copyright (c) 2023-2026 Intuitibits LLC
** Author: Adrian Granados <adrian@intuitibits.com>
** SPDX-License-Identifier: GPL-3.0-only
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
#include <time.h>
#include <unistd.h>

#define VERSION "2.3.0"

#define NL80211_GENL_FAMILY_NAME "nl80211"
#define NL80211_GENL_GROUP_NAME "scan"

// Snapshot length in the PCAP file header: libpcap's maximum, which is also
// tcpdump's default. Every frame we can build fits, since the information
// elements come from a netlink attribute, which is less than 64 KiB.
#define PCAP_SNAPLEN 262144

// Initial size of the buffer holding a scan's frames, which grows as needed.
#define MIN_FRAME_BUF_SIZE 16384

// Times the scan results are read again when the kernel's results changed
// while they were being read (-NLE_DUMP_INTR), before scanning again.
#define MAX_DUMP_ATTEMPTS 3

#define MAX_FREQS 100

// How long to wait for a netlink message before giving up, so a driver that
// never reports scan completion can't hang us indefinitely.
#define NL_RECV_TIMEOUT_SEC 30

// Consecutive transient trigger failures tolerated before giving up
// (2 seconds apart, so roughly a minute of retrying).
#define MAX_TRANSIENT_RETRIES 30
#define TRANSIENT_RETRY_DELAY_SEC 2

// Upper bound for -i/--interval, in seconds (one day).
#define MAX_INTERVAL_SEC 86400

// Exit statuses, besides 0 and EXIT_FAILURE (1, invalid arguments or an
// unknown interface name). A scan failure that is not transient exits with
// 256 minus its error code (see exit_status_for_error()), e.g. 225 for
// NLE_NODEV (not a wireless interface) or 228 for NLE_PERM (no
// CAP_NET_ADMIN). Callers such as remote-sensor scripts depend on these
// values, so they are documented in scandump(8) and must not change.
#define EXIT_BUSY 240          // gave up after MAX_TRANSIENT_RETRIES
#define EXIT_RUNTIME_ERROR 255 // any other failure

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

// Exit status for a fatal error from do_scan_trigger(): a negative libnl
// code (-NLE_*) or errno, mapped to 256 + err, which is what returning the
// error from main() has always produced.
static int exit_status_for_error(int err) {

  if (err < 0 && err > -256) {
    return 256 + err;
  }

  return EXIT_RUNTIME_ERROR;
}

// Radiotap channel flags for a given center frequency (MHz): 2 GHz with
// dynamic CCK-OFDM, 5 GHz with OFDM, or OFDM alone for 6 GHz, which radiotap
// has no band flag for. The ranges are the bands' edges rather than their
// first and last channels, so that no channel is missed, e.g. 5 GHz channel
// 177 (5885 MHz, U-NII-4). 6 GHz starts at the 5925 MHz band edge. Returns 0
// for frequencies outside these bands.
static uint16_t channel_flags_for_frequency(uint32_t freq_mhz) {

  if (freq_mhz >= 2400 && freq_mhz <= 2500) {
    return 0x0480;
  } else if (freq_mhz >= 4900 && freq_mhz < 5925) {
    return 0x0140;
  } else if (freq_mhz >= 5925 && freq_mhz <= 7125) {
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

// Radiotap header: version, padding, length and the present bitmap, followed
// by the fields in bit order, each aligned to its size: Flags (u8), a padding
// byte, Channel (u16 frequency, u16 flags) and, when the driver reports it in
// dBm, dBm Antenna Signal (s8). All fields are little-endian.
#define RADIOTAP_PRESENT_FLAGS 0x00000002
#define RADIOTAP_PRESENT_CHANNEL 0x00000008
#define RADIOTAP_PRESENT_DBM_ANTSIGNAL 0x00000020
#define RADIOTAP_LEN_NO_SIGNAL 14
#define RADIOTAP_LEN_SIGNAL 15

// 802.11 management header (24 bytes) plus the beacon's fixed fields:
// timestamp (8), beacon interval (2) and capability information (2).
#define BEACON_HEADER_LEN 36

// The parts of a scan result that go into a synthesized frame.
struct bss_frame {
  const uint8_t *bssid; // SCANDUMP_BSSID_LEN bytes
  uint32_t freq;        // center frequency in MHz
  int has_signal;       // whether signal_mbm is known
  int32_t signal_mbm;   // signal strength in mBm (dBm * 100)
  uint64_t tsf;
  uint16_t beacon_int;
  uint16_t capability;
  const uint8_t *ies; // information elements, the frame body
  size_t ies_len;
};

static void put_le16(uint8_t *p, uint16_t value) {
  p[0] = value & 0xFF;
  p[1] = (value >> 8) & 0xFF;
}

static void put_le32(uint8_t *p, uint32_t value) {
  for (int i = 0; i < 4; i++) {
    p[i] = (value >> (i * 8)) & 0xFF;
  }
}

static void put_le64(uint8_t *p, uint64_t value) {
  for (int i = 0; i < 8; i++) {
    p[i] = (value >> (i * 8)) & 0xFF;
  }
}

static size_t radiotap_len(const struct bss_frame *bss) {
  return bss->has_signal ? RADIOTAP_LEN_SIGNAL : RADIOTAP_LEN_NO_SIGNAL;
}

// Length of the frame build_frame() writes for `bss`, or 0 if it would be
// longer than a PCAP record may be.
static size_t frame_len(const struct bss_frame *bss) {

  size_t header_len = radiotap_len(bss) + BEACON_HEADER_LEN;
  if (bss->ies_len > PCAP_SNAPLEN - header_len) {
    return 0;
  }

  return header_len + bss->ies_len;
}

// Writes the radiotap + 802.11 beacon frame for `bss` to `buf`, which must
// hold frame_len(bss) bytes. The information elements are copied unchanged.
static void build_frame(const struct bss_frame *bss, uint8_t *buf) {

  uint8_t *p = buf;
  size_t rt_len = radiotap_len(bss);
  uint32_t present = RADIOTAP_PRESENT_FLAGS | RADIOTAP_PRESENT_CHANNEL;
  if (bss->has_signal) {
    present |= RADIOTAP_PRESENT_DBM_ANTSIGNAL;
  }

  // Radiotap header
  p[0] = 0x00; // version
  p[1] = 0x00; // padding
  put_le16(p + 2, (uint16_t)rt_len);
  put_le32(p + 4, present);
  p[8] = 0x00; // flags: no FCS at the end of the frame
  p[9] = 0x00; // padding, so the channel field is 2-byte aligned
  put_le16(p + 10, (uint16_t)bss->freq);
  put_le16(p + 12, channel_flags_for_frequency(bss->freq));
  if (bss->has_signal) {
    p[14] = (uint8_t)clamp_rssi_dbm(bss->signal_mbm / 100);
  }
  p += rt_len;

  // 802.11 header: a beacon from the BSSID to the broadcast address.
  p[0] = 0x80; // frame control: management, beacon
  p[1] = 0x00;
  put_le16(p + 2, 0);                             // duration
  memset(p + 4, 0xFF, SCANDUMP_BSSID_LEN);        // destination address
  memcpy(p + 10, bss->bssid, SCANDUMP_BSSID_LEN); // transmitter address
  memcpy(p + 16, bss->bssid, SCANDUMP_BSSID_LEN); // BSSID
  put_le16(p + 22, 0);                            // sequence control

  // Beacon fixed fields
  put_le64(p + 24, bss->tsf);
  put_le16(p + 32, bss->beacon_int);
  put_le16(p + 34, bss->capability);
  p += BEACON_HEADER_LEN;

  // Information elements
  memcpy(p, bss->ies, bss->ies_len);
}

struct trigger_results {
  int done;
  int aborted;
  int if_index;
};

// The frames of one scan, collected by callback_dump() and written by
// write_frames() once all the results have been read, so that a scan whose
// results can't be read in full leaves nothing in the output. `buf` holds
// one record per frame: its length (a size_t) followed by the frame.
struct dump_context {
  uint8_t *buf; // reused and grown as needed
  size_t buf_size;
  size_t len; // bytes of buf in use
  int err;    // set to a negative errno when memory ran out
};

// Set from SIGINT/SIGTERM to request a clean shutdown.
static volatile sig_atomic_t g_stop = 0;

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

// Waits `seconds` seconds, measured on the monotonic clock so that changes
// to the system time don't shorten or stretch the wait. Returns 0 after the
// full wait, -ECANCELED as soon as a stop signal is received, or -errno if
// the wait failed. SIGINT and SIGTERM are blocked except while ppoll() waits,
// so a stop signal can't slip in between checking g_stop and starting to
// wait.
static int wait_seconds(long seconds) {

  sigset_t stop_signals, wait_mask;
  sigemptyset(&stop_signals);
  sigaddset(&stop_signals, SIGINT);
  sigaddset(&stop_signals, SIGTERM);
  if (sigprocmask(SIG_BLOCK, &stop_signals, &wait_mask) < 0) {
    return -errno;
  }

  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += seconds;

  int ret = 0;
  for (;;) {
    if (g_stop) {
      ret = -ECANCELED;
      break;
    }

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    struct timespec left = {.tv_sec = deadline.tv_sec - now.tv_sec,
                            .tv_nsec = deadline.tv_nsec - now.tv_nsec};
    if (left.tv_nsec < 0) {
      left.tv_sec--;
      left.tv_nsec += 1000000000L;
    }
    if (left.tv_sec < 0) {
      break;
    }

    // Returns 0 on timeout, or -1 with EINTR when a signal was handled; the
    // loop then checks g_stop and how much of the wait is left.
    if (ppoll(NULL, 0, &left, &wait_mask) < 0 && errno != EINTR) {
      ret = -errno;
      break;
    }
  }

  sigprocmask(SIG_SETMASK, &wait_mask, NULL);
  return ret;
}

static void report_recv_error(int err) {

  if (err == -ETIMEDOUT) {
    fprintf(stderr, "nl80211: timed out after %d seconds waiting for a reply\n",
            NL_RECV_TIMEOUT_SEC);
  } else if (err != -ECANCELED) {
    fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(err), err);
  }
}

// After a fatal scan error has been reported, suggests a fix for the common
// causes.
static void report_scan_error_hint(int err, const char *ifname,
                                   int num_freqs) {

  switch (err) {
  case -NLE_PERM:
  case -NLE_NOACCESS:
    fprintf(stderr, "scanning requires the CAP_NET_ADMIN capability, "
                    "e.g. by running scandump as root\n");
    break;
  case -NLE_NODEV:
    fprintf(stderr, "%s is not a Wi-Fi (nl80211) interface\n", ifname);
    break;
  case -NLE_OPNOTSUPP:
    fprintf(stderr, "the driver of %s does not support this scan\n", ifname);
    break;
  case -NLE_INVAL:
    if (num_freqs > 0) {
      fprintf(stderr, "check that %s supports the frequencies given with -f\n",
              ifname);
    }
    break;
#ifdef NLE_NETDOWN // libnl 3.10 and later
  case -NLE_NETDOWN:
    fprintf(stderr, "%s is down; bring it up with: ip link set %s up\n",
            ifname, ifname);
    break;
#endif
  default:
    break;
  }
}

static int callback_trigger(struct nl_msg *msg, void *arg) {

  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct trigger_results *results = arg;
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  static struct nla_policy trigger_policy[NL80211_ATTR_MAX + 1] = {
      [NL80211_ATTR_IFINDEX] = {.type = NLA_U32},
  };

  // The "scan" multicast group carries events for every wireless interface on
  // the system, including scans started by other processes such as
  // wpa_supplicant. Ignore anything that isn't for our interface, otherwise a
  // foreign scan's event ends our wait early and is reported as ours. The
  // policy makes the parse reject an interface index too short to be a u32.
  if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                genlmsg_attrlen(gnlh, 0), trigger_policy) < 0) {
    return NL_SKIP;
  }

  if (!tb[NL80211_ATTR_IFINDEX] ||
      (int)nla_get_u32(tb[NL80211_ATTR_IFINDEX]) != results->if_index) {
    return NL_SKIP;
  }

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
  struct dump_context *ctx = arg;
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
    fprintf(stderr, "nl80211: skipping malformed scan result\n");
    return NL_SKIP;
  }

  // nl80211 leaves out the beacon interval when it is 0 and the signal
  // unless the driver measures it in dBm, so those are optional. It also
  // leaves out empty information elements, but a beacon without any (not
  // even an SSID) is malformed, so such a result is skipped.
  if (!bss[NL80211_BSS_BSSID] ||
      !bss[NL80211_BSS_FREQUENCY] ||
      !bss[NL80211_BSS_TSF] ||
      !bss[NL80211_BSS_CAPABILITY] ||
      !bss[NL80211_BSS_INFORMATION_ELEMENTS] ||
      nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]) <= 0)
  {
    fprintf(stderr, "nl80211: skipping incomplete scan result\n");
    return NL_SKIP;
  }

  // The BSSID attribute is unspecified/unvalidated by the parse policy above,
  // so its length has to be checked before it is copied into the packet.
  if (nla_len(bss[NL80211_BSS_BSSID]) != SCANDUMP_BSSID_LEN) {
    fprintf(stderr, "nl80211: skipping malformed scan result\n");
    return NL_SKIP;
  }

  struct bss_frame frame = {
      .bssid = nla_data(bss[NL80211_BSS_BSSID]),
      .freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]),
      // NL80211_BSS_TSF and NL80211_BSS_INFORMATION_ELEMENTS come from the
      // same frame: the most recent probe response if there was one,
      // otherwise the most recent beacon. NL80211_BSS_BEACON_TSF and
      // NL80211_BSS_BEACON_IES are not used, so that the timestamp and the
      // elements always match.
      .tsf = nla_get_u64(bss[NL80211_BSS_TSF]),
      .capability = nla_get_u16(bss[NL80211_BSS_CAPABILITY]),
      .ies = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]),
      .ies_len = (size_t)nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]),
  };

  if (bss[NL80211_BSS_SIGNAL_MBM]) {
    frame.has_signal = 1;
    frame.signal_mbm = (int32_t)nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
  }

  if (bss[NL80211_BSS_BEACON_INTERVAL]) {
    frame.beacon_int = nla_get_u16(bss[NL80211_BSS_BEACON_INTERVAL]);
  }

  size_t len = frame_len(&frame);
  if (len == 0) {
    fprintf(stderr, "nl80211: skipping scan result too large for PCAP\n");
    return NL_SKIP;
  }

  // Grow the buffer if this frame's record doesn't fit, at least doubling
  // it so that a scan's frames take few reallocations.
  if (len > SIZE_MAX - sizeof(size_t) - ctx->len) {
    ctx->err = -ENOMEM;
  } else if (ctx->len + sizeof(size_t) + len > ctx->buf_size) {
    size_t need = ctx->len + sizeof(size_t) + len;
    size_t size = ctx->buf_size < MIN_FRAME_BUF_SIZE ? MIN_FRAME_BUF_SIZE
                                                     : ctx->buf_size;
    while (size < need) {
      size = size <= SIZE_MAX / 2 ? size * 2 : need;
    }
    uint8_t *buf = realloc(ctx->buf, size);
    if (buf) {
      ctx->buf = buf;
      ctx->buf_size = size;
    } else {
      ctx->err = -ENOMEM;
    }
  }
  if (ctx->err < 0) {
    fprintf(stderr, "out of memory holding the scan results\n");
    return NL_STOP;
  }

  memcpy(ctx->buf + ctx->len, &len, sizeof(size_t));
  build_frame(&frame, ctx->buf + ctx->len + sizeof(size_t));
  ctx->len += sizeof(size_t) + len;

  return NL_SKIP;
}

// Writes the frames collected in `ctx` to `dumper`.
static void write_frames(struct dump_context *ctx, pcap_dumper_t *dumper) {

  size_t off = 0;
  while (off < ctx->len) {
    size_t len;
    memcpy(&len, ctx->buf + off, sizeof(size_t));
    off += sizeof(size_t);

    // The whole frame is written, so the captured and original lengths
    // match. The timestamp is when the frame is written, not when it was
    // received: see the limitations in scandump(8). Records stay in order
    // that way, which receive times can't guarantee, since the kernel's scan
    // results include networks last heard before this scan, until they
    // expire.
    struct pcap_pkthdr header = {.caplen = (bpf_u_int32)len,
                                 .len = (bpf_u_int32)len};
    gettimeofday(&header.ts, NULL);
    pcap_dump((u_char *)dumper, &header, ctx->buf + off);
    off += len;
  }
}

// Reads the scan results into `ctx`, replacing what it held. Results that
// changed while being read (-NLE_DUMP_INTR) are read again, up to
// MAX_DUMP_ATTEMPTS times. Returns 0 on success, -ECANCELED if a stop signal
// was received, or another negative error, already reported, if the results
// could not be read; ctx->err is set too if that was for lack of memory.
static int do_scan_dump(struct nl_sock *sk, int if_index, int genl_id,
                        struct dump_context *ctx) {

  int ret = 0;
  for (int attempt = 0; attempt < MAX_DUMP_ATTEMPTS; attempt++) {
    ctx->len = 0;

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg || !genlmsg_put(msg, 0, 0, genl_id, 0, NLM_F_DUMP,
                             NL80211_CMD_GET_SCAN, 0) ||
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index) < 0) {
      fprintf(stderr, "nl80211: failed to build scan results request\n");
      nlmsg_free(msg);
      ctx->err = -ENOMEM;
      return -ENOMEM;
    }

    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, callback_dump, ctx);
    ret = nl_send_auto(sk, msg);
    nlmsg_free(msg);
    if (ret < 0) {
      fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(ret), ret);
      return ret;
    }

    ret = nl_wait_readable(sk, NL_RECV_TIMEOUT_SEC);
    if (ret < 0) {
      report_recv_error(ret);
      return ret;
    }

    // Reads until the end of the dump. libnl reads an interrupted dump to
    // its end too, so nothing is left behind for the next read.
    ret = nl_recvmsgs_default(sk);
    if (ctx->err < 0) {
      return ctx->err;
    }
    if (ret != -NLE_DUMP_INTR) {
      break;
    }
  }

  if (ret < 0) {
    fprintf(stderr, "nl80211: reading scan results: %s (%d)\n",
            nl_geterror(ret), ret);
    return ret;
  }

  return 0;
}

static int do_scan_trigger(struct nl_sock *sk, int if_index, int genl_id,
                           int passive, int freqs[], int num_freqs) {

  // Starts the scan and waits for it to finish.
  // Does not return until the scan is done, has been aborted, has failed,
  // has timed out, or a stop signal was received.
  struct trigger_results results = {.done = 0, .aborted = 0,
                                    .if_index = if_index};
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
  // nl_recvmsgs() normally reports a NACK itself, as a libnl error code, so
  // this only runs if it didn't; convert err (a raw -errno from the kernel)
  // so callers see a libnl code either way.
  if (err < 0) {
    ret = -nl_syserr2nlerr(err);
    fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(ret), ret);
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

// Prints the usage summary to `out`: stdout when it was asked for with -h,
// stderr when it accompanies an error, so it never mixes into a PCAP stream
// written to stdout.
static void print_usage(FILE *out, const char *program_name)
{
  fprintf(out, "Usage: %s [-c count] [-i interval] [-f frequency-list] [-p] [-h] [-V] <interface> <filename>\n", program_name);
  fprintf(out, "Options:\n");
  fprintf(out, "  -c, --count         Exit after the specified number of scans\n");
  fprintf(out, "                      (default 0: scan until interrupted)\n");
  fprintf(out, "  -i, --interval      Wait the specified number of seconds between scans\n");
  fprintf(out, "                      (default 0: start the next scan right away)\n");
  fprintf(out, "  -f, --frequency     Comma-separated list of frequencies in MHz to scan\n");
  fprintf(out, "  -p, --passive       Use passive scan mode\n");
  fprintf(out, "  -h, --help          Display this help message\n");
  fprintf(out, "  -V, --version       Show version\n");
  fprintf(out, "Use - as <filename> to write to standard output.\n");
}

// Opens the output file for writing. The mode matches what tcpdump and
// pcap_dump_open() produce -- 0666 as masked by the caller's umask, so a
// root run under sudo's usual 022 umask yields 0644 -- but the open refuses
// to follow a symlink at the final path component, so a pre-planted symlink
// at a predictable output path cannot redirect a root write elsewhere.
static FILE *open_output_file(const char *file) {

  int fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0666);
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

// Flushes the output and reports whether everything written to it so far
// reached it. pcap_dump() cannot report errors and pcap_dump_close() returns
// nothing, so a full disk or a closed pipe is only noticed through the
// stream's error flag. The caller sets errno to 0 before writing, so that the
// cause of a failed write is still in errno here. Returns 0 on success,
// -EPIPE without a message if the output is a pipe or FIFO whose reader has
// gone (SIGPIPE is ignored), -ECANCELED without a message if a stop signal
// interrupted a write blocked on a reader that isn't reading, or -1 after
// printing a diagnostic for any other failure.
static int check_output(pcap_dumper_t *dumper, const char *name) {

  if (pcap_dump_flush(dumper) == 0 && !ferror(pcap_dump_file(dumper))) {
    return 0;
  }

  if (errno == EPIPE) {
    return -EPIPE;
  }
  if (errno == EINTR && g_stop) {
    return -ECANCELED;
  }

  fprintf(stderr, "%s: %s\n", name,
          errno != 0 ? strerror(errno) : "write error");
  return -1;
}

int main(int argc, char *argv[]) {

  struct nl_sock *sk = NULL;
  int opt, err;
  pcap_t *handle = NULL;
  pcap_dumper_t *dumper = NULL;
  struct dump_context dump_ctx = {0};
  int linktype = DLT_IEEE802_11_RADIO;
  int snaplen = PCAP_SNAPLEN;
  int exit_code = 0;

  int version_flag = 0;
  int use_passive = 0;
  char* frequency_list = NULL;
  int freqs[MAX_FREQS];
  int count = 0;
  long interval = 0;

  struct option long_options[] = {
    {"count", required_argument, 0, 'c'},
    {"interval", required_argument, 0, 'i'},
    {"frequency", required_argument, 0, 'f'},
    {"passive", no_argument, 0, 'p'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0}
  };

  while ((opt = getopt_long(argc, argv, "c:i:f:phV", long_options, NULL)) != -1) {
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
      case 'i':
        if (parse_long_strict(optarg, 0, MAX_INTERVAL_SEC, &interval) < 0) {
          fprintf(stderr, "invalid interval: %s (expected 0 to %d seconds)\n",
                  optarg, MAX_INTERVAL_SEC);
          exit(EXIT_FAILURE);
        }
        break;
      case 'f':
        frequency_list = optarg;
        break;
      case 'p':
        use_passive = 1;
        break;
      case 'V':
        version_flag = 1;
        break;
      case 'h':
          // Display help message
          print_usage(stdout, basename(argv[0]));
          exit(EXIT_SUCCESS);
          break;
      case '?':
        // Handle unknown or missing options
        print_usage(stderr, basename(argv[0]));
        exit(EXIT_FAILURE);
        break;
    }
  }

  // A fixed name, so the output doesn't depend on how scandump was invoked
  // (e.g. through a renamed symlink); scripts and packaging tests match it.
  if (version_flag) {
    printf("scandump version %s\n", VERSION);
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
    print_usage(stderr, basename(argv[0]));
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
  const char *output_name = to_stdout ? "stdout" : file;

  // Handle Ctrl-C and SIGTERM so a scan in progress can be interrupted and
  // the output file closed cleanly.
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_stop_signal;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGINT, &sa, NULL) < 0 || sigaction(SIGTERM, &sa, NULL) < 0) {
    fprintf(stderr, "sigaction: %s\n", strerror(errno));
    return EXIT_RUNTIME_ERROR;
  }

  // A reader that closes the pipe it reads the PCAP stream from, such as
  // "tcpdump -c 5", makes the next write fail with EPIPE instead of killing
  // scandump, which then stops as if interrupted (see check_output()).
  sa.sa_handler = SIG_IGN;
  if (sigaction(SIGPIPE, &sa, NULL) < 0) {
    fprintf(stderr, "sigaction: %s\n", strerror(errno));
    return EXIT_RUNTIME_ERROR;
  }

  sk = nl_socket_alloc();
  if (!sk) {
    fprintf(stderr, "nl80211: %s (%d)\n", strerror(errno), errno);
    return EXIT_RUNTIME_ERROR;
  }

  err = genl_connect(sk);
  if (err < 0) {
    fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(err), err);
    exit_code = EXIT_RUNTIME_ERROR;
    goto cleanup;
  }

  int genl_id = genl_ctrl_resolve(sk, NL80211_GENL_FAMILY_NAME);
  if (genl_id < 0) {
    fprintf(stderr, "nl80211: %s (%d)\n", nl_geterror(genl_id), genl_id);
    if (genl_id == -NLE_OBJ_NOTFOUND) {
      fprintf(stderr, "nl80211 is not available; is the cfg80211 kernel "
                      "module loaded?\n");
    }
    exit_code = EXIT_RUNTIME_ERROR;
    goto cleanup;
  }

  // Create pcap handle
  handle = pcap_open_dead(linktype, snaplen);
  if (!handle) {
    fprintf(stderr, "libpcap: error creating pcap handle\n");
    exit_code = EXIT_RUNTIME_ERROR;
    goto cleanup;
  }

  int n = 0;
  int transient_retries = 0;
  int output_closed = 0;
  while (((count == 0) || (n < count)) && !g_stop) {

    // Trigger scan and wait for it to finish
    int trigger_err = do_scan_trigger(sk, if_index, genl_id, use_passive,
                                      freqs, num_freqs);

    if (g_stop) {
      break;
    }

    // Read the networks found. A scan whose results can't be read in full
    // writes nothing and doesn't count; it is retried like a busy interface.
    int dump_failed = 0;
    if (trigger_err == 0) {
      int dump_err = do_scan_dump(sk, if_index, genl_id, &dump_ctx);
      if (dump_ctx.err < 0) {
        exit_code = EXIT_RUNTIME_ERROR;
        goto cleanup;
      }
      if (dump_err == -ECANCELED) {
        break;
      }
      dump_failed = dump_err < 0;
    }

    if (trigger_err != 0 || dump_failed) {
      // Netlink failures arrive as libnl codes (-NLE_*), not errno values.
      // The interface being busy (-NLE_BUSY, -25, the kernel's EBUSY while
      // another scan runs), an interrupted dump (-NLE_DUMP_INTR, -33) and a
      // sequence mismatch (-NLE_SEQ_MISMATCH, -16) can happen for various
      // reasons when doing a scan, but we can simply retry. So can a timeout
      // waiting for the kernel (-ETIMEDOUT, from poll()), and failing to
      // read the results.
      if (dump_failed || trigger_err == -NLE_BUSY ||
          trigger_err == -NLE_DUMP_INTR || trigger_err == -NLE_SEQ_MISMATCH ||
          trigger_err == -ETIMEDOUT) {
        if (++transient_retries > MAX_TRANSIENT_RETRIES) {
          fprintf(stderr,
                  "nl80211: giving up after %d consecutive transient errors\n",
                  MAX_TRANSIENT_RETRIES);
          exit_code = EXIT_BUSY;
          goto cleanup;
        }
        err = wait_seconds(TRANSIENT_RETRY_DELAY_SEC);
        if (err == -ECANCELED) {
          break;
        }
        if (err < 0) {
          fprintf(stderr, "wait: %s\n", strerror(-err));
          exit_code = EXIT_RUNTIME_ERROR;
          goto cleanup;
        }
        continue;
      }

      // Other errors are not expected, so we quit.
      report_scan_error_hint(trigger_err, argv[optind], num_freqs);
      exit_code = exit_status_for_error(trigger_err);
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
          exit_code = EXIT_RUNTIME_ERROR;
          goto cleanup;
        }
        // On failure libpcap closes the stream itself, so it must not be
        // closed here; the process exits right away in that case anyway.
        dumper = pcap_dump_fopen(handle, fp);
      }

      if (!dumper) {
        fprintf(stderr, "libpcap: %s\n", pcap_geterr(handle));
        exit_code = EXIT_RUNTIME_ERROR;
        goto cleanup;
      }
    }

    // Write the scan's frames and flush them, to a file as well as to
    // stdout, so that each finished scan is in the output even if scandump
    // is killed later. Stop on a write error rather than keep scanning into
    // a broken output, and quietly if the reader closed the pipe or a stop
    // signal interrupted the write.
    errno = 0;
    write_frames(&dump_ctx, dumper);
    err = check_output(dumper, output_name);
    if (err == -EPIPE || err == -ECANCELED) {
      output_closed = 1;
      break;
    }
    if (err < 0) {
      exit_code = EXIT_RUNTIME_ERROR;
      goto cleanup;
    }

    n++;

    // Wait between scans, but not before the first or after the last one.
    if (interval > 0 && (count == 0 || n < count)) {
      err = wait_seconds(interval);
      if (err == -ECANCELED) {
        break;
      }
      if (err < 0) {
        fprintf(stderr, "wait: %s\n", strerror(-err));
        exit_code = EXIT_RUNTIME_ERROR;
        goto cleanup;
      }
    }
  }

cleanup:
  if (dumper) {
    // Skipped after an earlier error, which has been reported already, and
    // when the reader has gone or a stop signal interrupted a write.
    errno = 0;
    if (exit_code == 0 && !output_closed &&
        check_output(dumper, output_name) == -1) {
      exit_code = EXIT_RUNTIME_ERROR;
    }
    pcap_dump_close(dumper);
  }
  free(dump_ctx.buf);
  if (handle) {
    pcap_close(handle);
  }
  if (sk) {
    nl_socket_free(sk);
  }

  return exit_code;
}
