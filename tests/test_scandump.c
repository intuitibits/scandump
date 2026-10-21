/*
** Copyright (c) 2026 Intuitibits LLC
** SPDX-License-Identifier: GPL-3.0-only
*/

// Tests for the parts of scandump that don't need a wireless interface:
// frame construction from nl80211 scan results (fed to callback_dump() as
// netlink messages built here, and read back from the PCAP file it writes),
// argument parsing, exit statuses, output error checks and the interval
// wait. scandump.c is included so that its static functions can be called;
// its main() is renamed so this file can have its own.
//
// Usage: test_scandump [sample.pcap]
// With an argument, also writes a PCAP file of sample frames (2.4, 5 and
// 6 GHz, large and empty bodies, no signal) for inspection with Wireshark.

#define main scandump_main
#include "../scandump.c"
#undef main

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,       \
              #cond);                                                        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

// Attributes of a synthetic scan result. Fields left NULL/0 are omitted
// where noted, so tests can leave out or corrupt individual attributes.
struct test_bss {
  const uint8_t *bssid;
  int bssid_len;
  uint32_t freq; // 0: omitted
  int has_signal;
  int32_t signal_mbm;
  int has_tsf;
  uint64_t tsf;
  int short_tsf; // put a 4-byte TSF, which the parse policy must reject
  int has_beacon_int;
  uint16_t beacon_int;
  int has_capability;
  uint16_t capability;
  const uint8_t *ies;
  size_t ies_len;
  int has_ies;
  // Beacon data alongside probe response data, as nl80211 reports it.
  const uint8_t *beacon_ies;
  size_t beacon_ies_len;
  uint64_t beacon_tsf;
  int has_last_seen; // NL80211_BSS_LAST_SEEN_BOOTTIME
  uint64_t last_seen_boottime_ns;
};

static const uint8_t test_bssid[SCANDUMP_BSSID_LEN] = {0x02, 0x11, 0x22,
                                                        0x33, 0x44, 0x55};
static const uint8_t default_ies[] = {0x00, 0x06, 's', 'a', 'm', 'p', 'l', 'e'};

// A complete scan result; tests change or remove attributes from it.
static struct test_bss default_bss(void) {
  struct test_bss t = {
      .bssid = test_bssid,
      .bssid_len = SCANDUMP_BSSID_LEN,
      .freq = 2437,
      .has_signal = 1,
      .signal_mbm = -4500,
      .has_tsf = 1,
      .tsf = 0x0102030405060708ULL,
      .has_beacon_int = 1,
      .beacon_int = 100,
      .has_capability = 1,
      .capability = 0x0431,
      .ies = default_ies,
      .ies_len = sizeof(default_ies),
      .has_ies = 1,
  };
  return t;
}

// Builds the NL80211_CMD_NEW_SCAN_RESULTS message nl80211 sends for `t`.
static struct nl_msg *make_bss_msg(const struct test_bss *t) {

  struct nl_msg *msg = nlmsg_alloc_size(128 * 1024);
  if (!msg || !genlmsg_put(msg, 0, 0, 0, 0, 0, NL80211_CMD_NEW_SCAN_RESULTS,
                           0)) {
    return NULL;
  }

  struct nlattr *nest = nla_nest_start(msg, NL80211_ATTR_BSS);
  int err = nest ? 0 : -1;
  if (t->bssid) {
    err |= nla_put(msg, NL80211_BSS_BSSID, t->bssid_len, t->bssid);
  }
  if (t->freq) {
    err |= nla_put_u32(msg, NL80211_BSS_FREQUENCY, t->freq);
  }
  if (t->has_signal) {
    err |= nla_put_u32(msg, NL80211_BSS_SIGNAL_MBM, (uint32_t)t->signal_mbm);
  }
  if (t->has_tsf) {
    err |= nla_put_u64(msg, NL80211_BSS_TSF, t->tsf);
  }
  if (t->short_tsf) {
    err |= nla_put_u32(msg, NL80211_BSS_TSF, 1);
  }
  if (t->has_beacon_int) {
    err |= nla_put_u16(msg, NL80211_BSS_BEACON_INTERVAL, t->beacon_int);
  }
  if (t->has_capability) {
    err |= nla_put_u16(msg, NL80211_BSS_CAPABILITY, t->capability);
  }
  if (t->has_ies) {
    err |= nla_put(msg, NL80211_BSS_INFORMATION_ELEMENTS, (int)t->ies_len,
                   t->ies);
  }
  if (t->beacon_ies) {
    err |= nla_put_flag(msg, NL80211_BSS_PRESP_DATA);
    err |= nla_put_u64(msg, NL80211_BSS_BEACON_TSF, t->beacon_tsf);
    err |= nla_put(msg, NL80211_BSS_BEACON_IES, (int)t->beacon_ies_len,
                   t->beacon_ies);
  }
  if (t->has_last_seen) {
    err |= nla_put_u64(msg, NL80211_BSS_LAST_SEEN_BOOTTIME,
                       t->last_seen_boottime_ns);
  }
  if (err || nla_nest_end(msg, nest) < 0) {
    nlmsg_free(msg);
    return NULL;
  }

  return msg;
}

// A valid information element blob of `len` (at least 2) bytes: an SSID
// element followed by vendor-specific elements filled with a pattern. The
// SSID's length absorbs remainders too short for another element.
static uint8_t *make_ies(size_t len) {

  uint8_t *ies = malloc(len);
  if (!ies || len < 2) {
    free(ies);
    return NULL;
  }

  size_t ssid_len = len - 2 < 13 ? len - 2 : 13;
  size_t rest = len - 2 - ssid_len;
  if (rest > 0 && rest < 6) {
    ssid_len += rest;
  }
  size_t i = 0;
  ies[i++] = 0;
  ies[i++] = (uint8_t)ssid_len;
  memset(ies + i, 'a', ssid_len);
  i += ssid_len;

  while (i < len) {
    size_t body = len - i - 2 > 255 ? 255 : len - i - 2;
    size_t left = len - i - 2 - body;
    if (left > 0 && left < 6) {
      body -= 6; // leave room for a final element with an OUI and a type
    }
    ies[i++] = 221;
    ies[i++] = (uint8_t)body;
    ies[i++] = 0x00; // OUI
    ies[i++] = 0x00;
    ies[i++] = 0x00;
    for (size_t j = 3; j < body; j++, i++) {
      ies[i] = (uint8_t)(i * 31);
    }
  }

  return ies;
}

// Feeds scan results to callback_dump() and reads back the PCAP file it
// writes. Returns the number of frames written (or -1 on a test setup
// error) and copies up to `max` of them, with their record headers.
struct frame {
  struct pcap_pkthdr hdr;
  uint8_t *data;
};

static int dump_frames(struct nl_msg **msgs, int num_msgs, struct frame *out,
                       int max, const char *keep_path) {

  char path[256];
  const char *tmpdir = getenv("TMPDIR");
  snprintf(path, sizeof(path), "%s/scandump-test-XXXXXX",
           tmpdir ? tmpdir : "/tmp");
  int fd = mkstemp(path);
  if (fd < 0) {
    perror("mkstemp");
    return -1;
  }

  FILE *fp = fdopen(fd, "w");
  pcap_t *dead = pcap_open_dead(DLT_IEEE802_11_RADIO, PCAP_SNAPLEN);
  pcap_dumper_t *dumper = fp ? pcap_dump_fopen(dead, fp) : NULL;
  if (!dumper) {
    fprintf(stderr, "failed to open %s\n", path);
    return -1;
  }

  // Frames are only collected until write_frames() is called.
  struct dump_context ctx = {0};
  for (int i = 0; i < num_msgs; i++) {
    callback_dump(msgs[i], &ctx);
  }
  CHECK(ctx.err == 0);
  CHECK(pcap_dump_ftell(dumper) == 24); // just the file header
  errno = 0;
  write_frames(&ctx, dumper);
  CHECK(check_output(dumper, path) == 0);
  pcap_dump_close(dumper);
  pcap_close(dead);
  free(ctx.buf);

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *rd = pcap_open_offline(path, errbuf);
  if (!rd) {
    fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
    return -1;
  }
  CHECK(pcap_datalink(rd) == DLT_IEEE802_11_RADIO);
  CHECK(pcap_snapshot(rd) == PCAP_SNAPLEN);

  int n = 0;
  struct pcap_pkthdr *hdr;
  const u_char *data;
  while (pcap_next_ex(rd, &hdr, &data) == 1) {
    if (n < max) {
      out[n].hdr = *hdr;
      out[n].data = malloc(hdr->caplen);
      memcpy(out[n].data, data, hdr->caplen);
    }
    n++;
  }
  pcap_close(rd);

  if (keep_path) {
    rename(path, keep_path);
  } else {
    unlink(path);
  }
  return n;
}

// dump_frames() for a single scan result.
static int dump_one(const struct test_bss *t, struct frame *out) {

  struct nl_msg *msg = make_bss_msg(t);
  if (!msg) {
    fprintf(stderr, "failed to build test message\n");
    failures++;
    return -1;
  }
  int n = dump_frames(&msg, 1, out, 1, NULL);
  nlmsg_free(msg);
  return n;
}

static uint16_t get_le16(const uint8_t *p) {
  return (uint16_t)(p[0] | (p[1] << 8));
}

static uint64_t get_le64(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) {
    v = (v << 8) | p[i];
  }
  return v;
}

// A complete scan result produces exactly the frame earlier versions did:
// the same 51 header bytes, followed by the information elements.
static void test_frame_layout(void) {

  uint8_t ies[] = {0x00, 0x04, 't', 'e', 's', 't', 0x01, 0x01, 0x82};
  struct test_bss t = default_bss();
  t.ies = ies;
  t.ies_len = sizeof(ies);
  t.has_ies = 1;

  static const uint8_t expected[] = {
      // Radiotap: length 15, present Flags | Channel | dBm Antenna Signal
      0x00, 0x00, 0x0f, 0x00, 0x2a, 0x00, 0x00, 0x00,
      // Flags, padding, 2437 MHz, 2 GHz + dynamic CCK-OFDM, -45 dBm
      0x00, 0x00, 0x85, 0x09, 0x80, 0x04, 0xd3,
      // Beacon, duration 0, broadcast DA, SA = BSSID, sequence 0
      0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x00, 0x00,
      // TSF, beacon interval 100, capability 0x0431
      0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x64, 0x00, 0x31, 0x04,
      // Information elements
      0x00, 0x04, 't', 'e', 's', 't', 0x01, 0x01, 0x82};

  struct frame f;
  CHECK(dump_one(&t, &f) == 1);
  CHECK(f.hdr.caplen == sizeof(expected));
  CHECK(f.hdr.len == sizeof(expected));
  CHECK(f.hdr.caplen == sizeof(expected) &&
        memcmp(f.data, expected, sizeof(expected)) == 0);
  free(f.data);
}

// Information elements beyond the old 2048-byte buffer are kept whole, and
// the record lengths cover the whole frame.
static void test_large_ies(void) {

  static const size_t sizes[] = {2048 - 51, 2048 - 50, 5000, 60000};
  for (size_t k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++) {
    uint8_t *ies = make_ies(sizes[k]);
    struct test_bss t = default_bss();
    t.ies = ies;
    t.ies_len = sizes[k];
    t.has_ies = 1;

    struct frame f;
    CHECK(dump_one(&t, &f) == 1);
    CHECK(f.hdr.caplen == 51 + sizes[k]);
    CHECK(f.hdr.len == f.hdr.caplen);
    CHECK(f.hdr.caplen == 51 + sizes[k] &&
          memcmp(f.data + 51, ies, sizes[k]) == 0);
    free(f.data);
    free(ies);
  }
}

// The frame buffer grows and shrinking frames reuse it: a run of different
// sizes in one dump each keep their own length and contents.
static void test_mixed_sizes(void) {

  static const size_t sizes[] = {100, 9000, 10, 3000, 2};
  enum { N = sizeof(sizes) / sizeof(sizes[0]) };
  struct nl_msg *msgs[N];
  uint8_t *ies[N];
  for (int k = 0; k < N; k++) {
    ies[k] = make_ies(sizes[k]);
    struct test_bss t = default_bss();
    t.ies = ies[k];
    t.ies_len = sizes[k];
    msgs[k] = make_bss_msg(&t);
    CHECK(msgs[k] != NULL);
  }

  struct frame f[N];
  CHECK(dump_frames(msgs, N, f, N, NULL) == N);
  for (int k = 0; k < N; k++) {
    CHECK(f[k].hdr.caplen == 51 + sizes[k]);
    CHECK(f[k].hdr.len == 51 + sizes[k]);
    CHECK(memcmp(f[k].data + 51, ies[k], sizes[k]) == 0);
    free(f[k].data);
    free(ies[k]);
    nlmsg_free(msgs[k]);
  }
}

// Optional attributes nl80211 leaves out are handled without dropping the
// network or making values up.
static void test_optional_attributes(void) {

  struct frame f;

  // No signal (a driver without dBm support): the radiotap header leaves
  // the signal field out instead of reporting a made-up value.
  struct test_bss t = default_bss();
  t.has_signal = 0;
  CHECK(dump_one(&t, &f) == 1);
  CHECK(f.hdr.caplen == 14 + 36 + sizeof(default_ies));
  CHECK(f.hdr.len == f.hdr.caplen);
  CHECK(get_le16(f.data + 2) == 14);
  CHECK(f.data[4] == 0x0a && f.data[5] == 0 && f.data[6] == 0 &&
        f.data[7] == 0);
  CHECK(get_le16(f.data + 10) == 2437);
  CHECK(f.data[14] == 0x80); // the 802.11 header starts right after
  CHECK(memcmp(f.data + 14 + 10, test_bssid, 6) == 0);
  CHECK(get_le64(f.data + 14 + 24) == t.tsf);
  CHECK(memcmp(f.data + 50, default_ies, sizeof(default_ies)) == 0);
  free(f.data);

  // No beacon interval: nl80211 only leaves it out when it is 0.
  t = default_bss();
  t.has_beacon_int = 0;
  CHECK(dump_one(&t, &f) == 1);
  CHECK(get_le16(f.data + 15 + 32) == 0);
  CHECK(get_le16(f.data + 15 + 34) == t.capability);
  free(f.data);
}

// Scan results missing attributes that nl80211 always sends, or with
// malformed ones, are skipped rather than written as broken frames.
static void test_incomplete_results(void) {

  struct frame f;
  struct test_bss t;
  static const uint8_t long_bssid[8] = {0};

  t = default_bss();
  t.bssid = NULL;
  CHECK(dump_one(&t, &f) == 0);

  t = default_bss();
  t.bssid_len = 5;
  CHECK(dump_one(&t, &f) == 0);

  t = default_bss();
  t.bssid = long_bssid;
  t.bssid_len = sizeof(long_bssid);
  CHECK(dump_one(&t, &f) == 0);

  t = default_bss();
  t.freq = 0;
  CHECK(dump_one(&t, &f) == 0);

  t = default_bss();
  t.has_tsf = 0;
  CHECK(dump_one(&t, &f) == 0);

  t = default_bss();
  t.has_tsf = 0;
  t.short_tsf = 1;
  CHECK(dump_one(&t, &f) == 0);

  t = default_bss();
  t.has_capability = 0;
  CHECK(dump_one(&t, &f) == 0);

  // No information elements, or an empty attribute: a beacon without even
  // an SSID element would be malformed.
  t = default_bss();
  t.has_ies = 0;
  CHECK(dump_one(&t, &f) == 0);

  t = default_bss();
  t.ies_len = 0;
  CHECK(dump_one(&t, &f) == 0);

  // A message without a BSS (e.g. some other nl80211 reply) is ignored.
  struct nl_msg *msg = nlmsg_alloc();
  CHECK(msg && genlmsg_put(msg, 0, 0, 0, 0, 0, NL80211_CMD_NEW_SCAN_RESULTS,
                           0));
  CHECK(dump_frames(&msg, 1, &f, 1, NULL) == 0);
  nlmsg_free(msg);
}

// When nl80211 has both probe response and beacon data for a BSS, the frame
// uses NL80211_BSS_INFORMATION_ELEMENTS and its own TSF, never the beacon's
// elements or timestamp mixed in.
static void test_probe_response_and_beacon(void) {

  uint8_t presp_ies[] = {0x00, 0x06, 'h', 'i', 'd', 'd', 'e', 'n'};
  uint8_t beacon_ies[] = {0x00, 0x00, 0x05, 0x04, 0x00, 0x01, 0x00, 0x00};
  struct test_bss t = default_bss();
  t.ies = presp_ies;
  t.ies_len = sizeof(presp_ies);
  t.has_ies = 1;
  t.tsf = 1111;
  t.beacon_ies = beacon_ies;
  t.beacon_ies_len = sizeof(beacon_ies);
  t.beacon_tsf = 2222;

  struct frame f;
  CHECK(dump_one(&t, &f) == 1);
  CHECK(f.hdr.caplen == 51 + sizeof(presp_ies));
  CHECK(memcmp(f.data + 51, presp_ies, sizeof(presp_ies)) == 0);
  CHECK(get_le64(f.data + 15 + 24) == 1111);
  free(f.data);
}

// Frequency, channel flags and signal in the radiotap header.
static void test_radio_metadata(void) {

  static const struct {
    uint32_t freq;
    uint16_t flags;
  } cases[] = {
      {2412, 0x0480}, {2484, 0x0480}, // 2.4 GHz channels 1 and 14
      {4900, 0x0140}, {5924, 0x0140}, // 5 GHz band edges
      {5180, 0x0140}, {5825, 0x0140}, // 5 GHz channels 36 and 165
      {5885, 0x0140},                 // 5 GHz channel 177
      {5925, 0x0040}, {5955, 0x0040}, // 6 GHz band edge, channel 1
      {6115, 0x0040}, {7115, 0x0040}, // 6 GHz channels 33 and 233
      {915, 0x0000},  {58320, 0x0000}, // sub-1 GHz, 60 GHz: no band flag
  };

  for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
    CHECK(channel_flags_for_frequency(cases[k].freq) == cases[k].flags);

    struct test_bss t = default_bss();
    t.freq = cases[k].freq;
    struct frame f;
    CHECK(dump_one(&t, &f) == 1);
    CHECK(get_le16(f.data + 10) == cases[k].freq);
    CHECK(get_le16(f.data + 12) == cases[k].flags);
    free(f.data);
  }

  static const struct {
    int32_t mbm;
    int8_t dbm;
  } signals[] = {{-4500, -45}, {-9900, -99}, {0, 0},
                 {-20000, -128}, {20000, 127}, {INT32_MIN, -128}};
  for (size_t k = 0; k < sizeof(signals) / sizeof(signals[0]); k++) {
    struct test_bss t = default_bss();
    t.signal_mbm = signals[k].mbm;
    struct frame f;
    CHECK(dump_one(&t, &f) == 1);
    CHECK((int8_t)f.data[14] == signals[k].dbm);
    free(f.data);
  }
}

static double timeval_secs(const struct timeval *tv) {
  return (double)tv->tv_sec + (double)tv->tv_usec / 1e6;
}

// Records are stamped with the time they are written, even when the kernel
// reports that the network was last seen earlier, so they stay in order.
static void test_timestamps(void) {

  struct frame f[2];
  struct timeval before, after;
  struct timespec boot;
  clock_gettime(CLOCK_BOOTTIME, &boot);

  struct test_bss t = default_bss();
  t.has_last_seen = 1;
  t.last_seen_boottime_ns = (uint64_t)boot.tv_sec * 1000000000 +
                            (uint64_t)boot.tv_nsec - 20000000000ULL;
  struct nl_msg *msgs[2] = {make_bss_msg(&t), NULL};
  t.last_seen_boottime_ns += 10000000000ULL; // seen 10 s later than the first
  msgs[1] = make_bss_msg(&t);
  CHECK(msgs[0] && msgs[1]);

  gettimeofday(&before, NULL);
  CHECK(dump_frames(msgs, 2, f, 2, NULL) == 2);
  gettimeofday(&after, NULL);
  for (int k = 0; k < 2; k++) {
    CHECK(timeval_secs(&f[k].hdr.ts) >= timeval_secs(&before));
    CHECK(timeval_secs(&f[k].hdr.ts) <= timeval_secs(&after));
    free(f[k].data);
    nlmsg_free(msgs[k]);
  }
  CHECK(timeval_secs(&f[0].hdr.ts) <= timeval_secs(&f[1].hdr.ts));
}

static void test_frame_len_bounds(void) {

  struct bss_frame bss = {.has_signal = 1};
  bss.ies_len = PCAP_SNAPLEN - 51;
  CHECK(frame_len(&bss) == PCAP_SNAPLEN);
  bss.ies_len = PCAP_SNAPLEN - 50;
  CHECK(frame_len(&bss) == 0);
  bss.ies_len = SIZE_MAX;
  CHECK(frame_len(&bss) == 0);
  bss.has_signal = 0;
  bss.ies_len = PCAP_SNAPLEN - 50;
  CHECK(frame_len(&bss) == PCAP_SNAPLEN);
}

static void test_parsing(void) {

  long v;
  CHECK(parse_long_strict("0", 0, MAX_INTERVAL_SEC, &v) == 0 && v == 0);
  CHECK(parse_long_strict("5", 0, MAX_INTERVAL_SEC, &v) == 0 && v == 5);
  CHECK(parse_long_strict("86400", 0, MAX_INTERVAL_SEC, &v) == 0 &&
        v == 86400);
  CHECK(parse_long_strict("86401", 0, MAX_INTERVAL_SEC, &v) < 0);
  CHECK(parse_long_strict("-1", 0, MAX_INTERVAL_SEC, &v) < 0);
  CHECK(parse_long_strict("1.5", 0, MAX_INTERVAL_SEC, &v) < 0);
  CHECK(parse_long_strict("5s", 0, MAX_INTERVAL_SEC, &v) < 0);
  CHECK(parse_long_strict("", 0, MAX_INTERVAL_SEC, &v) < 0);
  CHECK(parse_long_strict("99999999999999999999", 0, MAX_INTERVAL_SEC, &v) <
        0);

  int freqs[MAX_FREQS];
  int n;
  char ok[] = "2412,5180,5955";
  CHECK(parse_frequency_list(ok, freqs, MAX_FREQS, &n) == 0 && n == 3 &&
        freqs[2] == 5955);
  char dup[] = "2412,2412";
  CHECK(parse_frequency_list(dup, freqs, MAX_FREQS, &n) < 0);
  char bad[] = "2412,x";
  CHECK(parse_frequency_list(bad, freqs, MAX_FREQS, &n) < 0);
}

static void test_exit_status(void) {

  CHECK(exit_status_for_error(-NLE_NODEV) == 225);
  CHECK(exit_status_for_error(-NLE_PERM) == 228);
  CHECK(exit_status_for_error(-NLE_OPNOTSUPP) == 246);
  CHECK(exit_status_for_error(-ETIMEDOUT) == 256 - ETIMEDOUT);
  CHECK(exit_status_for_error(-300) == EXIT_RUNTIME_ERROR);
  CHECK(exit_status_for_error(0) == EXIT_RUNTIME_ERROR);
}

// A write error (here, a full device) is reported rather than lost, and a
// reader closing the pipe is told apart from it.
static void test_output_errors(void) {

  pcap_t *dead = pcap_open_dead(DLT_IEEE802_11_RADIO, PCAP_SNAPLEN);

  FILE *fp = fopen("/dev/full", "w");
  if (fp) {
    pcap_dumper_t *dumper = pcap_dump_fopen(dead, fp);
    CHECK(dumper != NULL);
    if (dumper) {
      errno = 0;
      CHECK(check_output(dumper, "/dev/full") == -1);
      pcap_dump_close(dumper);
    }
  } else {
    printf("skipping write error test: no /dev/full\n");
  }

  // With SIGPIPE ignored, as main() does, writing to a pipe whose reader
  // has gone fails with EPIPE, which is reported as -EPIPE and no message.
  struct sigaction sa, old;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_IGN;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGPIPE, &sa, &old);
  int fds[2];
  CHECK(pipe(fds) == 0);
  close(fds[0]);
  pcap_dumper_t *dumper = pcap_dump_fopen(dead, fdopen(fds[1], "w"));
  CHECK(dumper != NULL);
  if (dumper) {
    errno = 0;
    CHECK(check_output(dumper, "pipe") == -EPIPE);
    pcap_dump_close(dumper);
  }
  sigaction(SIGPIPE, &old, NULL);

  pcap_close(dead);
}

static double elapsed_since(const struct timespec *start) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (double)(now.tv_sec - start->tv_sec) +
         (double)(now.tv_nsec - start->tv_nsec) / 1e9;
}

static void raise_stop_signal(int signum) {
  (void)signum;
  raise(SIGTERM);
}

static void ignore_signal(int signum) {
  (void)signum;
}

static void test_wait(void) {

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_stop_signal;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGTERM, &sa, NULL);

  // The full interval.
  struct timespec start;
  g_stop = 0;
  clock_gettime(CLOCK_MONOTONIC, &start);
  CHECK(wait_seconds(1) == 0);
  CHECK(elapsed_since(&start) >= 1.0);

  // A stop requested before the wait returns right away.
  g_stop = 1;
  clock_gettime(CLOCK_MONOTONIC, &start);
  CHECK(wait_seconds(30) == -ECANCELED);
  CHECK(elapsed_since(&start) < 1.0);

  // A stop signal during the wait ends it early. SIGALRM's handler raises
  // SIGTERM, as a user's kill would.
  g_stop = 0;
  sa.sa_handler = raise_stop_signal;
  sigaction(SIGALRM, &sa, NULL);
  clock_gettime(CLOCK_MONOTONIC, &start);
  alarm(1);
  CHECK(wait_seconds(30) == -ECANCELED);
  CHECK(elapsed_since(&start) < 10.0);
  CHECK(g_stop == 1);

  // Other signals interrupt ppoll() but don't end the wait early.
  g_stop = 0;
  sa.sa_handler = ignore_signal;
  sigaction(SIGALRM, &sa, NULL);
  clock_gettime(CLOCK_MONOTONIC, &start);
  alarm(1);
  CHECK(wait_seconds(2) == 0);
  CHECK(elapsed_since(&start) >= 2.0);

  // The stop signals are unblocked again afterwards.
  sigset_t mask;
  sigprocmask(SIG_BLOCK, NULL, &mask);
  CHECK(!sigismember(&mask, SIGTERM) && !sigismember(&mask, SIGINT));
  g_stop = 0;
}

// Writes frames that cover each band and the edge cases to `path`, for
// checking with Wireshark or tshark.
static void write_sample(const char *path) {

  enum { N = 6 };
  struct nl_msg *msgs[N];
  uint8_t *big = make_ies(6000);
  static const uint32_t freqs[] = {2412, 5180, 5955, 6115, 5885, 2437};

  for (int k = 0; k < N; k++) {
    struct test_bss t = default_bss();
    t.freq = freqs[k];
    if (k == 3) {
      t.ies = big; // larger than the old 2048-byte limit
      t.ies_len = 6000;
    } else if (k == 4) {
      t.has_signal = 0;
    } else if (k == 5) {
      t.has_beacon_int = 0;
    }
    msgs[k] = make_bss_msg(&t);
  }

  struct frame f[N];
  int n = dump_frames(msgs, N, f, N, path);
  CHECK(n == N);
  for (int k = 0; k < N && k < n; k++) {
    free(f[k].data);
    nlmsg_free(msgs[k]);
  }
  free(big);
  printf("wrote %d sample frames to %s\n", n, path);
}

int main(int argc, char *argv[]) {

  test_frame_layout();
  test_large_ies();
  test_mixed_sizes();
  test_optional_attributes();
  test_incomplete_results();
  test_probe_response_and_beacon();
  test_radio_metadata();
  test_frame_len_bounds();
  test_timestamps();
  test_parsing();
  test_exit_status();
  test_output_errors();
  test_wait();
  if (argc > 1) {
    write_sample(argv[1]);
  }

  if (failures) {
    fprintf(stderr, "%d check(s) failed\n", failures);
    return 1;
  }
  printf("all tests passed\n");
  return 0;
}
