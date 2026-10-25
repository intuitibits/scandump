# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

`scandump` is a Linux command-line utility that triggers a Wi-Fi scan via the
802.11 netlink API (`nl80211`) and writes the results directly to a PCAP file
as synthetic radiotap + 802.11 beacon frames. It exists so callers don't have
to scrape `iw`'s text output. It is a single-file C program (`scandump.c`).

## Build

```shell
make            # builds ./scandump
make clean      # removes build artifacts
sudo make install   # installs scandump and scandump.8 under $(DESTDIR)$(PREFIX) (default /usr)
sudo make uninstall
make dist       # scandump-$(VERSION).tar.gz from HEAD (excludes debian/)
```

Build dependencies (Debian/Ubuntu): `libnl-genl-3-dev`, `libnl-3-dev`, `libpcap-dev`, `pkg-config`, `build-essential`.

Compiler flags are strict: `-Wall -Wextra ... -Werror -std=c99` (see
`Makefile`). Warnings fail the build, so treat any new warning as a bug to fix,
not suppress. Only distribution packaging passes `WERROR=` to drop `-Werror`.
The Makefile appends its flags to the environment's `CFLAGS`/`CPPFLAGS`/
`LDFLAGS`/`LDLIBS` and gets library flags from pkg-config; keep it that way so
distro build systems keep working.

`make check` runs the tests that need no wireless hardware (Linux only, as
they include the libnl headers): `tests/test_scandump.c` includes
`scandump.c` with `main` renamed and feeds synthetic nl80211 scan results to
`callback_dump`, reading back the PCAP it writes, and also tests parsing,
exit statuses and the interval wait; `tests/cli.sh` checks option handling
and exit statuses of the built binary. `./tests/test_scandump sample.pcap`
also writes sample frames for checking with Wireshark/tshark. Debian's build
runs `make check` (with `WERROR=`). Scanning itself is verified by running
`scandump` against a real wireless interface (requires root and a Linux
host with `nl80211` support — this won't run/test on macOS), or
`.github/workflows/functional.yml`, which scans `mac80211_hwsim`
radios on pull requests that change `scandump.c` (or on demand). Build and
packaging checks run in containers via `packaging/ci/*.sh`
(see `packaging/README.md`) and in `.github/workflows/ci.yml`.

```shell
sudo ./scandump wlan0 scan.pcap        # capture to a file
sudo ./scandump wlan0 -                # stream PCAP to stdout
sudo ./scandump -f 2412,5180 wlan0 scan.pcap   # restrict to specific frequencies (MHz)
sudo ./scandump --passive wlan0 scan.pcap      # passive scan (no probe requests)
sudo ./scandump -c 5 wlan0 scan.pcap   # stop after 5 scans
sudo ./scandump -c 5 -i 10 wlan0 scan.pcap   # ... waiting 10 s between scans
```

## Packaging

- `debian/` is the Debian/Ubuntu source package (`3.0 (quilt)`, maintainer
  `Adrian Granados <support@intuitibits.com>`). `.gitattributes` keeps it out
  of release tarballs.
- `packaging/arch/PKGBUILD` and `packaging/fedora/scandump.spec` hold the
  Arch and Fedora packaging.
- Keep this repository to public, user- or contributor-relevant material:
  source, build files, packaging and their docs. Release checklists,
  submission notes and security reviews are kept outside the repository.
- No package may grant privileges: no sudoers rule, setuid bit, file
  capability or maintainer script. The CI scripts enforce this. The
  passwordless-sudo rule ships only as `examples/sudoers`, because it lets
  any `sudo`-group user overwrite any file as root (see *Permissions* in
  `README.md`).
- When cutting a release, keep the version in sync across `VERSION` in
  `scandump.c`, `scandump.8`, `CHANGELOG.md`, `debian/changelog`, the spec
  and the PKGBUILD.
- Copyright is `Intuitibits LLC` and the license is GPL-3.0-only.

## Architecture

Everything is in `scandump.c` and follows one flow:

1. **Netlink/genl setup** (`main`): allocate an `nl_sock`, connect to the
   generic netlink family, and resolve the `nl80211` family ID.
2. **Trigger a scan** (`do_scan_trigger`): sends `NL80211_CMD_TRIGGER_SCAN`
   for the given interface, optionally with an SSID list (active scan, the
   default) or frequency list (`-f`), then blocks on `nl_recvmsgs` until the
   kernel reports `NL80211_CMD_NEW_SCAN_RESULTS` or
   `NL80211_CMD_SCAN_ABORTED` via `callback_trigger`. Passive scan (`-p`)
   simply omits the SSID attribute.
3. **Retry policy** (`main`'s scan loop): `-NLE_BUSY`, `-NLE_DUMP_INTR`,
   `-NLE_SEQ_MISMATCH` and `-ETIMEDOUT` from `do_scan_trigger` are treated
   as transient (another process may be scanning) and retried after a
   2-second `wait_seconds`; any other error is fatal (with a hint from
   `report_scan_error_hint`). A scan that comes back `aborted` is
   logged and the loop continues rather than exiting. Netlink failures are
   libnl `-NLE_*` codes, not errnos (the kernel's `EBUSY` arrives as
   `-NLE_BUSY`); only local failures such as the `poll()` timeout are
   `-errno`. Keep the two apart when touching this logic. Exit statuses are
   a public interface (callers map 225 and 240 to specific errors): 1 for
   usage, 240 when retries run out, 255 for other failures,
   and `256 + err` for a fatal scan error. They are documented in
   `scandump.8`; don't change them.
4. **Dump scan results** (`do_scan_dump`, `callback_dump`): once a scan
   completes, sends `NL80211_CMD_GET_SCAN` and, for each BSS the kernel
   reports, synthesizes a fake over-the-air frame. The frames are only
   collected in `dump_context`; `write_frames` writes them once the whole
   dump has been read, so a failed dump leaves nothing in the output. A
   dump interrupted by a change to the kernel's table (`-NLE_DUMP_INTR`) is
   read again (`MAX_DUMP_ATTEMPTS`); any other failed dump is retried like
   a transient trigger error, by scanning again, and isn't counted.
   - Collects the BSS's attributes into a `struct bss_frame`. BSSID,
     frequency, TSF, capability and information elements are required
     (a result without them is skipped with a warning); signal and beacon
     interval are optional, since nl80211 omits them for non-dBm drivers
     and a zero interval. TSF and IEs both come from
     `NL80211_BSS_TSF`/`NL80211_BSS_INFORMATION_ELEMENTS` (the latest probe
     response or beacon); the `BEACON_*` attributes are deliberately unused
     so the two never come from different frames.
   - `build_frame` writes the radiotap header (Flags, Channel and, when
     known, dBm Antenna Signal; 15 bytes, or 14 without signal), the
     802.11 beacon header and fixed fields (36 bytes), and the IEs
     unchanged, into `dump_context`'s buffer (one length-prefixed record per
     frame), which is grown with `realloc` as needed and reused. Nothing is truncated; `frame_len`
     returns 0 for a frame over `PCAP_SNAPLEN` (262144), which an nl80211
     attribute can't reach.
   - `write_frames` writes each frame via `pcap_dump`, with caplen = len =
     the frame length, stamped with the time it is written. Don't switch to the BSS's last-seen time: the kernel's scan
     results include networks heard up to ~30 s earlier (scandump itself
     caches nothing), so records would go out of order. Running out of memory sets
     `dump_context.err`, stops the dump and exits 255.
   - The frame layout is fixed by `tests/test_scandump.c`
     (`test_frame_layout` checks it byte for byte); keep the radiotap
     length field, present bitmap and field offsets in `build_frame`
     consistent if the layout changes.
5. **Output**: PCAP data is written via libpcap (`pcap_dump_open`/
   `pcap_dump_fopen`), to a file or to stdout when the filename is `-`.
   `DLT_IEEE802_11_RADIO` is the link type, matching the synthesized
   radiotap-prefixed frames. `pcap_dump()` can't report errors, so
   `check_output` flushes and checks the stream after each scan (file or
   stdout) and before closing; a write error stops the loop with a non-zero
   exit. SIGPIPE is ignored, so a reader closing the pipe shows up as
   `-EPIPE`, which stops the loop quietly with status 0. A write to an
   output that isn't a regular file (`output_can_block`) can block for as
   long as the reader doesn't read, and the C library retries a partial
   write without returning, so `g_stop` would go unseen; while such a write
   is in progress `g_exit_on_stop` is set and a stop signal calls
   `_exit(0)` from the handler instead, cutting off the scan being written.

The scan loop in `main` repeats indefinitely unless `-c/--count` is given,
waiting `-i/--interval` seconds between scans (not before the first or after
the last) with `wait_seconds`, which sleeps on the monotonic clock via
`ppoll` with SIGINT/SIGTERM blocked outside it, so a stop signal can't be
missed. The pcap dumper is opened lazily (only after the first successful scan) so no
empty/partial file is created if the very first scan fails outright.
