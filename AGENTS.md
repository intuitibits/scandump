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

There is no unit test suite. Verifying behavior changes means building and
running `scandump` against a real wireless interface (requires root and a Linux
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
   `sleep(2)`; any other error is fatal. A scan that comes back `aborted` is
   logged and the loop continues rather than exiting. Netlink failures are
   libnl `-NLE_*` codes, not errnos (the kernel's `EBUSY` arrives as
   `-NLE_BUSY`); only local failures such as the `poll()` timeout are
   `-errno`. Keep the two apart when touching this logic. Exit statuses are
   a public interface (callers map 225 and 240 to specific errors): 1 for
   usage, 240 when retries run out, 255 for other failures,
   and `256 + err` for a fatal scan error. They are documented in
   `scandump.8`; don't change them.
4. **Dump scan results** (`callback_dump`): once a scan completes, sends
   `NL80211_CMD_GET_SCAN` and, for each BSS the kernel reports, synthesizes a
   fake over-the-air frame:
   - Starts from the constant `packet_header` byte array — a pre-built
     radiotap header + 802.11 beacon frame header/addressing — and patches in
     per-BSS fields by direct byte offset (frequency, channel flags derived
     from the band, RSSI, transmitter/BSSID address, beacon TSF, beacon
     interval, capability).
   - Appends the raw information elements (`NL80211_BSS_INFORMATION_ELEMENTS`)
     as the beacon frame body, truncated to `MAX_PACKET_SIZE` (2048 bytes).
   - Writes the resulting frame to the open `pcap_dumper_t` via `pcap_dump`.
   - **When touching `packet_header` or the byte-offset patches in
     `callback_dump`, offsets are positional and coupled** — the radiotap
     header length field (bytes 2–3) and the offsets used later
     (e.g. `packet[10]`, `packet[25]`, `packet[39]`, ...) must stay
     consistent with each other if the header layout changes.
5. **Output**: PCAP data is written via libpcap (`pcap_dump_open`/
   `pcap_dump_fopen`), to a file or to stdout when the filename is `-`.
   `DLT_IEEE802_11_RADIO` is the link type, matching the synthesized
   radiotap-prefixed frames. `pcap_dump()` can't report errors, so
   `check_output` checks the stream after each scan and before closing;
   a write error stops the loop with a non-zero exit.

The scan loop in `main` repeats indefinitely unless `-c/--count` is given, and
the pcap dumper is opened lazily (only after the first successful scan) so no
empty/partial file is created if the very first scan fails outright.
