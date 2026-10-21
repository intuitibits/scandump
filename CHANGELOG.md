# Changelog

## 2.3.0 — unreleased

Packaging and documentation release, with small robustness fixes.
Scanning and PCAP output are unchanged.

- Report write errors (for example, a full disk) and exit non-zero instead
  of leaving a truncated PCAP file and exiting 0.
- Validate the interface index in scan events before reading it.
- Retry transient scan failures by their libnl error codes instead of
  errno values that happened to share the same numbers. Which errors are
  retried is unchanged.
- Document the exit statuses in `scandump(8)`. They are unchanged, except
  that giving up after 30 consecutive transient failures now exits with
  240 (as early versions did when retries ran out) instead of 255.
- Add `-V` as a short form of `--version`. The version line always reads
  `scandump version X.Y.Z`, whatever name scandump was invoked as.
- Print the usage summary to stderr when it accompanies an error; `-h`
  still prints it to stdout. The summary now explains `-c 0` and `-` for
  standard output.
- Add a `scandump(8)` manual page.
- Makefile: honor `CC`, `CFLAGS`, `CPPFLAGS`, `LDFLAGS`, `LDLIBS` and
  `PKG_CONFIG`; install to `PREFIX`/`BINDIR`/`MANDIR` under `DESTDIR`; add
  `uninstall` and `dist` targets; find libnl and libpcap with pkg-config;
  `WERROR=` disables `-Werror` for distribution builds.
- The Debian package no longer installs `/etc/sudoers.d/scandump`, which
  gave every member of the `sudo` group passwordless root access to
  scandump. The rule now ships as an example in
  `/usr/share/doc/scandump/examples/sudoers`. See *Permissions* in the README
  for opt-in setups. Upgrading an existing package leaves a previously
  installed rule in place.
- Add Arch Linux (`PKGBUILD`) and Fedora (RPM spec) packaging and CI
  validation of all package builds.
- State the license (GPL-3.0-only) in the source and update copyright
  years.

## 2.2.1 — 2026-08-14

- Ignore scan events for other interfaces so a scan started by another
  process (e.g. wpa_supplicant) is no longer reported as an aborted scan.

## 2.2.0 — 2026-08-14

- Fix an indefinite wait when the kernel rejects the scan trigger (e.g.
  `-EBUSY` while another process is scanning) instead of retrying.
- Add a receive timeout and SIGINT/SIGTERM handling so a stuck driver or
  Ctrl-C can no longer hang the process.
- Validate the BSSID attribute length before copying it into the packet
  buffer.
- Check the previously-unchecked netlink calls and bound the transient
  error retry loop.
- Reject invalid, out-of-range and duplicate values for `-c` and `-f`, and
  report a clear error for an unknown interface name.
- Refuse to follow a symlink at the output path. File permissions are
  unchanged, matching tcpdump (0666 as masked by umask).
- Build with `-O2` and honor the environment's `CFLAGS`/`CPPFLAGS`/`LDFLAGS`
  so the package build's hardening flags are applied.

## 1.0.4 — 2023-05-26

- Initial release.
