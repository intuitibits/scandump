# scandump

A command-line utility that scans for Wi-Fi networks using the 802.11 netlink API and outputs the scan results in PCAP format.

Typically, processes that need to gather data about nearby Wi-Fi networks would do a scan using [iw](https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw.html) and scrape its text output. However, it is generally a bad idea to try parsing another program's output if it is not designed to be consumed by other processes. The text may change with newer updates or simply by running the program on a different system. 

With **scandump**, no more scraping is needed. As an additional benefit, you can generate a PCAP file with radiotap + beacon frame data from the scan using a wireless interface that may not support monitor mode.

## Features

- Triggers active (default) or passive scans through `nl80211`, optionally restricted to a list of frequencies.
- Writes one radiotap + 802.11 beacon frame per network found, including BSSID, frequency and band, signal strength, TSF, beacon interval, capabilities and all information elements reported by the driver, however large (see [Limitations](#limitations)).
- Writes to a file or streams to standard output, so it can be piped into `tcpdump`, Wireshark or your own PCAP reader.
- Scans repeatedly (or a fixed number of times with `-c`, optionally waiting between scans with `-i`), retrying automatically while another process is scanning, and exits cleanly on Ctrl-C/SIGTERM.
- Reports failures with stable, documented [exit statuses](#exit-status), so scripts can tell a missing interface from missing privileges.

## Requirements

- Linux with nl80211/cfg80211 support and a wireless interface whose driver supports scanning. Any architecture is supported.
- Runtime libraries: libnl-3, libnl-genl-3 and libpcap.
- Build tools: a C99 compiler (GCC or Clang), GNU make and pkg-config.

## Installation

### From source

Install the build dependencies:

```shell
# Debian / Ubuntu
sudo apt install build-essential pkg-config libnl-3-dev libnl-genl-3-dev libpcap-dev

# Fedora
sudo dnf install gcc make pkgconf-pkg-config libnl3-devel libpcap-devel

# Arch Linux
sudo pacman -S --needed base-devel libnl libpcap
```

Then build and install:

```shell
git clone https://github.com/intuitibits/scandump.git
cd scandump
make
sudo make install
```

`make install` installs `scandump` to `/usr/bin` and its manual page to `/usr/share/man/man8`. The usual variables are honored:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PREFIX` | `/usr` | Installation prefix |
| `BINDIR` | `$(PREFIX)/bin` | Executable directory |
| `MANDIR` | `$(PREFIX)/share/man` | Manual page root |
| `DESTDIR` | *(empty)* | Staging root for packaging |
| `CC`, `CFLAGS`, `CPPFLAGS`, `LDFLAGS`, `LDLIBS` | | Compiler and linker settings; project warning and hardening flags are appended |
| `WERROR` | `-Werror` | Set `WERROR=` to stop treating warnings as errors |

For example, `make PREFIX=/usr/local && sudo make PREFIX=/usr/local install`. Use `sudo make uninstall` (with the same variables) to remove the installed files.

### Debian / Ubuntu package

The repository contains Debian packaging. With the build dependencies above installed, build a binary package locally:

```shell
sudo apt install debhelper devscripts
dpkg-buildpackage -b -us -uc
sudo apt install ../scandump_*.deb
```

Packaging for Arch Linux and Fedora lives in [`packaging/`](packaging/).

## Usage

```shell
Usage: scandump [-c count] [-i interval] [-f frequency-list] [-p] [-h] [-V] <interface> <filename>
Options:
  -c, --count         Exit after the specified number of scans
                      (default 0: scan until interrupted)
  -i, --interval      Wait the specified number of seconds between scans
                      (default 0: start the next scan right away)
  -f, --frequency     Comma-separated list of frequencies in MHz to scan
  -p, --passive       Use passive scan mode
  -h, --help          Display this help message
  -V, --version       Show version
Use - as <filename> to write to standard output.
```

Where `<interface>` is the name of the WLAN interface (e.g. `wlan0`), and `<filename>` is the name of the PCAP file to be generated. The file is created only after the first scan succeeds. See `man 8 scandump` for details.

The interval is a whole number of seconds from 0 to 86400, counted from the end of one scan (once its results are written) to the start of the next. There is no wait before the first scan or after the last one, and Ctrl-C or SIGTERM ends a wait right away.

## Permissions

Triggering a scan requires the `CAP_NET_ADMIN` capability, so scandump is normally run as root (e.g. with `sudo`). Installing scandump, from source or from a package, does not grant any privileges by itself; choose one of the options below if needed.

**Grant the capability to the binary.** Deployments that prefer to avoid running the tool as root can grant just that capability:

```shell
sudo setcap cap_net_admin+ep /usr/bin/scandump
```

**scandump** can then be run by any local user. The output file is created with the privileges of the calling user in that case. Some drivers or setups may still need more than `CAP_NET_ADMIN`, so test this before relying on it. Package upgrades replace the binary and drop the capability, so reapply it after upgrading.

**Allow passwordless sudo.** An example rule that lets members of the `sudo` group run scandump without a password is provided in [`examples/sudoers`](examples/sudoers) (installed by the Debian package as `/usr/share/doc/scandump/examples/sudoers`):

```shell
sudo install -m 0440 /usr/share/doc/scandump/examples/sudoers /etc/sudoers.d/scandump
sudo visudo -c
```

Be aware that a user who can run scandump as root can overwrite any file on the system with PCAP data, because scandump writes to whatever output path it is given. Only grant this to users you would trust with root, or prefer the capability option.

## Examples

Scan for Wi-Fi networks on `wlan0` and save the scan results to `scan.pcap`:
```console
$ sudo scandump wlan0 scan.pcap
```

Scan for Wi-Fi networks on `wlan0` and output the scan results to standard output in PCAP format:
```console
$ sudo scandump wlan0 -
```

Scan for Wi-Fi networks on `wlan0` using channels 1 (2.4 GHz) and 36 (5 GHz) only:
```console
$ sudo scandump -f 2412,5180 wlan0 scan.pcap
```

Scan for Wi-Fi networks on `wlan0` passively (don't transmit probe requests):
```console
$ sudo scandump --passive wlan0 scan.pcap
```

Scan 10 times, waiting 5 seconds between scans:
```console
$ sudo scandump --count 10 --interval 5 wlan0 scans.pcap
```

Do a single scan and print the networks found with tcpdump:
```console
$ sudo scandump -c 1 wlan0 - | tcpdump -r - -e
```

## Troubleshooting

Errors from the kernel are reported through libnl, so the number in parentheses is a libnl error code rather than an errno value. For the common ones, scandump prints a hint on the next line.

| Message | Cause and fix |
| --- | --- |
| `nl80211: Operation not permitted (-28)` | Missing `CAP_NET_ADMIN`. Run with `sudo` or see [Permissions](#permissions). |
| `wlan0: No such device` | No interface with that name. List wireless interfaces with `iw dev`. |
| `nl80211: No such device (-31)` | The interface exists but is not a Wi-Fi interface. |
| `nl80211: Object not found (-12)` | The kernel has no nl80211 support (cfg80211 is not loaded). |
| `nl80211: Network is down (-36)` | The interface is down. Bring it up with `sudo ip link set wlan0 up`. |
| `nl80211: Object busy (-25)`, repeated | Another process (often NetworkManager or wpa_supplicant) is scanning. scandump retries every 2 seconds. |
| `nl80211: scan aborted` | The driver or another process cancelled the scan; scandump continues with the next one. |
| `nl80211: timed out after 30 seconds waiting for a reply` | The driver never reported scan completion; scandump retries. |
| `nl80211: giving up after 30 consecutive transient errors` | The interface stayed busy, or the driver stopped responding, for about a minute. Stop the other scanning process or reload the driver. |
| `scan.pcap: Too many levels of symbolic links` | The output path is a symlink, which scandump refuses to follow. Write to a regular path. |
| `scan.pcap: No space left on device` | Writing the output failed. scandump stops and exits with an error, and the file may be incomplete. Free up space or write elsewhere. |
| `nl80211: Operation not supported (-10)` | The driver does not support scanning, or the requested kind of scan. |
| `nl80211: reading scan results: ...` | The scan's results could not be read in full. Nothing from that scan is written, it doesn't count towards `-c`, and scandump scans again after 2 seconds. |
| `nl80211: skipping incomplete scan result` | The kernel reported a network without the data needed to build a frame (for example, no information elements). That network is left out; the scan continues. |

## Exit status

Scripts can rely on these values:

| Status | Meaning |
| --- | --- |
| 0 | The requested number of scans completed, scandump was interrupted, or the program reading its standard output closed the pipe (e.g. `tcpdump -c 5`). |
| 1 | Invalid arguments, or no interface with the given name. |
| 240 | Gave up after 30 consecutive transient failures. |
| 255 | Any other error, such as an output file that cannot be created or written. |
| 256 − *N* | A scan failed with the netlink error *N* shown in the message, e.g. 225 for `No such device (-31)` (not a Wi-Fi interface) or 228 for `Operation not permitted (-28)` (missing `CAP_NET_ADMIN`). |

## Limitations

The frames are reconstructed from the kernel's scan results, not captured over the air, so they differ from the frames the access points sent:

- Every frame is written as a beacon, even when the kernel's most recent data for a network came from a probe response (which is usual after an active scan). Its information elements and timestamp then come from that probe response, which, unlike a beacon, has no TIM element and carries the real SSID of a hidden network. scandump never mixes beacon and probe response data in one frame.
- The destination is always the broadcast address, the sequence number and duration are 0, and there is no FCS.
- Each scan writes every network in the kernel's scan results, the same table `iw dev wlan0 scan` shows, not only the networks that scan heard. The kernel keeps a network there for about 30 seconds after it last received a frame from it (longer for the network the interface is connected to), whichever process's scan or connection received that frame, e.g. NetworkManager or wpa_supplicant. So a scan can include networks it missed and, with `-f`, networks on other channels. scandump itself keeps no results between scans.
- The PCAP timestamp is when the results were written, not when the frame was received, so that records are always in time order. A network the kernel still reports from an earlier frame is written with each scan's time.
- The signal is the kernel's value rounded toward zero to whole dBm. Drivers that don't report signal in dBm get no signal field, rather than a made-up one.
- Networks the kernel reports without information elements are skipped, since a beacon without them would be malformed.

## Contributing

Bug reports and pull requests are welcome on [GitHub](https://github.com/intuitibits/scandump). The build treats compiler warnings as errors, so `make` must succeed without warnings. `make check` runs the tests that don't need Wi-Fi hardware: frame construction from synthetic nl80211 scan results, option parsing and exit statuses. CI builds with GCC and Clang, runs static analysis, and builds and checks the Debian, Ubuntu, Arch and Fedora packages on every pull request. To run the package checks locally, see [`packaging/README.md`](packaging/README.md).

## License

Copyright (c) 2023-2026 Intuitibits LLC. Written by Adrian Granados.

scandump is licensed under the GNU General Public License, version 3. See [LICENSE](LICENSE).
