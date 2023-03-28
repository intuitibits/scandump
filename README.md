# scandump

A command-line utility that scans for Wi-Fi networks using the 802.11 netlink API and outputs the scan results in PCAP format.

## Installation

```shell
# Install pre-requisites
sudo apt update
sudo apt install git libnl-genl-3-dev libpcap-dev

# Download, build, and install scandump
git clone https://github.com/intuitibits/scandump.git
cd scandump
make
sudo make install
```

## Usage

```shell
Usage: scandump <interface> <filename>
       scandump --version
```

Where `<interface>` is the name of the WLAN interface (e.g. `wlan0`), and `<filename>` is the name of the PCAP file to be generated. Standard output is used if file is `-`.

The command must be run as root since only privileged users can initiate a scan.

## Example

Scan for Wi-Fi networks on `wlan0` and save the scan results to `scan.pcap`:
```console
$ sudo scandump wlan0 scan.pcap
```

Scan for Wi-Fi networks on `wlan0` and output the scan results to standard output in PCAP format:
```console
$ sudo scandump wlan0 -
```
