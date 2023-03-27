# scandump

A command-link utility that scans for Wi-Fi networks using the 802.11 netlink API and outputs the scan results in PCAP format.

## Installation

```
sudo apt update
sudo apt install libnl-genl3-dev
sudo apt install libpcap-dev

git checkout https://github.com/intuitibits/scandump.git
cd scandump
make
sudo make install
```

## Usage

```
Usage: scandump --version
       scandump <interface> <filename>
```

Where `<interface>` is the name of the WLAN interface (e.g. `wlan0`), and `<filename>` is the name of the PCAP file to be generated. Standard output is used if file is `-`.

The command must be run as root since only privileged users can initiate a scan.

## Example
```
sudo scandump wlan0 scan.pcap
```
