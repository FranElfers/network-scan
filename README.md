# Network Device Scanner

Lightweight CLI scanner in Go. Maps your local network (nmap) and nearby Bluetooth devices (btmgmt), and labels each device with an emoji based on its OS, open ports and MAC address.

## Features

- One nmap run: host discovery, top-50 port scan, service versions and OS fingerprinting (`-O`)
- Host names via mDNS (unicast reverse lookup), falling back to NetBIOS
- Device type heuristics: default gateway / router 🖧, phone 📱, TV 📺, IP camera (RTSP) 📷, computer 💻
- Phones that hide behind a randomized Wi-Fi MAC are flagged as probable phones 📱?
- Lists named Bluetooth devices (in a separate section, since Bluetooth and Wi-Fi MACs differ)
- Auto-detects the network of the default-route interface

## Requirements

- Linux (reads `/proc/net/route`)
- Go 1.27+
- `nmap` in PATH
- Root (nmap needs it for MAC addresses and OS detection; the program exits otherwise)
- Optional: BlueZ `btmgmt` and `script` (util-linux) for Bluetooth. Skipped if `btmgmt` is missing.

## Build

```bash
go build .   # produces ./network-scan
go test .
```

## Usage

```bash
sudo ./network-scan                   # auto-detect network
sudo ./network-scan 192.168.1.0/24    # explicit target
sudo ./network-scan -mac              # also show MAC addresses
sudo ./network-scan -v                # hide the [*] progress logs
```

Auto-detection uses the subnet of the default-route interface, narrowed to a `/24` around your IP when the subnet is larger. Pass a CIDR to scan something else.

### Example output

```
IP              Name                 OS                        Ports                     Version                   Device
---             ----                 --                        -----                     -------                   -----
192.168.100.1                        Linux 3.10 - 4.11         53/tcp,80/tcp,49152/tcp   -                         🖧
192.168.100.13                       Linux 3.2 - 4.14          80/tcp,554/tcp            -                         📷
192.168.100.68                                                 none                      -                         📱?
192.168.100.230 lenovo               Linux 5.0 - 6.2           22/tcp                    OpenSSH 10.6              💻

📡 Bluetooth
Mi Smart Band 4
```

## Notes

- Device detection is heuristic and can be wrong; phones usually expose no open ports, so 📱? (randomized MAC) is often the only signal.
- A phone shows up over Bluetooth only while its Bluetooth settings screen is open.
- Scan time grows with network size; OS detection adds a few seconds per host.
