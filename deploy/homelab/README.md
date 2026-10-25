# AEGIS home lab kit: scripts

Scripts to test **one streaming box you own** on an isolated Wi-Fi network and capture its
traffic **metadata only**. Read [the home-lab guide](../../docs/homelab/GUIDE.md) first: it covers
safety, legality (France / EU), responsible disclosure and what you may and may not say about a
device afterwards.

| script | where | what |
|---|---|---|
| `homelab.env.example` | all | configuration; copy to `homelab.env` and set `LAB_PASSPHRASE` |
| `setup-ap.sh` | Raspberry Pi OS / Debian | isolated WPA2 access point (hostapd, client isolation), dnsmasq DHCP + logged DNS, nftables NAT and isolation, optional rate cap |
| `capture.sh start\|stop\|status` | Pi, Linux laptop | header-only rotating capture (`tcpdump -s 96`) with a hard time limit, manifest, dnsmasq log collection |
| `zeek-convert.sh CAPTURE_DIR` | anywhere with Zeek | offline pcap to Zeek `conn.log` / `dns.log` |
| `laptop-hotspot-linux.sh start\|stop` | Linux laptop (NetworkManager) | same isolation with a NetworkManager hotspot |
| `laptop-hotspot-macos.sh start\|stop` | macOS (Internet Sharing) | pf anchor + header-only capture (+ DNS-only capture at 512 bytes) |
| `teardown.sh [--purge-captures]` | Pi, Linux laptop | removes everything the scripts created; restores forwarding and service states |

Every script is idempotent (safe to re-run), refuses a snaplen above 128 bytes, and only removes
files that carry its "managed by aegis-homelab" marker.

```bash
cp homelab.env.example homelab.env && $EDITOR homelab.env     # LAB_PASSPHRASE, interfaces, country
sudo ./setup-ap.sh                                             # Pi: access point up
# join ONLY the device under test to the lab Wi-Fi, then:
sudo ./capture.sh start box1                                   # stops by itself after MAX_HOURS
# ... use the box as usual and note when you use it (usage.json, see the guide) ...
sudo ./capture.sh stop
./zeek-convert.sh /var/lib/aegis-homelab/captures/box1
python -m aegis.homelab analyze /var/lib/aegis-homelab/captures/box1 --out ./box1-report --label 10.42.0.23="box 1"
sudo ./teardown.sh
```

Lab defaults: SSID `aegis-lab`, network `10.42.0.0/24`, gateway `10.42.0.1`, DHCP `.20` to `.60`,
upstream DNS Quad9, rate cap 500 kB/s each way, capture 72 h maximum.
