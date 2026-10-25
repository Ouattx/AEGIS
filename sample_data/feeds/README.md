# Synthetic threat-feed fixtures

Small, hand-written files in the published formats of public threat feeds, used by
`tests/unit/test_intel*.py` and for offline demos of `aegis.intel`.

**Everything here is synthetic.** Addresses come only from IETF documentation and
benchmarking ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 198.18.0.0/15,
2001:db8::/32) and names only from reserved suffixes (`.example`, `.test`). No row
describes real infrastructure, a real report or a real subscriber.

| file | format | what it exercises |
|---|---|---|
| `urlhaus_recent.csv` | abuse.ch URLhaus CSV dump | host extraction from URLs, offline URLs, shared-platform skip (GitHub), private IP and malformed rows rejected |
| `threatfox_recent.json` | abuse.ch ThreatFox JSON export | `ip:port`, domain and URL IOCs, hash skipped, expired IOC, shared-platform skip, cross-feed dedup with URLhaus (same independence group) |
| `feodo_ipblocklist.csv` / `.txt` | Feodo Tracker IP blocklist | snapshot feed (withdrawal on re-import), offline C2 |
| `spamhaus_drop.txt` / `spamhaus_drop_v4.json` / `spamhaus_edrop.txt` | Spamhaus DROP / EDROP (text and JSON lines) | CIDR indicators, `/32` collapsed to an IP, private prefix rejected, IPv6 |
| `shadowserver_event4_sinkhole_http.csv` | Shadowserver sinkhole report | victim lines pseudonymized at parse time, sinkholed C2 names as indicators, sinkhole IP skipped |
| `shadowserver_botnet_drone.csv` | Shadowserver drone report (legacy columns) | C2 from `cc` (IP and `host:port`) |
| `shadowserver_scan_telnet.csv` | Shadowserver scan report | exposure only: never treated as compromise |

In the tests, the operator's subscriber space is 198.18.0.0/15.
