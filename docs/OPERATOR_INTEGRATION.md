# Operator telemetry integration guide

What to send AEGIS, from where, in which format, and what each vantage point can and cannot detect. Read
this with the network architect and the DPO before the pilot kick-off: the vantage points chosen decide both
the detection coverage and the data-protection footprint.

## 1. Principles

* **Security metadata only.** Flow records and DNS query/response metadata. No packet payloads, no TLS
  decryption, no URLs or HTTP content, no subscriber names, contracts or addresses.
* **Pseudonymize at the edge of AEGIS.** The entity identifier (device MAC from a CPE, or the subscriber-side
  IP) is replaced at ingest by `p_<hmac>` keyed per tenant. The subscriber source IP is validated and then
  dropped from the stored event. The mapping back to a subscriber stays with the operator (section 6).
* **Authorized collection only.** Every source is registered with a `collection_authorization_id` (the
  operator's internal reference for the legal basis and DPIA). Events from unregistered sources or with an
  unknown authorization are refused and counted.
* **Nothing is silently dropped.** Unparseable or invalid records are quarantined with their original bytes
  and a reason code, kept for the source's `retention_days`, and visible to the tenant admin.

## 2. Vantage points at a glance

| Vantage | AEGIS `source_kind` / `vantage` | Identity AEGIS sees | Typical sampling |
|---|---|---|---|
| Core / BNG NetFlow v9 or IPFIX | `netflow` / `subscriber_line` | one pseudonym per subscriber line (or per CGNAT-inside address) | often 1:100 to 1:1000 |
| Operator resolver query logs (dnstap, BIND/Unbound/PowerDNS/Knot query logs as JSON lines) | `dns` / `subscriber_line` | one pseudonym per client address of the resolver | unsampled |
| Zeek sensor on an aggregation link | `zeek_conn` + `zeek_dns` / `subscriber_line` | one pseudonym per inside address seen by the sensor | unsampled (capacity-bound) |
| Operator-managed CPE / home gateway agent | `cpe` (or `netflow`/`dns` exports from the CPE) / `device` | one pseudonym per device behind the gateway, plus a device-class hint | unsampled, per device |

### What each vantage can and cannot detect

| Behaviour | Core NetFlow/IPFIX | Resolver DNS | Zeek | CPE / gateway |
|---|---|---|---|---|
| Contact with a known C2 IP from a signed IOC bundle | yes | no (sees names, not connections) | yes | yes |
| Lookup of a known C2 / malware domain | no | yes | yes (dns.log) | yes (if the CPE exports DNS) |
| DGA activity (NXDOMAIN storms, many random names) | no | yes | yes | yes |
| Periodic beaconing of one device | weak when sampled; merged with other devices behind the home NAT | yes for name-based C2 when lookups repeat (DNS caching hides some) | yes, at line level | yes, per device |
| Residential-proxy egress (many outbound sessions to unrelated destinations) | yes at line level | partial | yes | yes, per device |
| DDoS-bot bursts | yes | no | yes | yes |
| Which device in the home is compromised | no | no | no | yes |
| C2 over DoH/DoT to a third-party resolver | flow-level contact only (IOC IP) | no | flow-level only | flow-level only |
| Content, URLs, credentials, viewing behaviour | never collected | never collected | never collected | never collected |

How to read it: a subscriber-line vantage can say "this line hosts at least one device behaving like a
compromised host", never "this device" or "this person". Device-level attribution needs the CPE vantage.
Device class (from a CPE hint) selects the comparison baseline only; AEGIS never treats a device class,
vendor, IPTV app or geography as evidence of compromise.

## 3. NAT, CGNAT and IPv6 caveats

* **Home NAT.** Behind a subscriber line sit several devices. Line-level telemetry mixes them: a beacon
  from one TV box is diluted by the household's other traffic, and benign periodic apps (push, NTP, IPTV
  heartbeats) are present on almost every line. AEGIS treats per-line periodicity alone as weak evidence.
* **Carrier-grade NAT.** Collect on the subscriber side of the CGNAT (BNG / inside interface), where each
  line still has its own address. Flows exported after the CGNAT carry shared public addresses: one public
  IP maps to many subscribers over time, so per-entity baselines are meaningless there. AEGIS v1 does not
  ingest CGNAT translation logs; do not register post-CGNAT exports as `subscriber_line` sources.
* **Dynamic addressing.** If subscriber IPs change (DHCP/PPP re-assignment), the pseudonym follows the
  address, not the subscriber. Prefer exports keyed by a stable line identifier where the collector can add
  one (`device_id` column; it is pseudonymized like an address). Otherwise a renumbered line appears as a new
  entity: recall drops, false attribution does not increase.
* **IPv6.** Each address is an entity. Hosts using temporary (privacy) addresses therefore appear as several
  short-lived entities, which weakens per-entity baselines. Key IPv6 exports by the delegated prefix in the
  `device_id` column when possible.
* **Sampling.** Packet-sampled NetFlow loses most packets of short, sparse flows. Known-indicator matching
  still works for any exported flow; behavioural detection of low-rate beacons needs unsampled DNS, Zeek or
  CPE telemetry. Record the sampling rate per source in the pilot plan so results are interpreted correctly.

## 4. Formats and field mapping

All parsers accept plain or gzip-compressed input. Timestamps: RFC 3339 with offset (or `Z`) or epoch
seconds; naive timestamps are rejected unless the source is registered with `assume_utc_for_naive: true`.
Events more than 5 minutes in the future (`max_clock_skew_s`) are quarantined. Missing values are kept as
missing (never zero): use an empty field or `-`.

### NetFlow / IPFIX (CSV)

Any collector that writes CSV works: nfdump (`nfdump -r <file> -o csv`), pmacct (print plugin with `print_output: csv`), or a vendor collector export. The
header row is matched case-insensitively against these aliases:

| AEGIS field | accepted column names |
|---|---|
| observed_at (required) | `ts`, `timestamp`, `time`, `start`, `start_time`, `flow_start`, `first_seen`, `flowStartMilliseconds`, `observed_at` |
| dst_ip (required) | `dst_ip`, `da`, `dstaddr`, `dst_addr`, `destination_ip`, `destinationIPv4Address`, `destinationIPv6Address`, `ipv4_dst_addr` |
| device_id | `device_id`, `device`, `mac`, `device_mac`, `src_mac`, `cpe_device_id` |
| src_ip | `src_ip`, `sa`, `srcaddr`, `src_addr`, `source_ip`, `sourceIPv4Address`, `sourceIPv6Address`, `ipv4_src_addr` |
| src_port / dst_port | `src_port`, `sp`, `srcport`, `sourceTransportPort`, `l4_src_port` / `dst_port`, `dp`, `dstport`, `destinationTransportPort`, `l4_dst_port` |
| protocol | `protocol`, `proto`, `pr`, `protocolIdentifier` (number or name) |
| bytes_out / bytes_in | `bytes_out`, `ibyt`, `in_bytes`, `octetDeltaCount`, `orig_bytes`, `bytes` / `bytes_in`, `obyt`, `out_bytes`, `reverseOctetDeltaCount`, `resp_bytes` |
| packets_out / packets_in | `packets_out`, `ipkt`, `in_pkts`, `packetDeltaCount`, `orig_pkts`, `packets` / `packets_in`, `opkt`, `out_pkts`, `reversePacketDeltaCount`, `resp_pkts` |
| duration | `duration_ms`, or seconds in `duration_s`, `duration`, `td`, `dur` |
| device_class | `device_class`, `class`, `device_type` |

"out" means from the observed subscriber/device towards the destination. Export bi-flows (or both
directions joined) when the collector supports it. Examples: `sample_data/lab/netflow.csv`,
`sample_data/formats/nfdump.csv`.

### Resolver DNS (JSON Lines)

One flat JSON object per query/response, using the keys below. dnstap is a binary framed format: either use
the resolver's native JSON query/response logging, or convert dnstap to flat JSON lines (for example the
`dnstap` tool's JSON output piped through a `jq` filter that maps its fields to these keys).

| AEGIS field | accepted keys |
|---|---|
| observed_at (required) | `ts`, `timestamp`, `time`, `query_time`, `observed_at`, `@timestamp` |
| qname (required) | `qname`, `query`, `question`, `name`, `query_name` |
| src_ip (client) | `client_ip`, `client`, `src_ip`, `source_ip`, `query_address` |
| dst_ip (resolver) | `resolver_ip`, `server_ip`, `dst_ip`, `response_address` |
| qtype / rcode | `qtype`, `type`, `query_type`, `qtype_name` / `rcode`, `response_code`, `rcode_name`, `status` |
| answers | `answers`, `answer`, `response`, `rdata` (list or single value) |
| device_id / device_class | as for NetFlow |

Example: `sample_data/lab/dns.jsonl`. Log responses, not only queries: NXDOMAIN rates and answer addresses
(which join DNS names to flows) come from responses.

### Zeek

Standard TSV `conn.log` (`source_kind: zeek_conn`) and `dns.log` (`zeek_dns`) with their `#fields` header,
as written by Zeek's default ASCII writer. Register both from the same sensor. Examples: `sample_data/zeek/`.

### CPE / gateway telemetry (JSON)

A JSON document with per-device flow and DNS records:

```json
{"devices": [
  {"device_id": "02:00:5e:10:00:01", "device_class": "android_tv",
   "flows": [{"ts": "2026-10-01T20:00:00Z", "dst_ip": "198.18.0.20", "dst_port": 443, "proto": "tcp",
              "bytes_out": 52000, "bytes_in": 41000000, "duration_ms": 60000}],
   "dns":   [{"ts": "2026-10-01T19:59:59.900Z", "qname": "vod01.streamcdn.example", "qtype": "A",
              "rcode": "NOERROR", "answers": ["198.18.0.20"]}]}
]}
```

Device-level fields inherit from the device object. Example: `sample_data/formats/cpe.json`. CPE telemetry
requires that the operator manages the gateway and that its terms or an opt-in cover security telemetry
(see the DPIA template).

### Pre-normalized events

Collectors that already produce AEGIS `ObservationEvent` objects (schema 3.0, `aegis/contracts/models.py`)
can post them as JSON to `POST /api/v1/ingest/events` (up to 50,000 per request). Each event is validated;
invalid ones are reported per item and quarantined.

## 5. Delivery

### Push (recommended): `aegis_push.py`

The collector host pushes rotated export files over HTTPS with a token holding only the `integration` role.
See [INSTALL.md section 9](INSTALL.md#9-send-telemetry) for the systemd timer. Raw API equivalent:

```bash
curl -fsS -X POST "https://aegis.operator.example/api/v1/ingest?source_id=core-ipfix&name=ipfix-20261101-1200.csv" \
  -H "Authorization: Bearer $INTEGRATION_TOKEN" --data-binary @ipfix-20261101-1200.csv
```

The response reports `records_read`, `accepted`, `quarantined` (with reasons), `duplicates`, and the
findings and cases the batch produced. Add `flush=true` on the last file of a backfill or when a source goes
quiet, to close open detection windows.

Recommended cadence: files of 1 to 5 minutes. Detection windows are 5 minutes, 15 minutes and 24 hours;
the known-IOC alert latency SLO (spec section 13) is measured from the event time, so long export
intervals add directly to it.

### Buffered collection (optional `bus` profile)

`--profile bus` starts a single-node Redpanda (Kafka API) on `BUS_BIND:19092`. Use it when collectors
already speak Kafka or when exports must be buffered through AEGIS maintenance windows: collectors produce to
one topic per source, and a forwarder (the operator's Vector, Fluent Bit or Logstash pipeline with a Kafka
source and an HTTP sink to `/api/v1/ingest?source_id=<topic's source>`) delivers batches. In v1 the AEGIS API
does not consume Kafka itself; the bus is a buffer in front of the HTTPS ingest API, not a separate ingest
path. Size its retention for the longest outage you want to absorb.

## 6. Re-identification stays with the operator

AEGIS stores pseudonyms only. When the operator decides to act on a verified case (for example notifying the
subscriber through its abuse process), it re-identifies the line itself by computing the same HMAC over its
own list of line identifiers with the tenant key, inside its own systems and under its own access controls.
AEGIS has no API that returns a subscriber identity, and none is planned for SHIELD.

## 7. Onboarding checklist (pilot week 1)

- [ ] Vantage points chosen and recorded in the pilot plan with sampling rates and NAT position
- [ ] `collection_authorization_id` issued by the operator for each source (DPIA reference)
- [ ] Sources registered (`POST /api/v1/sources`), one per exporter and format
- [ ] One hour of each export pushed; quarantine reasons reviewed and collector config fixed
- [ ] Ingest valid ratio >= 99.9% on the Grafana dashboard
- [ ] Clock sync (NTP) verified on exporters; no future-timestamp quarantines
- [ ] Signed IOC bundle loaded (operator SOC feed and/or partner CERT feed), indicators fresh
- [ ] Hosting topology loaded (prefixes the operator can vouch for; `complete` set honestly)
- [ ] Shadow policy signed and loaded
- [ ] Continuous delivery enabled (timer) and monitored (`AegisIngestStalled` alert)
