"""Raw collector-format writers used by the lab corpus.

The formats are exactly what :mod:`aegis.ingest.parsers` reads, so lab files go
through the same ingest path as operator telemetry.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from functools import lru_cache
from typing import Iterable, Sequence

NETFLOW_HEADER: tuple[str, ...] = (
    "ts", "device_id", "device_class", "src_ip", "src_port", "dst_ip", "dst_port", "proto",
    "packets_out", "bytes_out", "packets_in", "bytes_in", "duration_ms",
)

ZEEK_CONN_FIELDS: tuple[str, ...] = (
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
    "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents",
)
ZEEK_CONN_TYPES: tuple[str, ...] = (
    "time", "string", "addr", "port", "addr", "port", "enum", "string", "interval", "count", "count",
    "string", "bool", "bool", "count", "string", "count", "count", "count", "count", "set[string]",
)
ZEEK_DNS_FIELDS: tuple[str, ...] = (
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "trans_id", "rtt", "query",
    "qclass", "qclass_name", "qtype", "qtype_name", "rcode", "rcode_name", "AA", "TC", "RD", "RA", "Z",
    "answers", "TTLs", "rejected",
)
ZEEK_DNS_TYPES: tuple[str, ...] = (
    "time", "string", "addr", "port", "addr", "port", "enum", "count", "interval", "string", "count",
    "string", "count", "string", "count", "string", "bool", "bool", "bool", "bool", "count",
    "vector[string]", "vector[interval]", "bool",
)

_QTYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28,
              "SRV": 33, "HTTPS": 65}
_RCODE_NUM = {"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5}
_PROTO_NAME = {6: "tcp", 17: "udp", 1: "icmp"}


@lru_cache(maxsize=4096)
def _day_prefix(day: int) -> str:
    return datetime.fromtimestamp(day * 86400, tz=timezone.utc).strftime("%Y-%m-%dT")


def rfc3339_ms(t: float) -> str:
    """Epoch seconds -> ``YYYY-MM-DDTHH:MM:SS.mmmZ`` (millisecond precision, UTC)."""
    ms = int(round(t * 1000))
    secs, milli = divmod(ms, 1000)
    day, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    m, sec = divmod(rem, 60)
    return f"{_day_prefix(day)}{h:02d}:{m:02d}:{sec:02d}.{milli:03d}Z"


def _s(v: object) -> str:
    return "" if v is None else str(v)


def netflow_header_line() -> str:
    return ",".join(NETFLOW_HEADER)


def netflow_line(ts: str, device_id: str, device_class: str, src_ip: str, src_port: int, dst_ip: str,
                 dst_port: int | None, proto: int, packets_out: int | None, bytes_out: int | None,
                 packets_in: int | None, bytes_in: int | None, duration_ms: int | None) -> str:
    return ",".join((ts, device_id, device_class, src_ip, str(src_port), dst_ip, _s(dst_port), str(proto),
                     _s(packets_out), _s(bytes_out), _s(packets_in), _s(bytes_in), _s(duration_ms)))


def dns_line(ts: str, device_id: str, device_class: str, client_ip: str, qname: str, qtype: str, rcode: str,
             answers: Sequence[str]) -> str:
    return json.dumps({"ts": ts, "device_id": device_id, "device_class": device_class, "client_ip": client_ip,
                       "qname": qname, "qtype": qtype, "rcode": rcode, "answers": list(answers)},
                      separators=(",", ":"))


def zeek_uid(*parts: object) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    n = int.from_bytes(hashlib.sha256("|".join(map(str, parts)).encode()).digest()[:12], "big")
    out: list[str] = []
    while len(out) < 17:
        n, rem = divmod(n, 62)
        out.append(alphabet[rem])
    return "C" + "".join(out)


def zeek_header(path: str, fields: Iterable[str], types: Iterable[str], open_ts: float) -> list[str]:
    opened = datetime.fromtimestamp(open_ts, tz=timezone.utc).strftime("%Y-%m-%d-%H-%M-%S")
    return ["#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-",
            f"#path\t{path}", f"#open\t{opened}", "#fields\t" + "\t".join(fields), "#types\t" + "\t".join(types)]


def zeek_close(close_ts: float) -> str:
    return "#close\t" + datetime.fromtimestamp(close_ts, tz=timezone.utc).strftime("%Y-%m-%d-%H-%M-%S")


def _z(v: object) -> str:
    return "-" if v is None else str(v)


def zeek_conn_line(t: float, uid: str, orig_h: str, orig_p: int, resp_h: str, resp_p: int | None, proto: int,
                   duration_ms: int | None, orig_bytes: int | None, resp_bytes: int | None,
                   orig_pkts: int | None, resp_pkts: int | None) -> str:
    pname = _PROTO_NAME.get(proto, "unknown_transport")
    state = "S0" if (resp_bytes == 0 and (resp_pkts or 0) == 0) else "SF"
    dur = None if duration_ms is None else f"{duration_ms / 1000:.6f}"
    oib = None if orig_bytes is None or orig_pkts is None else orig_bytes + 40 * orig_pkts
    rib = None if resp_bytes is None or resp_pkts is None else resp_bytes + 40 * resp_pkts
    return "\t".join((f"{t:.6f}", uid, orig_h, str(orig_p), resp_h, _z(resp_p), pname, "-", _z(dur),
                      _z(orig_bytes), _z(resp_bytes), state, "T", "F", "0", "-" if state == "SF" else "S",
                      _z(orig_pkts), _z(oib), _z(resp_pkts), _z(rib), "(empty)"))


def zeek_dns_line(t: float, uid: str, orig_h: str, orig_p: int, resp_h: str, trans_id: int, qname: str,
                  qtype: str, rcode: str, answers: Sequence[str]) -> str:
    ans = ",".join(answers) if answers else "-"
    ttls = ",".join("300.000000" for _ in answers) if answers else "-"
    return "\t".join((f"{t:.6f}", uid, orig_h, str(orig_p), resp_h, "53", "udp", str(trans_id), "0.012000",
                      qname, "1", "C_INTERNET", str(_QTYPE_NUM.get(qtype, 0)), qtype,
                      str(_RCODE_NUM.get(rcode, 2)), rcode, "F", "F", "T", "T", "0", ans, ttls, "F"))
