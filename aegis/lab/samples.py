"""Committed sample data (``sample_data/``), regenerated deterministically.

``python -m aegis.lab.samples sample_data`` rewrites the directory; a unit test
checks the committed files still match the generator byte for byte.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

from aegis.lab.corpus import generate_corpus

SAMPLE_SEED = 11

NFDUMP_CSV = """\
ts,te,td,sa,da,sp,dp,pr,flg,ipkt,ibyt,opkt,obyt
2026-10-01T08:00:01.250Z,2026-10-01T08:00:02.000Z,0.750,100.64.9.10,198.18.0.20,51544,443,6,.AP.SF,12,4210,15,18892
2026-10-01T08:00:05.000Z,2026-10-01T08:00:05.100Z,0.100,100.64.9.10,198.18.255.53,40112,53,17,......,1,74,1,138
2026-10-01T08:01:00.000Z,2026-10-01T08:02:00.000Z,60.000,100.64.9.11,203.0.113.77,40001,443,6,.AP...,3,812,3,640
Summary
flows,bytes,packets
3,24746,35
"""

CPE_JSON = """\
{"devices": [
  {"device_id": "02:00:5e:10:00:01", "device_class": "android_tv",
   "flows": [{"ts": "2026-10-01T20:00:00Z", "dst_ip": "198.18.0.20", "dst_port": 443, "proto": "tcp",
              "bytes_out": 52000, "bytes_in": 41000000, "duration_ms": 60000}],
   "dns": [{"ts": "2026-10-01T19:59:59.900Z", "qname": "vod01.streamcdn.example", "qtype": "A",
            "rcode": "NOERROR", "answers": ["198.18.0.20"]}]},
  {"device_id": "02:00:5e:10:00:02", "device_class": "camera",
   "flows": [{"ts": "2026-10-01T20:00:00Z", "dst_ip": "198.18.56.10", "dst_port": 443, "proto": 6,
              "bytes_out": 7400000, "bytes_in": 210000, "duration_ms": 60000}]}
]}
"""

# Every line below must be quarantined, each for a different reason.
MALFORMED_NETFLOW = """\
ts,device_id,device_class,src_ip,src_port,dst_ip,dst_port,proto,packets_out,bytes_out,packets_in,bytes_in,duration_ms
2026-10-01T00:00:00.000Z,02:00:5e:00:00:01,android_tv,100.64.0.1,40000,198.18.0.5,443,6,10,1000,12,20000,60000
2026-10-01 00:00:01,02:00:5e:00:00:01,android_tv,100.64.0.1,40000,198.18.0.5,443,6,10,1000,12,20000,60000
2026-10-01T00:00:02.000Z,02:00:5e:00:00:01,android_tv,100.64.0.1,40000,not-an-ip,443,6,10,1000,12,20000,60000
2026-10-01T00:00:03.000Z,02:00:5e:00:00:01,android_tv,100.64.0.1,40000,198.18.0.5,70000,6,10,1000,12,20000,60000
2026-10-01T00:00:04.000Z,02:00:5e:00:00:01,android_tv,100.64.0.1,40000,198.18.0.5,443,6,10,-5,12,20000,60000
2026-10-01T00:00:05.000Z,02:00:5e:00:00:01,android_tv,100.64.0.1,40000,198.18.0.5,443,6,10,1e3,12,20000,60000
2026-10-01T00:00:06.000Z,02:00:5e:00:00:01,android_tv,100.64.0.1,40000,198.18.0.5,443
2099-01-01T00:00:00.000Z,02:00:5e:00:00:01,android_tv,100.64.0.1,40000,198.18.0.5,443,6,10,1000,12,20000,60000
2026-10-01T00:00:08.000Z,,android_tv,,40000,198.18.0.5,443,6,10,1000,12,20000,60000
"""


def write_samples(out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    for sub in ("lab", "zeek", "formats"):
        shutil.rmtree(out / sub, ignore_errors=True)
    written: dict[str, Path] = {}
    lab = generate_corpus(seed=SAMPLE_SEED, days=1, n_devices=8, malicious_fraction=0.5)
    for k, p in lab.write_raw(out / "lab", zeek=False).items():
        written[f"lab/{k}"] = p
    tiny = generate_corpus(seed=SAMPLE_SEED + 1, days=1, n_devices=3, malicious_fraction=0.34)
    zdir = out / "zeek"
    zdir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        files = tiny.write_raw(tmp, zeek=True, extras=False)
        for key in ("zeek_conn", "zeek_dns"):
            dest = zdir / files[key].name
            shutil.copyfile(files[key], dest)
            written[f"zeek/{dest.name}"] = dest
    fmt = out / "formats"
    fmt.mkdir(parents=True, exist_ok=True)
    for name, text in (("nfdump.csv", NFDUMP_CSV), ("cpe.json", CPE_JSON),
                       ("malformed_netflow.csv", MALFORMED_NETFLOW)):
        p = fmt / name
        p.write_text(text, encoding="utf-8")
        written[f"formats/{name}"] = p
    return written


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "sample_data"
    for key, path in sorted(write_samples(target).items()):
        print(f"{key}: {path}")
