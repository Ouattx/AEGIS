"""AEGIS home lab kit: deploy scripts and guide.

The scripts touch a person's network, so their safety properties are tested like code:
strict mode, header-only capture with a time limit, isolation firewall rules (validated by
``nft -c`` when nftables is installed), client isolation, logged DNS in UTC, idempotent writes
and a teardown that removes everything the setup scripts create. The guide must cover safety,
legality, responsible disclosure and naming, and its links must resolve.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / "deploy" / "homelab"
GUIDE = ROOT / "docs" / "homelab" / "GUIDE.md"
SCRIPTS = sorted(p.name for p in KIT.glob("*.sh"))


def _bash(snippet: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", "-c", snippet], cwd=KIT, capture_output=True, text=True, timeout=60,
                          env={**os.environ, **(env or {})})


def test_kit_has_every_script():
    assert set(SCRIPTS) >= {"common.sh", "setup-ap.sh", "capture.sh", "zeek-convert.sh", "teardown.sh",
                            "laptop-hotspot-linux.sh", "laptop-hotspot-macos.sh"}
    assert (KIT / "homelab.env.example").exists() and (KIT / "README.md").exists()


@pytest.mark.parametrize("script", SCRIPTS)
def test_scripts_are_strict_executable_and_commented(script):
    path = KIT / script
    text = path.read_text()
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in text
    assert os.stat(path).st_mode & stat.S_IXUSR
    assert text.splitlines()[1].startswith("#")                      # every script explains itself


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_shellcheck_clean():
    res = subprocess.run(["shellcheck", "-x", *SCRIPTS], cwd=KIT, capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr


def _rules(rate: str = "500", dot: str = "0") -> str:
    res = _bash(f'set -euo pipefail; . ./common.sh; LAB_GATEWAY=10.42.0.1; LAB_SUBNET=10.42.0.0/24; '
                f'EGRESS_RATE_KBYTES={rate}; BLOCK_DOT={dot}; nft_lab_rules aegis_homelab wlan0 eth0')
    assert res.returncode == 0, res.stderr
    return res.stdout


def test_firewall_rules_isolate_the_lab():
    r = _rules()
    for needle in ('iifname "wlan0" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16', "drop",
                   'iifname "wlan0" oifname "wlan0" drop', "meta nfproto ipv6 drop",
                   "th dport 53 dnat ip to 10.42.0.1", 'ip saddr 10.42.0.0/24 oifname "eth0" masquerade',
                   'iifname "eth0" oifname "wlan0" ct state established,related accept',
                   'iifname "eth0" oifname "wlan0" drop', "limit rate over 500 kbytes/second drop",
                   'iifname "wlan0" udp dport 67 accept'):
        assert needle in r, needle
    # the lab may not reach the gateway's other services (SSH, web UI): input ends with a drop
    assert re.search(r'chain input \{.*iifname "wlan0" drop\s*\}', r, re.S)
    assert "limit rate" not in _rules(rate="")
    assert "tcp dport 853 reject" in _rules(dot="1")


@pytest.mark.skipif(shutil.which("nft") is None, reason="nftables not installed")
@pytest.mark.parametrize("rate,dot", [("500", "0"), ("", "1")])
def test_firewall_rules_parse_with_nft(rate, dot):
    res = subprocess.run(["nft", "-c", "-f", "-"], input=_rules(rate, dot), capture_output=True, text=True,
                         timeout=60)
    assert res.returncode == 0, res.stderr


@pytest.mark.parametrize("override,message", [
    ("SNAPLEN=1500", "headers only"),
    ("MAX_HOURS=1000", "MAX_HOURS"),
    ("LAB_SUBNET=8.8.8.0/24", "private"),
    ("EGRESS_RATE_KBYTES=fast", "EGRESS_RATE_KBYTES"),
])
def test_unsafe_configuration_is_refused(tmp_path, override, message):
    env = tmp_path / "homelab.env"
    env.write_text(override + "\n")
    res = _bash(". ./common.sh; load_env", {"AEGIS_HOMELAB_ENV": str(env)})
    assert res.returncode != 0 and message in res.stderr


def test_example_env_is_accepted_and_covers_every_default(tmp_path):
    example = (KIT / "homelab.env.example").read_text()
    env = tmp_path / "homelab.env"
    env.write_text(example.replace("LAB_PASSPHRASE=", "LAB_PASSPHRASE=correct-horse-battery"))
    res = _bash(". ./common.sh; load_env; require_passphrase; echo ok:$SNAPLEN:$MAX_HOURS",
                {"AEGIS_HOMELAB_ENV": str(env)})
    assert res.returncode == 0 and "ok:96:72" in res.stdout, res.stderr
    keys = set(re.findall(r"^([A-Z_]+)=", example, re.M))
    defaults = (KIT / "common.sh").read_text()
    for k in keys:
        assert f"{k}=" in defaults, k
    short = tmp_path / "short.env"
    short.write_text("LAB_PASSPHRASE=short\n")
    res = _bash(". ./common.sh; load_env; require_passphrase", {"AEGIS_HOMELAB_ENV": str(short)})
    assert res.returncode != 0 and "12+" in res.stderr


def test_write_managed_is_idempotent_and_marked(tmp_path):
    target = tmp_path / "x.conf"
    snippet = f'. ./common.sh; printf "a=1\\n" | write_managed "{target}"'
    assert _bash(snippet).stdout.strip() == "changed"
    assert _bash(snippet).stdout.strip() == ""
    assert target.read_text().splitlines()[0].startswith("# managed by aegis-homelab")
    assert _bash(f'. ./common.sh; is_managed "{target}" && remove_managed "{target}"').returncode == 0
    assert not target.exists()


def test_teardown_removes_every_file_the_setup_scripts_write():
    written = set()
    for name in ("setup-ap.sh", "laptop-hotspot-linux.sh"):
        written |= set(re.findall(r"write_managed (/etc/[\w./-]+)", (KIT / name).read_text()))
    assert written
    teardown = (KIT / "teardown.sh").read_text()
    for path in written:
        assert path in teardown, path
    assert "nft delete table inet aegis_homelab" in teardown
    assert "restore_forward_state" in teardown and "restore_unit_state hostapd.service dnsmasq.service" in teardown
    assert "--purge-captures" in teardown


def test_access_point_isolation_and_logging_settings():
    setup = (KIT / "setup-ap.sh").read_text()
    for needle in ("ap_isolate=1", "wpa=2", "rsn_pairwise=CCMP", "country_code=$COUNTRY_CODE",
                   "log-queries=extra", "log-facility=$DNSMASQ_LOG", "Environment=TZ=UTC",
                   "net.ipv6.conf.$LAB_IFACE.disable_ipv6=1", "require_passphrase", "save_forward_state",
                   "save_unit_state hostapd.service dnsmasq.service"):
        assert needle in setup, needle
    laptop = (KIT / "laptop-hotspot-linux.sh").read_text()
    for needle in ("802-11-wireless.ap-isolation yes", "ipv6.method disabled", "log-queries=extra", "apply_nft"):
        assert needle in laptop, needle


def test_capture_is_header_only_rotating_and_time_limited():
    cap = (KIT / "capture.sh").read_text()
    assert '-s "$SNAPLEN"' in cap and "-G \"$ROTATE_SECONDS\"" in cap and '-W "$files"' in cap
    assert "RuntimeMaxSec" in cap and "TZ=UTC tcpdump" in cap and " -n " in cap
    assert "write_manifest" in cap and "finish_manifest" in cap
    mac = (KIT / "laptop-hotspot-macos.sh").read_text()
    assert '-s "$SNAPLEN"' in mac and "-s 512" in mac and "'port 53'" in mac and "-W \"$files\"" in mac
    assert "SNAPLEN must stay at or below 128" in mac
    zeek = (KIT / "zeek-convert.sh").read_text()
    assert "-C -r" in zeek and "conn dns" in zeek


def test_manifest_written_by_scripts_is_read_by_the_importer(tmp_path):
    res = _bash(f'. ./common.sh; SNAPLEN=96; write_manifest "{tmp_path}" wlan0 test; finish_manifest "{tmp_path}"')
    assert res.returncode == 0, res.stderr
    from aegis.homelab.importer import CaptureManifest
    import json
    m = CaptureManifest.from_dict(json.loads((tmp_path / "capture.json").read_text()))
    assert m.snaplen == 96 and not m.synthetic and m.started_at and m.ended_at and m.ended_at >= m.started_at
    assert m.dnsmasq_timezone


# ============================================================================ guide

def test_guide_covers_safety_legality_disclosure_and_naming():
    text = GUIDE.read_text(encoding="utf-8")
    low = text.lower()
    for needle in ("isolat", "time limit", "no personal accounts", "residential proxies", "rate cap",
                   "pirate iptv", "test the device only", "metadata only", "226-15", "323-1", "gdpr",
                   "counsel", "cert-fr", "90 days", "marketplace", "no naming without proof", "factory reset",
                   "not legal advice", "synthetic"):
        assert needle in low, needle


def test_guide_and_kit_readme_links_resolve():
    for doc in (GUIDE, KIT / "README.md", ROOT / "aegis" / "homelab" / "INTEGRATION.md"):
        text = doc.read_text(encoding="utf-8")
        anchors = {re.sub(r"[^\w\- ]", "", h.strip().lower()).replace(" ", "-")
                   for h in re.findall(r"^#{1,6}\s+(.+?)\s*$", text, re.M)}
        for target in re.findall(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)", text):
            if re.match(r"^[a-z]+:", target):
                continue
            path, _, anchor = target.partition("#")
            dest = (doc.parent / path).resolve() if path else doc
            assert dest.exists(), f"{doc.name}: broken link {target}"
            if anchor and not path:
                assert anchor in anchors, f"{doc.name}: missing anchor {anchor}"
