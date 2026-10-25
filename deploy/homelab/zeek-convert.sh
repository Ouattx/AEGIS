#!/usr/bin/env bash
# AEGIS home lab: offline conversion of header-only pcaps to Zeek conn.log / dns.log.
#
#   ./zeek-convert.sh CAPTURE_DIR          (CAPTURE_DIR holds pcap/*.pcap and capture.json)
#
# Runs Zeek on each pcap (no root needed, no network access) and writes
# CAPTURE_DIR/zeek/<pcap name>/{conn,dns}.log in Zeek's TSV format, which
# `python -m aegis.homelab analyze CAPTURE_DIR` imports. Idempotent: pcaps that already have
# a conn.log are skipped (delete CAPTURE_DIR/zeek to redo everything).
#
# Notes
#   * -C ignores checksums (capture offloading makes them look wrong).
#   * With a 96-byte snaplen Zeek reports truncated packets; connection sizes come from TCP
#     sequence numbers and stay usable. DNS answers may be cut: the dnsmasq query log is the
#     primary DNS source and Zeek's dns.log is only used when no dnsmasq log is present.
#   * Zeek may be slow on a Raspberry Pi: copy the capture directory to a laptop and run this
#     script there if needed (zeek package or the official zeek/zeek container image).
#   * Only these two logs are kept; other Zeek logs (weird, files, ssl...) are deleted.
set -euo pipefail

die() { printf '[aegis-homelab] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[aegis-homelab] %s\n' "$*" >&2; }

[ $# -eq 1 ] || die "usage: $0 CAPTURE_DIR"
CAP="$(cd "$1" && pwd)"
[ -d "$CAP/pcap" ] || die "$CAP/pcap not found"

ZEEK="${ZEEK:-$(command -v zeek || true)}"
[ -n "$ZEEK" ] || { [ -x /opt/zeek/bin/zeek ] && ZEEK=/opt/zeek/bin/zeek; }
[ -n "$ZEEK" ] || die "zeek not found (install the zeek package, or set ZEEK=/path/to/zeek)"

shopt -s nullglob
pcaps=("$CAP"/pcap/*.pcap "$CAP"/pcap/*.pcap.gz)
[ "${#pcaps[@]}" -gt 0 ] || die "no pcap files in $CAP/pcap"

done_n=0; skip_n=0
for p in "${pcaps[@]}"; do
  base="$(basename "$p")"; base="${base%.gz}"; base="${base%.pcap}"
  out="$CAP/zeek/$base"
  if [ -s "$out/conn.log" ]; then skip_n=$((skip_n + 1)); continue; fi
  work="$(mktemp -d)"
  src="$p"
  if [[ "$p" == *.gz ]]; then gunzip -c "$p" > "$work/in.pcap"; src="$work/in.pcap"; fi
  # TZ=UTC so that Zeek's #open/#close headers match the epoch timestamps
  ( cd "$work" && TZ=UTC "$ZEEK" -C -r "$src" LogAscii::use_json=F >/dev/null 2>"$work/zeek.stderr" ) \
    || { cat "$work/zeek.stderr" >&2; rm -rf "$work"; die "zeek failed on $p"; }
  mkdir -p "$out"
  for l in conn dns; do
    [ -f "$work/$l.log" ] && mv "$work/$l.log" "$out/$l.log"
  done
  rm -rf "$work"
  done_n=$((done_n + 1))
done
log "converted $done_n pcap(s), skipped $skip_n already converted; logs in $CAP/zeek/"
