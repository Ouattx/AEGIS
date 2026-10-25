#!/usr/bin/env bash
# AEGIS home lab: header-only capture of the lab interface, with a hard time limit.
#
#   sudo ./capture.sh start [NAME]   start a capture (tcpdump -s SNAPLEN, one file per ROTATE_SECONDS)
#   sudo ./capture.sh stop           stop it and collect the dnsmasq query log into the capture
#   sudo ./capture.sh status
#
# The capture keeps SNAPLEN (default 96) bytes per packet: link, IP and TCP/UDP headers only.
# It stops by itself after MAX_HOURS (tcpdump file limit + systemd RuntimeMaxSec), so a forgotten
# lab does not record indefinitely. Output: CAPTURE_ROOT/captures/NAME/
#   capture.json   manifest (start/end, interface, snaplen) read by `python -m aegis.homelab analyze`
#   pcap/          rotating header-only pcaps
#   dnsmasq.log*   the lab resolver's query log for the capture period (copied on stop)
# Then convert offline with ./zeek-convert.sh CAPTURE_ROOT/captures/NAME
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$(cd "$(dirname "$0")" && pwd)/common.sh"

UNIT=aegis-homelab-capture
CURRENT_LINK=""

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

start() {
  local name="${1:-lab-$(date -u +%Y%m%dT%H%M%SZ)}" dir files
  [[ "$name" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "capture name may use letters, digits, . _ - only"
  require_cmd tcpdump systemd-run
  if systemctl is-active --quiet "$UNIT"; then die "a capture is already running (./capture.sh stop first)"; fi
  dir="$CAPTURE_ROOT/captures/$name"
  [ ! -e "$dir/capture.json" ] || die "capture $name already exists"
  # traverse-only (0751) parents, so that tcpdump can reach pcap/ after dropping root privileges
  install -d -m 0751 "$dir"
  install -d -m 0750 "$dir/pcap"
  # tcpdump drops root privileges after opening the interface: let its user write the pcaps
  local as_user=root
  if id tcpdump >/dev/null 2>&1; then chown tcpdump "$dir/pcap"; as_user=tcpdump; fi
  files=$(( (MAX_HOURS * 3600 + ROTATE_SECONDS - 1) / ROTATE_SECONDS ))
  write_manifest "$dir" "$LAB_IFACE" "deploy/homelab/capture.sh"
  ln -sfn "$dir" "$CURRENT_LINK"
  # -s: headers only; -n: no name resolution (no extra DNS traffic); -G/-W: rotation that ends the capture
  systemd-run --unit="$UNIT" --description="AEGIS home lab header-only capture ($name)" \
    --property=RuntimeMaxSec=$(( MAX_HOURS * 3600 + 300 )) --collect \
    /usr/bin/env TZ=UTC tcpdump -i "$LAB_IFACE" -s "$SNAPLEN" -n -U -Z "$as_user" -G "$ROTATE_SECONDS" \
    -W "$files" -w "$dir/pcap/lab-%Y%m%dT%H%M%SZ.pcap" >/dev/null
  log "capture '$name' started on $LAB_IFACE (snaplen $SNAPLEN, up to $MAX_HOURS h, $files file(s))"
  log "output: $dir"
}

stop() {
  local dir
  dir="$(readlink -f "$CURRENT_LINK" 2>/dev/null || true)"
  if systemctl is-active --quiet "$UNIT"; then systemctl stop "$UNIT"; log "capture stopped"; fi
  [ -n "$dir" ] && [ -d "$dir" ] || die "no current capture"
  finish_manifest "$dir"
  if [ -f "$DNSMASQ_LOG" ]; then
    # the resolver log for the capture period (the analyzer ignores queries outside the lab subnet)
    cp -p "$DNSMASQ_LOG" "$dir/dnsmasq.log"
    [ -f "$DNSMASQ_LOG.1" ] && cp -p "$DNSMASQ_LOG.1" "$dir/dnsmasq.log.1"
    log "copied dnsmasq query log"
  else
    log "no dnsmasq log at $DNSMASQ_LOG (laptop hotspot? see the guide)"
  fi
  rm -f "$CURRENT_LINK"
  log "next: ./zeek-convert.sh $dir   then   python -m aegis.homelab analyze $dir --out <report-dir>"
}

status() {
  if systemctl is-active --quiet "$UNIT"; then
    systemctl status --no-pager "$UNIT" | sed -n '1,5p'
    log "current capture: $(readlink -f "$CURRENT_LINK" 2>/dev/null || echo unknown)"
  else
    log "no capture running"
  fi
}

require_root "$@"
load_env
CURRENT_LINK="$CAPTURE_ROOT/current"
install -d -m 0751 "$CAPTURE_ROOT" "$CAPTURE_ROOT/captures"
case "${1:-}" in
  start) shift; start "$@" ;;
  stop) stop ;;
  status) status ;;
  *) usage ;;
esac
