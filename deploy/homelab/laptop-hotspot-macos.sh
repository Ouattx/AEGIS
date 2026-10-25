#!/usr/bin/env bash
# AEGIS home lab, macOS variant: header-only capture of a device joined to macOS Internet Sharing.
#
#   sudo ./laptop-hotspot-macos.sh start [NAME]   firewall anchor + capture on the sharing bridge
#   sudo ./laptop-hotspot-macos.sh stop           stop the capture, remove the firewall anchor
#
# macOS has no supported command line for Internet Sharing, so enable it by hand first:
#   System Settings > General > Sharing > Internet Sharing: share from Ethernet (or a USB/Thunderbolt
#   adapter) to Wi-Fi, set a WPA2/WPA3 password, turn it on, then join ONLY the device under test.
# The sharing bridge is usually bridge100 with the gateway 192.168.2.1 (override with BRIDGE_IFACE,
# MAC_LAB_SUBNET, MAC_GATEWAY in homelab.env).
#
# Differences from the Raspberry Pi kit (state them in your notes):
#   * no client isolation at layer 2 (Internet Sharing has none): connect a single device only;
#   * no dnsmasq: DNS comes from a second capture of port 53 only, with a 512-byte snaplen so that
#     answers survive (DNS metadata only), converted by zeek-convert.sh into dns.log;
#   * a pf anchor blocks the lab from private ranges (your home LAN) except the sharing gateway.
#     Verify it after macOS updates (pfctl -a com.apple/250.AegisHomelab -s rules).
set -euo pipefail

log() { printf '[aegis-homelab] %s\n' "$*" >&2; }
die() { printf '[aegis-homelab] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Darwin" ] || die "this script is for macOS; on Linux use laptop-hotspot-linux.sh"
[ "$(id -u)" -eq 0 ] || die "run with sudo"

HERE="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${AEGIS_HOMELAB_ENV:-$HERE/homelab.env}"
BRIDGE_IFACE=bridge100; MAC_LAB_SUBNET=192.168.2.0/24; MAC_GATEWAY=192.168.2.1
CAPTURE_ROOT="$HOME/aegis-homelab"; SNAPLEN=96; ROTATE_SECONDS=3600; MAX_HOURS=72
# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
[ "$SNAPLEN" -le 128 ] || die "SNAPLEN must stay at or below 128 bytes (headers only)"
ANCHOR="com.apple/250.AegisHomelab"
STATE="$CAPTURE_ROOT/.macos-capture"

start() {
  local name="${1:-lab-$(date -u +%Y%m%dT%H%M%SZ)}" dir files
  [[ "$name" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "capture name may use letters, digits, . _ - only"
  ifconfig "$BRIDGE_IFACE" >/dev/null 2>&1 || die "$BRIDGE_IFACE not found: turn Internet Sharing on first"
  [ ! -f "$STATE" ] || die "a capture is already running (stop it first)"
  dir="$CAPTURE_ROOT/captures/$name"
  mkdir -p "$dir/pcap"
  chmod 0750 "$CAPTURE_ROOT" "$dir"

  # firewall: the lab may reach the sharing gateway and the internet, never private ranges
  pfctl -a "$ANCHOR" -f - 2>/dev/null <<EOF
pass in quick on $BRIDGE_IFACE inet from $MAC_LAB_SUBNET to $MAC_GATEWAY
block drop in quick on $BRIDGE_IFACE inet from $MAC_LAB_SUBNET to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 }
block drop in quick on $BRIDGE_IFACE inet6 all
EOF
  pfctl -E >/dev/null 2>&1 || true
  log "pf anchor $ANCHOR loaded"

  files=$(( (MAX_HOURS * 3600 + ROTATE_SECONDS - 1) / ROTATE_SECONDS ))
  cat > "$dir/capture.json" <<EOF
{
  "capture_id": "$name",
  "started_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "ended_at": null,
  "interface": "$BRIDGE_IFACE",
  "snaplen": $SNAPLEN,
  "synthetic": false,
  "tool": "deploy/homelab/laptop-hotspot-macos.sh",
  "notes": "macOS Internet Sharing. Headers only (snaplen $SNAPLEN); DNS port 53 captured separately at 512 bytes."
}
EOF
  # headers only for all traffic, and DNS (port 53) at 512 bytes in a separate ring so answers survive
  TZ=UTC nohup tcpdump -i "$BRIDGE_IFACE" -s "$SNAPLEN" -n -U -G "$ROTATE_SECONDS" -W "$files" \
    -w "$dir/pcap/lab-%Y%m%dT%H%M%SZ.pcap" 'not port 53' >/dev/null 2>&1 &
  echo "$! $dir" > "$STATE"
  TZ=UTC nohup tcpdump -i "$BRIDGE_IFACE" -s 512 -n -U -G "$ROTATE_SECONDS" -W "$files" \
    -w "$dir/pcap/dns-%Y%m%dT%H%M%SZ.pcap" 'port 53' >/dev/null 2>&1 &
  echo "$! $dir" >> "$STATE"
  log "capture '$name' started on $BRIDGE_IFACE (stops by itself after $MAX_HOURS h); output: $dir"
}

stop() {
  local pid dir=""
  if [ -f "$STATE" ]; then
    while read -r pid d; do
      kill "$pid" 2>/dev/null || true
      dir="$d"
    done < "$STATE"
    rm -f "$STATE"
    log "capture stopped"
  else
    log "no capture running"
  fi
  if [ -n "$dir" ] && [ -f "$dir/capture.json" ]; then
    sed -i '' "s/\"ended_at\": null/\"ended_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"/" "$dir/capture.json"
    log "next: ./zeek-convert.sh $dir   then   python -m aegis.homelab analyze $dir --out <report-dir>"
  fi
  pfctl -a "$ANCHOR" -F all >/dev/null 2>&1 && log "pf anchor removed"
  log "turn Internet Sharing off in System Settings when you are done"
}

case "${1:-}" in
  start) shift; start "$@" ;;
  stop) stop ;;
  *) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
