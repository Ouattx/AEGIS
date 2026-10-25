#!/usr/bin/env bash
# Shared helpers for the AEGIS home-lab scripts. Sourced, not executed.
# shellcheck shell=bash
set -euo pipefail

HOMELAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MARKER="# managed by aegis-homelab (deploy/homelab); remove with teardown.sh"

log() { printf '[aegis-homelab] %s\n' "$*" >&2; }
die() { printf '[aegis-homelab] ERROR: %s\n' "$*" >&2; exit 1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "run as root (sudo $0 $*)"
}

# shellcheck disable=SC2034  # variables are used by the scripts that source this file
load_env() {
  # Defaults, then homelab.env (or the file named by AEGIS_HOMELAB_ENV) overrides them.
  LAB_IFACE=wlan0; UPLINK_IFACE=eth0; LAB_SSID=aegis-lab; LAB_PASSPHRASE=""; COUNTRY_CODE=FR
  WIFI_CHANNEL=6; LAB_GATEWAY=10.42.0.1; LAB_PREFIX_LEN=24; LAB_SUBNET=10.42.0.0/24
  DHCP_START=10.42.0.20; DHCP_END=10.42.0.60; UPSTREAM_DNS="9.9.9.9 149.112.112.112"
  EGRESS_RATE_KBYTES=500; BLOCK_DOT=0; CAPTURE_ROOT=/var/lib/aegis-homelab; SNAPLEN=96
  ROTATE_SECONDS=3600; MAX_HOURS=72
  local env_file="${AEGIS_HOMELAB_ENV:-$HOMELAB_DIR/homelab.env}"
  if [ -f "$env_file" ]; then
    # shellcheck disable=SC1090
    . "$env_file"
    log "configuration: $env_file"
  else
    log "no $env_file: using defaults (copy homelab.env.example to homelab.env to change them)"
  fi
  LOG_DIR=/var/log/aegis-homelab
  DNSMASQ_LOG="$LOG_DIR/dnsmasq.log"
  validate_env
}

validate_env() {
  [[ "$SNAPLEN" =~ ^[0-9]+$ ]] || die "SNAPLEN must be a number"
  # header-only by design: refuse anything that could carry meaningful payload
  [ "$SNAPLEN" -le 128 ] || die "SNAPLEN=$SNAPLEN is above 128 bytes; the lab captures headers only"
  [[ "$ROTATE_SECONDS" =~ ^[0-9]+$ ]] && [ "$ROTATE_SECONDS" -ge 60 ] || die "ROTATE_SECONDS must be >= 60"
  [[ "$MAX_HOURS" =~ ^[0-9]+$ ]] && [ "$MAX_HOURS" -ge 1 ] && [ "$MAX_HOURS" -le 336 ] \
    || die "MAX_HOURS must be between 1 and 336 (two weeks)"
  [ -z "$EGRESS_RATE_KBYTES" ] || [[ "$EGRESS_RATE_KBYTES" =~ ^[0-9]+$ ]] || die "EGRESS_RATE_KBYTES must be a number"
  case "$LAB_SUBNET" in
    10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) ;;
    *) die "LAB_SUBNET must be a private RFC 1918 network" ;;
  esac
}

require_passphrase() {
  [ "${#LAB_PASSPHRASE}" -ge 12 ] || die "set LAB_PASSPHRASE (12+ characters) in homelab.env"
}

require_cmd() {
  local c
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || die "missing command: $c"; done
}

# write_managed FILE MODE: write stdin to FILE (with the managed marker) only when the content changed.
# Prints "changed" when it wrote the file, nothing otherwise (idempotent re-runs).
write_managed() {
  local file="$1" mode="${2:-0644}" tmp
  tmp="$(mktemp)"
  { printf '%s\n' "$MARKER"; cat; } > "$tmp"
  if [ -f "$file" ] && cmp -s "$tmp" "$file"; then
    rm -f "$tmp"
    return 0
  fi
  install -D -m "$mode" "$tmp" "$file"
  rm -f "$tmp"
  echo changed
}

is_managed() {
  [ -f "$1" ] && head -n 1 "$1" | grep -qF "$MARKER"
}

remove_managed() {
  local f
  for f in "$@"; do
    if is_managed "$f"; then rm -f "$f"; log "removed $f"; fi
  done
}

# Private and special-purpose ranges the lab device must never reach (your home LAN, other lab clients).
PRIVATE_V4="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16, 224.0.0.0/4"

# nft_lab_rules TABLE LAB_IF UPLINK_IF: the lab firewall as an nftables ruleset on stdout.
# One dedicated table, replaced as a whole on every run (idempotent), deleted by teardown.
nft_lab_rules() {
  local table="$1" lab_if="$2" up_if="$3" rate_rule="" dot_rule=""
  if [ -n "${EGRESS_RATE_KBYTES:-}" ]; then
    rate_rule="iifname \"$lab_if\" limit rate over ${EGRESS_RATE_KBYTES} kbytes/second drop
    oifname \"$lab_if\" limit rate over ${EGRESS_RATE_KBYTES} kbytes/second drop"
  fi
  if [ "${BLOCK_DOT:-0}" = "1" ]; then
    dot_rule="iifname \"$lab_if\" tcp dport 853 reject with tcp reset"
  fi
  cat <<EOF
table inet $table {
  chain input {
    type filter hook input priority filter - 5; policy accept;
    # the device under test may only use DHCP and DNS on the lab gateway, nothing else (no SSH, no admin UI)
    iifname "$lab_if" udp dport 67 accept
    iifname "$lab_if" ip daddr $LAB_GATEWAY meta l4proto { tcp, udp } th dport 53 accept
    iifname "$lab_if" ct state established,related accept
    iifname "$lab_if" drop
  }
  chain forward {
    type filter hook forward priority filter - 5; policy accept;
    # no IPv6 from the lab: everything the device does stays visible to the IPv4 logs
    iifname "$lab_if" meta nfproto ipv6 drop
    oifname "$lab_if" meta nfproto ipv6 drop
    # client isolation at layer 3 and protection of your home network
    iifname "$lab_if" oifname "$lab_if" drop
    iifname "$lab_if" ip daddr { $PRIVATE_V4 } drop
    $dot_rule
    $rate_rule
    iifname "$lab_if" oifname "$up_if" accept
    iifname "$up_if" oifname "$lab_if" ct state established,related accept
    iifname "$up_if" oifname "$lab_if" drop
    iifname "$lab_if" drop
  }
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    # DNS interception: queries to any outside resolver are answered (and logged) by the lab resolver
    iifname "$lab_if" ip daddr != $LAB_GATEWAY meta l4proto { tcp, udp } th dport 53 dnat ip to $LAB_GATEWAY
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $LAB_SUBNET oifname "$up_if" masquerade
  }
}
EOF
}

apply_nft() {
  local table="$1" lab_if="$2" up_if="$3" rules
  rules="$(nft_lab_rules "$table" "$lab_if" "$up_if")"
  nft list table inet "$table" >/dev/null 2>&1 && nft delete table inet "$table"
  printf '%s\n' "$rules" | nft -f -
  log "firewall table inet $table applied"
}

write_manifest() {
  # write_manifest DIR IFACE TOOL: capture.json read by `python -m aegis.homelab analyze`
  local dir="$1" iface="$2" tool="$3"
  mkdir -p "$dir"
  cat > "$dir/capture.json" <<EOF
{
  "capture_id": "$(basename "$dir")",
  "started_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "ended_at": null,
  "interface": "$iface",
  "snaplen": $SNAPLEN,
  "synthetic": false,
  "tool": "$tool",
  "dnsmasq_timezone": "$(dnsmasq_tz)",
  "notes": "Home-lab capture of the lab owner's own device. Headers only (snaplen $SNAPLEN)."
}
EOF
}

finish_manifest() {
  local dir="$1" now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  [ -f "$dir/capture.json" ] || return 0
  sed -i.bak "s/\"ended_at\": null/\"ended_at\": \"$now\"/" "$dir/capture.json" && rm -f "$dir/capture.json.bak"
}

# IPv4 forwarding: remember the value before the lab enabled it, restore exactly that on teardown
save_forward_state() {
  local f="$CAPTURE_ROOT/.ip_forward_before"
  install -d -m 0751 "$CAPTURE_ROOT"
  [ -f "$f" ] || sysctl -n net.ipv4.ip_forward > "$f"
}

restore_forward_state() {
  local f="$CAPTURE_ROOT/.ip_forward_before" v
  [ -f "$f" ] || return 0
  v="$(cat "$f")"
  [[ "$v" =~ ^[01]$ ]] && sysctl -q -w "net.ipv4.ip_forward=$v" >/dev/null && log "ip_forward restored to $v"
  rm -f "$f"
}

# Units the lab enables: remember whether they were enabled before, restore that on teardown
save_unit_state() {
  local u f
  install -d -m 0751 "$CAPTURE_ROOT"
  for u in "$@"; do
    f="$CAPTURE_ROOT/.unit_before_$u"
    [ -f "$f" ] || { systemctl is-enabled "$u" 2>/dev/null || true; } > "$f"
  done
}

restore_unit_state() {
  local u f before
  for u in "$@"; do
    f="$CAPTURE_ROOT/.unit_before_$u"
    [ -f "$f" ] || continue
    before="$(cat "$f")"
    if [ "$before" = "enabled" ]; then
      systemctl restart "$u" >/dev/null 2>&1 || true
    else
      systemctl stop "$u" >/dev/null 2>&1 || true
      systemctl disable "$u" >/dev/null 2>&1 || true
    fi
    rm -f "$f"
    log "$u restored to its previous state (${before:-not enabled})"
  done
}

local_tz() {
  local tz=""
  tz="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
  [ -n "$tz" ] || tz="$(readlink /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||' || true)"
  printf '%s\n' "${tz:-UTC}"
}

# Timezone of dnsmasq's syslog-style timestamps: UTC on the Pi (setup-ap.sh sets TZ=UTC for
# dnsmasq), the machine's local time for NetworkManager's dnsmasq on a laptop.
dnsmasq_tz() {
  if is_managed /etc/systemd/system/dnsmasq.service.d/aegis-homelab.conf; then echo UTC; else local_tz; fi
}
