#!/usr/bin/env bash
# AEGIS home lab, laptop variant (Linux with NetworkManager): an isolated Wi-Fi hotspot for ONE
# device under test, without a Raspberry Pi.
#
#   sudo ./laptop-hotspot-linux.sh start    create/refresh and bring up the hotspot (idempotent)
#   sudo ./laptop-hotspot-linux.sh stop     bring the hotspot down (configuration kept)
#   sudo ./teardown.sh                      remove everything (hotspot profile, logging, firewall)
#
# Requirements: NetworkManager >= 1.28 (nmcli), nftables, tcpdump, a Wi-Fi adapter that supports
# AP mode (check: iw list | grep -A8 'Supported interface modes' | grep AP) and an internet uplink
# on ANOTHER interface (Ethernet, or a second Wi-Fi adapter). LAB_IFACE / UPLINK_IFACE come from
# homelab.env (e.g. LAB_IFACE=wlp2s0 UPLINK_IFACE=enp0s31f6).
#
# Same protections as the Raspberry Pi variant: WPA2, client isolation (ap-isolation), no access
# to your home LAN or to the laptop, no IPv6, DNS interception to the logged resolver, rate cap.
# NetworkManager's own dnsmasq serves DHCP/DNS; its query log goes to
# /var/log/aegis-homelab/dnsmasq.log in the laptop's local time (recorded in capture.json).
# Capture with ./capture.sh start|stop as on the Pi.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$(cd "$(dirname "$0")" && pwd)/common.sh"

CON=aegis-homelab

start() {
  require_passphrase
  require_cmd nmcli nft tcpdump
  systemctl is-active --quiet NetworkManager || die "NetworkManager is not running"
  ip link show "$LAB_IFACE" >/dev/null 2>&1 || die "interface $LAB_IFACE not found"
  [ "$LAB_IFACE" != "$UPLINK_IFACE" ] || die "the hotspot needs an uplink on another interface"
  if command -v iw >/dev/null 2>&1 && ! iw list 2>/dev/null | grep -A10 'Supported interface modes' | grep -q '\* AP'; then
    log "warning: no Wi-Fi adapter reports AP mode; the hotspot may fail to start"
  fi

  # query logging for NetworkManager's shared-mode dnsmasq
  install -d -m 0751 "$LOG_DIR"
  touch "$DNSMASQ_LOG"
  chown nobody "$DNSMASQ_LOG" 2>/dev/null || true
  chmod 0640 "$DNSMASQ_LOG"
  write_managed /etc/NetworkManager/dnsmasq-shared.d/aegis-homelab.conf >/dev/null <<EOF
log-queries=extra
log-dhcp
log-facility=$DNSMASQ_LOG
EOF

  # the hotspot profile (re-created on every run so the configuration always matches homelab.env)
  if nmcli -t -f NAME connection show | grep -qx "$CON"; then
    nmcli connection down "$CON" >/dev/null 2>&1 || true
    nmcli connection delete "$CON" >/dev/null
  fi
  nmcli connection add type wifi ifname "$LAB_IFACE" con-name "$CON" autoconnect no ssid "$LAB_SSID" \
    802-11-wireless.mode ap 802-11-wireless.band bg 802-11-wireless.channel "$WIFI_CHANNEL" \
    802-11-wireless.ap-isolation yes \
    wifi-sec.key-mgmt wpa-psk wifi-sec.proto rsn wifi-sec.pairwise ccmp wifi-sec.group ccmp \
    wifi-sec.psk "$LAB_PASSPHRASE" \
    ipv4.method shared ipv4.addresses "$LAB_GATEWAY/$LAB_PREFIX_LEN" ipv6.method disabled >/dev/null
  save_forward_state
  nmcli connection up "$CON" >/dev/null
  apply_nft aegis_homelab "$LAB_IFACE" "$UPLINK_IFACE"
  log "hotspot '$LAB_SSID' up on $LAB_IFACE ($LAB_GATEWAY/$LAB_PREFIX_LEN), uplink $UPLINK_IFACE"
  log "dnsmasq log timezone: $(local_tz) (pass --dnsmasq-tz to the analyzer if capture.json lacks it)"
  log "next: connect ONLY the device under test, then: sudo ./capture.sh start"
}

stop() {
  if nmcli connection down "$CON" >/dev/null 2>&1; then log "hotspot down"; else log "hotspot was not up"; fi
  nft list table inet aegis_homelab >/dev/null 2>&1 && nft delete table inet aegis_homelab && log "firewall removed"
  restore_forward_state
}

require_root "$@"
load_env
case "${1:-}" in
  start) start ;;
  stop) stop ;;
  *) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
