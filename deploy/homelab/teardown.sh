#!/usr/bin/env bash
# AEGIS home lab: undo setup-ap.sh (Raspberry Pi) or laptop-hotspot-linux.sh.
#
#   sudo ./teardown.sh                    stop the lab, remove every file the lab scripts created
#   sudo ./teardown.sh --purge-captures   ... and delete CAPTURE_ROOT (pcaps, logs) as well
#
# Only files carrying the "managed by aegis-homelab" marker are removed; packages installed by
# setup-ap.sh (hostapd, dnsmasq, nftables, tcpdump, iw) are left in place. Safe to re-run.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$(cd "$(dirname "$0")" && pwd)/common.sh"

require_root "$@"
load_env
PURGE=0
[ "${1:-}" = "--purge-captures" ] && PURGE=1

stop_unit() {
  local u
  for u in "$@"; do
    systemctl stop "$u" >/dev/null 2>&1 || true
    systemctl disable "$u" >/dev/null 2>&1 || true
  done
}

# a running capture first (keeps what was recorded so far)
if systemctl is-active --quiet aegis-homelab-capture; then
  "$HOMELAB_DIR/capture.sh" stop || systemctl stop aegis-homelab-capture || true
fi

# Raspberry Pi access-point mode (setup-ap.sh) vs laptop hotspot (NetworkManager): never touch a
# laptop's own Wi-Fi interface address or a hostapd the lab did not configure
PI_MODE=0
is_managed /etc/systemd/system/aegis-homelab-addr.service && PI_MODE=1
if [ "$PI_MODE" -eq 1 ]; then
  stop_unit hostapd.service aegis-homelab-firewall.service aegis-homelab-addr.service
fi
nft list table inet aegis_homelab >/dev/null 2>&1 && nft delete table inet aegis_homelab && log "firewall table removed"

remove_managed \
  /etc/hostapd/aegis-homelab.conf \
  /etc/systemd/system/hostapd.service.d/aegis-homelab.conf \
  /etc/dnsmasq.d/aegis-homelab.conf \
  /etc/systemd/system/dnsmasq.service.d/aegis-homelab.conf \
  /etc/systemd/system/aegis-homelab-addr.service \
  /etc/systemd/system/aegis-homelab-firewall.service \
  /etc/aegis-homelab/nftables.nft \
  /etc/sysctl.d/90-aegis-homelab.conf \
  /etc/logrotate.d/aegis-homelab \
  /etc/NetworkManager/conf.d/90-aegis-homelab.conf \
  /etc/NetworkManager/dnsmasq-shared.d/aegis-homelab.conf
rmdir /etc/aegis-homelab 2>/dev/null || true

systemctl daemon-reload
# hostapd / dnsmasq back to how they were before setup-ap.sh (usually: not running)
restore_unit_state hostapd.service dnsmasq.service
# forwarding back to its value before the lab (other sysctl.d settings are re-read first)
sysctl -q --system >/dev/null || true
restore_forward_state
[ "$PI_MODE" -eq 1 ] && { ip addr flush dev "$LAB_IFACE" 2>/dev/null || true; }
if systemctl is-active --quiet NetworkManager; then
  systemctl reload NetworkManager 2>/dev/null || systemctl restart NetworkManager || true
  if nmcli -t -f NAME connection show 2>/dev/null | grep -qx aegis-homelab; then
    nmcli connection delete aegis-homelab >/dev/null && log "removed NetworkManager hotspot connection"
  fi
fi

if [ "$PURGE" -eq 1 ]; then
  rm -rf "$CAPTURE_ROOT" "$LOG_DIR"
  log "deleted $CAPTURE_ROOT and $LOG_DIR"
else
  log "captures kept in $CAPTURE_ROOT (delete them with --purge-captures once analyzed)"
fi
log "lab removed. Factory-reset the device under test before any other use."
