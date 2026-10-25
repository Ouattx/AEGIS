#!/usr/bin/env bash
# AEGIS home lab: turn a Raspberry Pi (Raspberry Pi OS Bookworm / Debian 12) into an ISOLATED
# Wi-Fi access point for ONE device under test.
#
#   sudo ./setup-ap.sh            # install / update (safe to re-run: idempotent)
#   sudo ./teardown.sh            # undo everything this script did
#
# What it sets up
#   * hostapd: WPA2 access point on LAB_IFACE with client isolation (ap_isolate=1)
#   * dnsmasq: DHCP + DNS for the lab only, every query logged (log-queries=extra) to
#     /var/log/aegis-homelab/dnsmasq.log with UTC timestamps
#   * nftables table "aegis_homelab": NAT to UPLINK_IFACE, no access to your home LAN or to the
#     Pi itself (DHCP/DNS only), no IPv6, DNS interception to the logged resolver, optional
#     rate cap and DNS-over-TLS block
#   * IPv4 forwarding (sysctl drop-in)
#
# It does NOT start a capture: run ./capture.sh start when the device is connected.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$(cd "$(dirname "$0")" && pwd)/common.sh"

require_root "$@"
load_env
require_passphrase

if ! grep -qiE 'debian|raspbian' /etc/os-release 2>/dev/null; then
  die "this script targets Raspberry Pi OS / Debian; on a laptop use laptop-hotspot-linux.sh"
fi
ip link show "$LAB_IFACE" >/dev/null 2>&1 || die "interface $LAB_IFACE not found"
ip link show "$UPLINK_IFACE" >/dev/null 2>&1 || die "uplink interface $UPLINK_IFACE not found"
[ "$LAB_IFACE" != "$UPLINK_IFACE" ] || die "LAB_IFACE and UPLINK_IFACE must differ"

# ---------------------------------------------------------------- packages
missing=()
for pkg in hostapd dnsmasq nftables tcpdump iw; do
  dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
done
if [ "${#missing[@]}" -gt 0 ]; then
  log "installing: ${missing[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"
fi

# ---------------------------------------------------------------- keep NetworkManager off the lab interface
if systemctl is-active --quiet NetworkManager; then
  if [ -n "$(printf '[keyfile]\nunmanaged-devices=interface-name:%s\n' "$LAB_IFACE" \
        | write_managed /etc/NetworkManager/conf.d/90-aegis-homelab.conf)" ]; then
    systemctl reload NetworkManager || systemctl restart NetworkManager
  fi
fi
rfkill unblock wlan 2>/dev/null || true

# ---------------------------------------------------------------- static address on the lab interface
write_managed /etc/systemd/system/aegis-homelab-addr.service >/dev/null <<EOF
[Unit]
Description=AEGIS home lab: address on $LAB_IFACE
Before=hostapd.service dnsmasq.service
After=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ip link set $LAB_IFACE up
ExecStart=/usr/sbin/ip addr replace $LAB_GATEWAY/$LAB_PREFIX_LEN dev $LAB_IFACE
ExecStop=/usr/sbin/ip addr flush dev $LAB_IFACE

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------- hostapd (WPA2, client isolation)
write_managed /etc/hostapd/aegis-homelab.conf 0600 >/dev/null <<EOF
interface=$LAB_IFACE
driver=nl80211
ssid=$LAB_SSID
country_code=$COUNTRY_CODE
ieee80211d=1
hw_mode=g
channel=$WIFI_CHANNEL
wmm_enabled=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=$LAB_PASSPHRASE
# lab clients cannot talk to each other at layer 2
ap_isolate=1
ignore_broadcast_ssid=0
max_num_sta=4
EOF
write_managed /etc/systemd/system/hostapd.service.d/aegis-homelab.conf >/dev/null <<EOF
[Unit]
Requires=aegis-homelab-addr.service
After=aegis-homelab-addr.service

[Service]
ExecStart=
ExecStart=/usr/sbin/hostapd /etc/hostapd/aegis-homelab.conf
EOF

# ---------------------------------------------------------------- dnsmasq (DHCP + logged DNS for the lab only)
install -d -m 0750 "$LOG_DIR"
# dnsmasq reopens its log as the unprivileged dnsmasq user after rotation
if id dnsmasq >/dev/null 2>&1; then chown dnsmasq:adm "$LOG_DIR" 2>/dev/null || chown dnsmasq "$LOG_DIR"; fi
servers=""
for s in $UPSTREAM_DNS; do servers="${servers}server=$s"$'\n'; done
write_managed /etc/dnsmasq.d/aegis-homelab.conf >/dev/null <<EOF
interface=$LAB_IFACE
bind-interfaces
except-interface=lo
listen-address=$LAB_GATEWAY
no-resolv
${servers}domain-needed
bogus-priv
no-hosts
dhcp-range=$DHCP_START,$DHCP_END,255.255.255.0,12h
dhcp-option=option:router,$LAB_GATEWAY
dhcp-option=option:dns-server,$LAB_GATEWAY
dhcp-authoritative
# every query with its serial number and client (parsed by aegis.homelab.dnsmasq)
log-queries=extra
log-dhcp
log-facility=$DNSMASQ_LOG
EOF
# UTC timestamps in the query log (syslog-style lines carry no timezone)
write_managed /etc/systemd/system/dnsmasq.service.d/aegis-homelab.conf >/dev/null <<EOF
[Unit]
Requires=aegis-homelab-addr.service
After=aegis-homelab-addr.service

[Service]
Environment=TZ=UTC
EOF
write_managed /etc/logrotate.d/aegis-homelab >/dev/null <<EOF
$DNSMASQ_LOG {
  daily
  rotate 14
  missingok
  notifempty
  compress
  delaycompress
  postrotate
    systemctl kill -s USR2 dnsmasq.service >/dev/null 2>&1 || true
  endscript
}
EOF

# ---------------------------------------------------------------- forwarding + firewall
save_forward_state
write_managed /etc/sysctl.d/90-aegis-homelab.conf >/dev/null <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.$LAB_IFACE.disable_ipv6=1
EOF
sysctl -q --system >/dev/null
nft_lab_rules aegis_homelab "$LAB_IFACE" "$UPLINK_IFACE" | write_managed /etc/aegis-homelab/nftables.nft >/dev/null
write_managed /etc/systemd/system/aegis-homelab-firewall.service >/dev/null <<EOF
[Unit]
Description=AEGIS home lab firewall (nftables table inet aegis_homelab)
After=nftables.service network-pre.target
Before=hostapd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/sbin/nft delete table inet aegis_homelab
ExecStart=/usr/sbin/nft -f /etc/aegis-homelab/nftables.nft
ExecStop=-/usr/sbin/nft delete table inet aegis_homelab

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------- (re)start
save_unit_state hostapd.service dnsmasq.service
systemctl daemon-reload
systemctl unmask hostapd.service >/dev/null 2>&1 || true
systemctl enable --quiet aegis-homelab-addr.service aegis-homelab-firewall.service hostapd.service dnsmasq.service
systemctl restart aegis-homelab-addr.service aegis-homelab-firewall.service
systemctl restart hostapd.service dnsmasq.service

log "lab access point '$LAB_SSID' is up on $LAB_IFACE ($LAB_GATEWAY/$LAB_PREFIX_LEN), NAT via $UPLINK_IFACE"
log "DNS query log: $DNSMASQ_LOG"
log "rate cap: ${EGRESS_RATE_KBYTES:-none} kB/s; DoT blocked: $BLOCK_DOT"
log "next: connect ONLY the device under test, then: sudo ./capture.sh start"
