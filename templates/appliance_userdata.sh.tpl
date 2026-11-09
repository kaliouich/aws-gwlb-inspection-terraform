#!/bin/bash
set -eux
mkdir -p /opt/gwlb-ips /var/log/gwlb-ips
echo '${ips_script_b64}' | base64 -d | gunzip > /opt/gwlb-ips/ips.py
chmod 755 /opt/gwlb-ips/ips.py

cat > /etc/systemd/system/gwlb-ips.service <<'UNIT'
[Unit]
Description=GWLB GENEVE inline IPS (demo)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/gwlb-ips/ips.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now gwlb-ips.service
