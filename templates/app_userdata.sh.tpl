#!/bin/bash
set -eux
mkdir -p /opt/app /var/log/app
echo '${app_script_b64}' | base64 -d | gunzip > /opt/app/app.py
chmod 755 /opt/app/app.py

cat > /etc/systemd/system/demo-app.service <<'UNIT'
[Unit]
Description=Demo protected application
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/app/app.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now demo-app.service
