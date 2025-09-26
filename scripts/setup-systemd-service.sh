#!/bin/sh

# Set up a systemd service to run the `ra-https-demo` server on boot.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
WORKDIR=$(cd "$SCRIPT_DIR/.." && pwd)
UNIT=/etc/systemd/system/ra-https.service
RUN_USER=${SUDO_USER:-root}

cat > "$UNIT" <<EOF
[Unit]
Description=RA-HTTPS Demo Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$WORKDIR
Environment=NODE_VERSION=22
ExecStart=/root/.nvm/nvm-exec npm run server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ra-https.service
systemctl restart ra-https.service || systemctl start ra-https.service
echo ok
