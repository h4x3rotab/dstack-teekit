#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

UNIT=/etc/systemd/system/tee-channels.service

systemctl stop tee-channels.service 2>/dev/null || true
systemctl disable tee-channels.service 2>/dev/null || true

rm -f "$UNIT"
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true