#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

UNIT=/etc/systemd/system/ra-https.service

systemctl stop ra-https.service 2>/dev/null || true
systemctl disable ra-https.service 2>/dev/null || true

rm -f "$UNIT"
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true