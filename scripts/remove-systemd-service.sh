#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

UNIT=/etc/systemd/system/teekit-demo.service

systemctl stop teekit-demo.service 2>/dev/null || true
systemctl disable teekit-demo.service 2>/dev/null || true

rm -f "$UNIT"
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true
