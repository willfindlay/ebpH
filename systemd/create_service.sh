#!/bin/sh

SYSTEMD_PATH=/etc/systemd/system
SERVICE_DIR="$(dirname "${BASH_SOURCE:=$0}")"
SERVICE=ebphd.service

cp -f "$SERVICE_DIR/$SERVICE" "$SYSTEMD_PATH/$SERVICE"
chown root:root "$SYSTEMD_PATH/$SERVICE"

systemctl enable "$SERVICE"
