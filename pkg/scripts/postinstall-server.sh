#!/usr/bin/env sh

# Reload the Systemd daemon
systemctl daemon-reload

# Enable and start the service
systemctl enable --now pam-oauth-server