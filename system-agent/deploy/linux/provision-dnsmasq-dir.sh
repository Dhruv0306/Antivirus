#!/usr/bin/env bash
# provision-dnsmasq-dir.sh
#
# Creates (if needed) and grants group-write access to the dnsmasq config
# file the agent writes. Unlike /etc/hosts (a shared system file, hence
# the ACL approach in provision-hosts-acl.sh), this file is entirely
# owned by this application, so a plain group grant is simpler and just
# as narrow: root:antivirus-agent ownership, 664 permissions, exactly the
# one file, not the whole /etc/dnsmasq.d directory.
#
# Idempotent: safe to re-run.
#
# USAGE: sudo ./provision-dnsmasq-dir.sh [conf_path] [agent_username]
#   Defaults: /etc/dnsmasq.d/antivirus-blocked.conf, antivirus-agent
set -euo pipefail

CONF_PATH="${1:-/etc/dnsmasq.d/antivirus-blocked.conf}"
AGENT_USER="${2:-antivirus-agent}"
CONF_DIR="$(dirname "$CONF_PATH")"

if ! id "$AGENT_USER" &>/dev/null; then
    echo "ERROR: user '$AGENT_USER' does not exist. Run provision-agent-user.sh first." >&2
    exit 1
fi

mkdir -p "$CONF_DIR"

if [ ! -f "$CONF_PATH" ]; then
    touch "$CONF_PATH"
fi

chown "root:${AGENT_USER}" "$CONF_PATH"
chmod 664 "$CONF_PATH"

echo "Configured $CONF_PATH: owner root, group $AGENT_USER, mode 664."
echo "Verify with: ls -l $CONF_PATH"
