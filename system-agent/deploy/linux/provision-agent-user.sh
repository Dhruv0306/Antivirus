#!/usr/bin/env bash
# provision-agent-user.sh
#
# Creates the dedicated, unprivileged system user the agent runs as.
# No login shell, no password, no home directory needed, this account
# exists only to be the identity systemd runs the agent process under and
# the identity the ACL/group grants (provision-hosts-acl.sh,
# provision-dnsmasq-dir.sh) target.
#
# Idempotent: safe to re-run, does nothing if the user already exists.
#
# USAGE: sudo ./provision-agent-user.sh [username]
set -euo pipefail

AGENT_USER="${1:-antivirus-agent}"

if id "$AGENT_USER" &>/dev/null; then
    echo "User '$AGENT_USER' already exists, nothing to do."
    exit 0
fi

useradd \
    --system \
    --no-create-home \
    --shell /usr/sbin/nologin \
    --comment "Antivirus system-agent service account (privileged domain-blocking sync)" \
    "$AGENT_USER"

echo "Created system user '$AGENT_USER'."
echo "Next: run provision-hosts-acl.sh and provision-dnsmasq-dir.sh for this user."
