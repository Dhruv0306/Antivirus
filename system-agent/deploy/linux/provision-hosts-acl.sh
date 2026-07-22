#!/usr/bin/env bash
# provision-hosts-acl.sh
#
# Grants the agent user read/write access to the hosts file via a POSIX
# ACL, deliberately not chown (that would take ownership away from root),
# not a Linux capability (CAP_DAC_OVERRIDE is effectively root-equivalent
# for file access, defeating the point), and not sudo (systemctl reload
# is the one place this deployment actually needs sudo, see the sudoers
# file, everything else should be a plain DAC grant). See
# docs/plans/h1-privilege-split-plan.md section 5 for the full reasoning.
#
# Idempotent: re-running just re-applies the same ACL entry.
#
# USAGE: sudo ./provision-hosts-acl.sh [hosts_file_path] [agent_username]
#   Defaults: /etc/hosts, antivirus-agent
#   The path argument exists mainly so CI/tests can point this at a
#   throwaway file instead of the real system hosts file.
set -euo pipefail

HOSTS_FILE="${1:-/etc/hosts}"
AGENT_USER="${2:-antivirus-agent}"

if ! command -v setfacl &>/dev/null; then
    echo "ERROR: setfacl not found. Install the 'acl' package (e.g. apt-get install acl)." >&2
    exit 1
fi

if ! id "$AGENT_USER" &>/dev/null; then
    echo "ERROR: user '$AGENT_USER' does not exist. Run provision-agent-user.sh first." >&2
    exit 1
fi

if [ ! -f "$HOSTS_FILE" ]; then
    echo "ERROR: $HOSTS_FILE does not exist." >&2
    exit 1
fi

setfacl -m "u:${AGENT_USER}:rw" "$HOSTS_FILE"

echo "Granted rw ACL on $HOSTS_FILE to $AGENT_USER."
echo "Verify with: getfacl $HOSTS_FILE"
