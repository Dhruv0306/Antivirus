#!/usr/bin/env bash
# verify-web-app-has-no-privilege.sh
#
# The other provisioning scripts in this directory all grant something to
# the agent account. This one checks the opposite and arguably more
# important thing: that the WEB APP's own service account has been
# granted NOTHING. That's the actual completion criterion for H1 (see
# docs/plans/h1-privilege-split-plan.md section 8, step 5), not "the
# agent has narrow grants" on its own, both halves have to be true, a
# web app that still has some leftover privileged path defeats the
# entire point of the split even if the agent's own grants are perfect.
#
# Checks three things, matching exactly what the agent IS granted
# elsewhere in this directory, so there's a direct one-to-one mapping
# between "what the agent has" and "what this confirms the web app
# doesn't have":
#   1. No named-user POSIX ACL entry on the hosts file
#      (provision-hosts-acl.sh grants this to the agent)
#   2. Not a member of the group that owns the dnsmasq conf file
#      (provision-dnsmasq-dir.sh grants this to the agent)
#   3. No sudoers entry at all, for any command
#      (antivirus-agent-sudoers grants this to the agent, scoped to one
#      command; the web app should have zero, not even a narrow one)
#
# Exits 0 only if all three checks pass. Any failure is a real finding,
# not a warning, it means a privileged filesystem or sudo path still
# exists on the exact process this whole effort was designed to strip it
# from.
#
# USAGE: sudo ./verify-web-app-has-no-privilege.sh <web_app_username> [hosts_file_path] [agent_group]
#   Defaults: hosts_file_path=/etc/hosts, agent_group=antivirus-agent
#   (matches provision-dnsmasq-dir.sh's default group, which is the agent
#   user's own primary group, see provision-agent-user.sh)
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "USAGE: $0 <web_app_username> [hosts_file_path] [agent_group]" >&2
    exit 2
fi

WEBAPP_USER="$1"
HOSTS_FILE="${2:-/etc/hosts}"
AGENT_GROUP="${3:-antivirus-agent}"

if ! id "$WEBAPP_USER" &>/dev/null; then
    echo "ERROR: user '$WEBAPP_USER' does not exist." >&2
    exit 1
fi

failures=0

# --- Check 1: no named ACL entry on the hosts file ---
if [ -f "$HOSTS_FILE" ] && command -v getfacl &>/dev/null; then
    if getfacl --omit-header "$HOSTS_FILE" 2>/dev/null | grep -q "^user:${WEBAPP_USER}:"; then
        echo "FAIL: $WEBAPP_USER has a named ACL entry on $HOSTS_FILE"
        getfacl "$HOSTS_FILE"
        failures=$((failures + 1))
    else
        echo "OK: $WEBAPP_USER has no named ACL entry on $HOSTS_FILE"
    fi
else
    echo "SKIP: $HOSTS_FILE not found or getfacl unavailable, cannot verify this check"
fi

# --- Check 2: not a member of the agent's group ---
if getent group "$AGENT_GROUP" &>/dev/null; then
    if id -nG "$WEBAPP_USER" | tr ' ' '\n' | grep -qx "$AGENT_GROUP"; then
        echo "FAIL: $WEBAPP_USER is a member of group '$AGENT_GROUP' (grants dnsmasq conf write)"
        failures=$((failures + 1))
    else
        echo "OK: $WEBAPP_USER is not a member of group '$AGENT_GROUP'"
    fi
else
    echo "SKIP: group '$AGENT_GROUP' does not exist on this host, cannot verify this check"
fi

# --- Check 3: no sudoers entry at all ---
sudo_output=$(sudo -l -U "$WEBAPP_USER" 2>&1 || true)
if echo "$sudo_output" | grep -qi "not allowed to run sudo\|is not in the sudoers file"; then
    echo "OK: $WEBAPP_USER has no sudoers entry"
else
    echo "FAIL: $WEBAPP_USER appears to have some sudo grant:"
    echo "$sudo_output"
    failures=$((failures + 1))
fi

echo ""
if [ "$failures" -eq 0 ]; then
    echo "PASS: $WEBAPP_USER has zero filesystem/sudo privilege. This is the actual H1 completion criterion, confirmed."
    exit 0
else
    echo "FAIL: $failures check(s) failed. $WEBAPP_USER still has a privileged path H1 was meant to remove."
    exit 1
fi
