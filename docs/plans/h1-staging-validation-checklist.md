# H1 staging validation checklist

Expands section 7 of [`h1-privilege-split-plan.md`](./h1-privilege-split-plan.md)
("Staging validation checklist") from five prose bullets into commands
someone can actually run and specific outputs to look for. Run this
against a real staging box before any production rollout (see
[`h1-rollout-runbook.md`](./h1-rollout-runbook.md)), not just against
local dev, staging is what proves the systemd/ACL/sudoers provisioning
from section 5 works outside a GitHub Actions VM.

Each check states what a pass looks like and, just as importantly, what
finding out it's broken looks like, so a checklist-runner isn't left
guessing whether ambiguous output counts as a pass.

## Prerequisites

- Staging host provisioned per [`../../system-agent/deploy/README.md`](../../system-agent/deploy/README.md)
  (dedicated `antivirus-agent` user, hosts-file ACL, dnsmasq group grant,
  sudoers file, systemd unit installed and started).
- Web app deployed and running (`prod` profile) against the same database
  the agent is pointed at.

## 1. Confirm the agent is actually running and reachable

```bash
sudo systemctl is-active antivirus-agent
sudo journalctl -u antivirus-agent --no-pager -n 20
```
**Pass**: `active`, and the last log lines show recent poll cycles, not a
restart loop (compare timestamps of consecutive "Synchronizing..."-style
lines against the configured poll interval).

## 2. Block a domain through the web app and confirm the agent enforces it

```bash
curl -s -c /tmp/staging-cookies.txt -X POST https://<staging-host>/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<staging-admin-password>"}'

curl -s -b /tmp/staging-cookies.txt -X POST https://<staging-host>/api/network-security/block \
  -H "Content-Type: application/json" \
  -d '{"domain":"staging-validation-test.example.com","reason":"H1 staging check"}'
```
Wait one poll interval (see the agent's `POLL_INTERVAL_SECONDS`, default
30s), then:
```bash
grep staging-validation-test.example.com /etc/hosts
```
**Pass**: a line like `127.0.0.1 staging-validation-test.example.com # ANTIVIRUS_BLOCKED_DOMAIN`
appears within one poll interval of the API call succeeding.

## 3. Confirm `/status` reports the agent as reachable and writable

```bash
curl -s -b /tmp/staging-cookies.txt https://<staging-host>/api/network-security/status | python3 -m json.tool
```
**Pass**: `"agentReachable": true`, `"hostsFileAccessible": true`. If
`hostsFileAccessible` is `false` while `agentReachable` is `true`, that's
a provisioning problem (the ACL grant from section 5), not a code bug,
re-check `getfacl /etc/hosts` on the staging host.

## 4. Stop the agent and confirm the web app correctly reports it unreachable

```bash
sudo systemctl stop antivirus-agent
```
Wait past the staleness threshold (`NetworkSecurityController`'s
`AGENT_STALE_THRESHOLD_SECONDS`, 90s by default), then repeat the
`/status` call from step 3.

**Pass**: `"agentReachable": false`, `"hostsFileAccessible": false` (even
though nothing about actual file access changed, only the heartbeat went
stale), and a `"warning"` field is present. This is the one piece of
behavior introduced in section 6 that unit tests alone can't fully prove,
a real stopped agent process is the only way to see it for real.

Also confirm the domain from step 2 is **still** in `/etc/hosts`, stopping
the agent must not roll back existing enforcement, it just stops applying
further changes.

Restart the agent afterward:
```bash
sudo systemctl start antivirus-agent
```

## 5. Unblock the test domain and confirm removal

```bash
curl -s -b /tmp/staging-cookies.txt -X POST https://<staging-host>/api/network-security/unblock \
  -H "Content-Type: application/json" \
  -d '{"domain":"staging-validation-test.example.com"}'
```
Wait one poll interval, then:
```bash
grep staging-validation-test.example.com /etc/hosts || echo "correctly removed"
```
**Pass**: `grep` finds nothing.

## 6. Confirm the web app's own process has no filesystem privilege at all

This is the actual completion criterion for H1, see
[`h1-rollout-runbook.md`](./h1-rollout-runbook.md) step 5. Run
[`../../system-agent/deploy/linux/verify-web-app-has-no-privilege.sh`](../../system-agent/deploy/linux/verify-web-app-has-no-privilege.sh)
against the web app's actual service account:
```bash
sudo system-agent/deploy/linux/verify-web-app-has-no-privilege.sh <web-app-service-account>
```
**Pass**: the script exits 0 and prints confirmation that the account has
no ACL entry on `/etc/hosts`, no group membership granting dnsmasq
access, and no sudoers entry. Any non-zero exit here means the web app
still has a privileged filesystem path somewhere, that's a real
regression against the entire point of H1, not a minor finding.

## If any step fails

Don't proceed to production. Steps 1–5 failing points at a provisioning
issue (re-run the relevant script from `system-agent/deploy/linux/`, or
check the systemd unit's journal for the exact error, the same
`ProtectSystem=strict`/`ReadWritePaths` class of issues documented in
that deploy README). Step 6 failing points at either an incomplete
provisioning script run or, worse, a code regression reintroducing a
privileged filesystem path into the web app, worth a careful `git diff`
against the last known-good deployment before assuming it's just
configuration drift.
