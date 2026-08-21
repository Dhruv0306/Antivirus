# H1 rollout runbook

Expands section 8 of [`h1-privilege-split-plan.md`](./h1-privilege-split-plan.md)
("Rollout sequencing") from five planning bullets into an actual runbook
referencing the real artifacts built in sections 3–8. Follow this in
order; each step depends on the previous one having actually succeeded,
not just been attempted.

## Step 1: Land the read-only side first (safe, no behavior change)

This already happened, in section 6 (`agent_status` migration,
`AgentStatusRepository`, `NetworkSecurityController` reading it). Nothing
to do here for a fresh rollout, this step is listed for completeness
since the plan's original sequencing put it first, and it's worth
confirming it's actually deployed before proceeding:
```bash
curl -s https://<host>/api/network-security/status | python3 -m json.tool
```
Should return `"agentReachable": false` (no agent deployed yet) rather
than an error, that's the "no behavior change" property this step was
meant to guarantee, the endpoint degrades gracefully instead of breaking.

## Step 2: Deploy the agent to staging, verify it end to end

```bash
cd system-agent && mvn clean package -DskipTests
scp target/system-agent.jar <staging-host>:/tmp/
```

On the staging host, in order (see
[`../../system-agent/deploy/README.md`](../../system-agent/deploy/README.md)
for the full detail behind each command):
```bash
sudo ./provision-agent-user.sh
sudo ./provision-hosts-acl.sh
sudo ./provision-dnsmasq-dir.sh          # only if DNS blocking will be used
sudo cp antivirus-agent-sudoers /etc/sudoers.d/antivirus-agent
sudo chmod 440 /etc/sudoers.d/antivirus-agent
sudo visudo -c -f /etc/sudoers.d/antivirus-agent
sudo mkdir -p /opt/antivirus-agent
sudo mv /tmp/system-agent.jar /opt/antivirus-agent/system-agent.jar
# Edit antivirus-agent.service's ExecStart if the jar path differs, and
# confirm /usr/bin/java on this host is actually Java 21+ (see the
# comment on that line, this exact assumption broke CI once already).
sudo cp antivirus-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now antivirus-agent
```

Then run the full
[`h1-staging-validation-checklist.md`](./h1-staging-validation-checklist.md).
**Do not proceed to step 3 until every check in that list passes.** This
is the step that actually proves the agent works against this specific
host's real permissions, not just against a GitHub Actions VM.

## Step 3: Deploy to production, agent before web app changes

Deploy the agent to production the same way as step 2, provisioning
scripts, systemd unit, the works, **before** touching the production web
app's deployment at all. At this point in production: the agent is
running and keeping `agent_status` fresh, but the production web app is
still whatever version predates this rollout (either pre-H1 entirely, or
mid-rollout on an earlier host). This ordering means there's a window
where the agent is live but nothing's consuming its output yet, that's
intentional and safe, an agent polling an unpopulated or
not-yet-referenced `blocked_domains` table does nothing harmful.

Confirm via the same `/status` check as step 1, `agentReachable` should
now flip to `true` in production.

## Step 4: Deploy the web app with the H1 cutover (section 6 code)

Standard deployment of the section 6 changes. Once live, run steps 2–5 of
the staging checklist again, but against production, block a real
(test) domain, confirm enforcement, confirm removal, confirm `/status`
reachability.

## Step 5: Confirm completion, the actual criterion

This is the step that's easy to skip because everything already looks
like it's working, don't skip it. "The agent works" and "the web app has
been fully stripped of privilege" are two different claims; only the
second one is what H1 was actually for.

```bash
sudo system-agent/deploy/linux/verify-web-app-has-no-privilege.sh <web-app-service-account>
```

**This must exit 0 before H1 is considered complete for this
environment.** If it doesn't:
- A named ACL entry on the hosts file for the web app's account means
  either leftover provisioning from before this rollout, or a
  configuration management script that's still granting it (check
  whatever provisioned the host before this rollout existed).
- Group membership in the agent's group means the web app's account was
  added to it at some point, intentionally or not, remove it.
- Any sudoers entry at all means something granted the web app account
  privilege outside of what these runbooks describe, track down what and
  why before removing it, don't just delete the grant blind.

Once this passes, H1 is done for that environment: the web app process
has zero code path and zero OS-level grant capable of writing to the
filesystem for domain blocking, that capability belongs entirely to the
agent, confirmed, not assumed.
