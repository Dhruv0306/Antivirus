# system-agent deployment runbook

This directory contains the provisioning artifacts for the H1 privilege
split (see [`docs/plans/h1-privilege-split-plan.md`](../../docs/plans/h1-privilege-split-plan.md)
section 5). Everything here is Linux-first, since that's the real
production target (systemd, POSIX ACLs, sudoers); a Windows equivalent is
included for the hosts-file grant only, dnsmasq/systemctl have no Windows
analog and that code path is already Linux-only in the main app.

None of this is exercised by the application's own test suite (`mvn test`
in either `system-agent/` or the root project), it's OS-level provisioning,
not application code. It's validated instead by the CI simulation
workflows described below, since neither of us can run systemd, `setfacl`,
or `sudo` meaningfully on a Windows dev machine.

## Linux deployment order

Run as root (or via `sudo`), in this order, each step depends on the
previous one having succeeded:

```bash
sudo ./linux/provision-agent-user.sh
sudo ./linux/provision-hosts-acl.sh
sudo ./linux/provision-dnsmasq-dir.sh
sudo cp ./linux/antivirus-agent-sudoers /etc/sudoers.d/antivirus-agent
sudo chmod 440 /etc/sudoers.d/antivirus-agent
sudo visudo -c -f /etc/sudoers.d/antivirus-agent
# Edit ExecStart in antivirus-agent.service to point at the real deployed jar path first.
sudo cp ./linux/antivirus-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now antivirus-agent
sudo systemctl status antivirus-agent
```

Each provisioning script accepts overrides as positional arguments (e.g.
a different hosts-file path, a different agent username) specifically so
they can be pointed at throwaway paths for testing rather than the real
system files, see the CI workflow for exactly that usage.

## Verifying the result

```bash
getfacl /etc/hosts                          # should show antivirus-agent:rw-
ls -l /etc/dnsmasq.d/antivirus-blocked.conf  # should show root:antivirus-agent, -rw-rw-r--
sudo -u antivirus-agent sudo -n systemctl reload dnsmasq   # should succeed with no password prompt
sudo -u antivirus-agent sudo -n systemctl restart sshd     # should be REFUSED — confirms the sudoers scope
```

That last command failing is not a bug, it's the actual point: confirming
the grant really is scoped to the one command in the sudoers file and
nothing broader.

## Windows (hosts-file grant only)

```powershell
# Create the service account first via your organization's standard process, then:
.\windows\provision-hosts-acl.ps1 -AgentUser "antivirus-agent"
```

There is no systemd equivalent shipped here for Windows. Running the
agent as a genuine Windows Service (rather than an interactive process)
needs either a service wrapper (e.g. WinSW) or Task Scheduler configured
to run at boot as the dedicated account; neither is included in this PR,
flagging it as a known gap rather than a false "handled" claim, since
production is Linux and this project's own dnsmasq code path is already
Linux-only.

## Why no automated end-to-end test exists for this locally

Every one of these scripts changes real OS-level state (users, ACLs,
sudoers, systemd units). None of it is safe or meaningful to run against
a developer's own machine as part of `mvn test`. The CI workflow
(`.github/workflows/system_agent_privilege_simulation.yml`) runs the
Linux scripts for real on a disposable GitHub-hosted VM (which does run
genuine systemd, unlike most containers) against throwaway paths and a
throwaway test user, and asserts the actual resulting permissions, not
just "the script exited zero." The Windows job does the same for the
hosts-file ACL script. See that workflow file for exactly what's
asserted and what isn't (documented there, not just implied).
