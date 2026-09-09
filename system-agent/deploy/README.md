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

## Running locally alongside the web app (no provisioning needed)

For quick local testing, `system-agent/target/system-agent.jar` can just
be run directly, no systemd, no ACLs, no sudo, none of the provisioning
below is needed for this. Point it at the same database the web app's
`local` profile uses:

```powershell
# Throwaway hosts file so no admin rights are needed either:
"127.0.0.1 localhost" | Out-File -Encoding ascii D:\github\Antivirus\test-hosts.txt
$env:HOSTS_FILE_PATH="D:\github\Antivirus\test-hosts.txt"
$env:POLL_INTERVAL_SECONDS="5"
java -jar system-agent\target\system-agent.jar
```

Wait for `"hosts file updated with 0 blocked domain(s)"` in the agent's
own log before doing anything else — that's confirmation it started,
found the hosts file, and completed its first poll cycle. If that line
doesn't appear, don't move on to testing domain blocking; see
"Troubleshooting" below.

**If you're running the web app (`local` profile) at the same time**,
which is the actual point of this, proving the two processes talk to each
other through the database, both sides need `AUTO_SERVER=TRUE` on the H2
URL. H2's embedded file mode otherwise locks the database exclusively to
whichever process opens it first, the second one to connect gets
`Database may be already in use ... file is locked`, not a real error,
just H2 refusing concurrent access by default. `AgentConfig`'s own
default `DB_URL` already includes this, and so does
`application-local.properties`, so this works out of the box as long as
neither side overrides `DB_URL` with a URL that drops the flag.

**Use the `local` profile, not `dev`.** `application-dev.properties`
points at `jdbc:h2:mem:antivirus_v3`, an in-memory database private to
that one JVM — the agent (a separate process) can never see it no matter
what `DB_URL` you give it, since H2's `mem:` mode isn't cross-process
without a TCP server. `application-local.properties` is the one built
for this pairing (file-based, `AUTO_SERVER=TRUE`, same default DB name
the agent expects). Running `dev` alongside the agent won't error, it'll
just look like the agent is silently doing nothing: `DomainSyncTask`
only logs when the domain set changes, so against an empty database
that never changes, you'd only ever see that one startup log line and
nothing after — easy to mistake for "the agent isn't polling" when it's
actually polling a completely different, permanently-empty database.

```powershell
mvn clean spring-boot:run "-Dspring-boot.run.profiles=local"
```

### End-to-end test: block a domain and watch the agent enforce it

This drives the real web app API (auth, CSRF, validation) rather than
writing to the database directly, so it actually proves the full pipeline
works, not just the agent in isolation. Requires the web app (`local`
profile) and the agent both already running per above.

```powershell
$base = "http://localhost:8080"

# 1. CSRF + session
$csrf = Invoke-RestMethod -Uri "$base/api/auth/csrf" -Method Get -SessionVariable session
$token = $csrf.token

# 2. Login (replace with your real local admin credentials)
$loginBody = @{ username = "admin"; password = "YOUR_LOCAL_ADMIN_PASSWORD" }
Invoke-RestMethod -Uri "$base/api/auth/login" -Method Post -WebSession $session `
  -Headers @{ "X-XSRF-TOKEN" = $token } `
  -ContentType "application/x-www-form-urlencoded" -Body $loginBody

# 3. Re-fetch the CSRF token — Spring Security rotates it on successful
#    login, so the pre-login token from step 1 will 403 on every POST
#    from here on if you reuse it.
$csrf = Invoke-RestMethod -Uri "$base/api/auth/csrf" -Method Get -WebSession $session
$token = $csrf.token

# 4. Confirm you're actually authenticated as ADMIN
Invoke-RestMethod -Uri "$base/api/auth/me" -WebSession $session

# 5. Block a domain
$blockBody = @{ domain = "github.com" } | ConvertTo-Json
Invoke-RestMethod -Uri "$base/api/network-security/block" -Method Post -WebSession $session `
  -Headers @{ "X-XSRF-TOKEN" = $token } -ContentType "application/json" -Body $blockBody

# 6. Wait past one poll cycle, then check the hosts file directly
Start-Sleep -Seconds 6
Get-Content D:\github\Antivirus\test-hosts.txt
# expect a new line: 127.0.0.1 github.com # ANTIVIRUS_BLOCKED_DOMAIN

# 7. Status should now show the agent reachable, hosts file writable,
#    and the domain listed
Invoke-RestMethod -Uri "$base/api/network-security/status" -WebSession $session | ConvertTo-Json -Depth 5

# 8. Unblock and confirm the agent removes the line again
$unblockBody = @{ domain = "github.com" } | ConvertTo-Json
Invoke-RestMethod -Uri "$base/api/network-security/unblock" -Method Post -WebSession $session `
  -Headers @{ "X-XSRF-TOKEN" = $token } -ContentType "application/json" -Body $unblockBody
Start-Sleep -Seconds 6
Get-Content D:\github\Antivirus\test-hosts.txt
```

The agent's log should print `"hosts file updated with 1 blocked domain(s)"`
after step 5, and `"...0 blocked domain(s)"` after step 8.

**Use `Invoke-RestMethod`, not `curl.exe`, for the JSON-body requests.**
PowerShell reconstructs the command line when handing arguments to a
native executable like `curl.exe`, and embedded `\"` sequences in a
`-d '{\"domain\":\"...\"}'` argument frequently get mangled in that
handoff — the request either never carries valid JSON or silently fails
domain validation, with no obvious error since `curl.exe -s` still exits
0. `Invoke-RestMethod -Body (... | ConvertTo-Json)` builds the request
directly with no subprocess or command-line parsing involved, and throws
a real, visible exception on a non-2xx response instead of failing
silently.

### Troubleshooting

- **Only one `"hosts file updated"` log line, ever, no matter what you
  block.** Check the web app's active profile is `local`, not `dev` (see
  above). `DomainSyncTask` only logs when the domain set changes since
  the last poll, so silence after the first line usually means the agent
  and the web app are reading two different databases, not that polling
  stopped.
- **`hostsFileAccessible: false` / `hasAdminPrivileges: false` in
  `/api/network-security/status`.** `HostsFileWriter.isWritable()`
  requires the target file to already exist (`Files.exists(hostsPath)`),
  it won't create one. Re-run the `Out-File` throwaway-hosts-file command
  above before starting the agent — this file doesn't persist across
  fresh clones/sessions the way the H2 file database does.
- **`403` on every POST after a successful login.** The CSRF token
  rotates on login; you're reusing the pre-login token. Re-fetch
  `/api/auth/csrf` once, immediately after login, and use that value for
  every subsequent state-changing request in the same session.
- **Leftover `HOSTS_FILE_PATH`/`POLL_INTERVAL_SECONDS`/`DB_URL` env vars
  from an earlier test.** `AgentConfig.get()` checks `System.getenv()`
  before the properties file or built-in default, unconditionally, on
  every call — including from `AgentConfigTest`'s `fromProperties()`
  construction. A value set with `$env:VAR = "..."` in a PowerShell
  session persists for every command after it, Maven's test JVM
  included, and can make `AgentConfigTest` fail with no code change
  involved. `Remove-Item Env:\VAR_NAME` before re-running `mvn test` if
  its assertions suddenly don't match the documented defaults.

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

**These commands only confirm what the agent has.** They don't confirm
the web app doesn't have the same thing, that's a separate, equally
important check:
```bash
sudo ./verify-web-app-has-no-privilege.sh <web-app-service-account>
```
See [`../../docs/plans/h1-rollout-runbook.md`](../../docs/plans/h1-rollout-runbook.md)
step 5, this is the actual H1 completion criterion, not an optional
extra.

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
