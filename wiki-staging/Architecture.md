# Architecture

## The two processes

SecureGuard runs as two separate Spring Boot processes that share one database:

**The web app** (`src/main/`) handles everything user-facing: authentication, file uploads, scanning, quarantine, and the network security dashboard. It runs under whatever account serves the web traffic, and it has no OS-level privileges beyond reading and writing files it's explicitly given paths to.

**system-agent** (`system-agent/`) does the one thing the web app deliberately can't: write to the hosts file and dnsmasq config to actually block a domain at the OS level. It runs under its own OS identity, with a narrow sudoers grant for exactly those two operations, and nothing else.

They don't call each other directly. Instead:

1. The web app writes a domain to `blocked_domains` when an admin blocks it.
2. system-agent polls that table, applies the change to the hosts file / dnsmasq, and writes its own health into a single `agent_status` row.
3. The web app reads `agent_status` to answer "is blocking actually being enforced right now" for the dashboard. It never writes to that table.

This split exists because a single process that both accepts arbitrary file uploads from users and holds root-equivalent privileges over system DNS is a large attack surface collapsed into one place. If the web app is compromised through, say, a scanning bug, the attacker still doesn't get a path to modifying the hosts file: system-agent is a different process, different OS user, different privilege set, talking to the database through a role that can only `SELECT` on `blocked_domains` and `SELECT`+`UPDATE` on `agent_status`.

See `docs/plans/h1-privilege-split-plan.md` in the repo for the original design rationale and the sequence of changes that got here, and `docs/plans/h1-rollout-runbook.md` for how it was rolled out.

## Request flow: scanning a file

1. Frontend sends `POST /api/antivirus/scan/file` as multipart form data.
2. `AntivirusController` validates the filename and content type against an allowlist.
3. `SecurityService` runs the actual scan logic and produces a verdict (see [Scanning and Verdicts](Scanning-and-Verdicts)).
4. The result is persisted as a `ScanResult` row, tagged with the calling user's username in `ownerUsername`.
5. If the verdict warrants it, the file is moved to the configured quarantine directory (`app.quarantine.dir`).
6. The frontend polls or re-fetches `/api/antivirus/history/me` to show the result.

## Data layer

- H2 running in PostgreSQL compatibility mode (not a toy in-memory choice here: it's deliberately run in file-backed mode with `AUTO_SERVER=TRUE` outside of `dev`, so schema behavior matches a real Postgres-like target closely enough that the SQL in migrations is portable)
- Flyway owns schema changes (`src/main/resources/db/migration/V1` through `V7`); Hibernate does not auto-migrate outside of the `dev` profile
- Hibernate/JPA for the ORM layer

## Frontend

React 18 + Vite + MUI. No server-side rendering, talks to the backend entirely over the `/api/**` REST surface with session cookies (not JWT) for auth. See `frontend/src/api/` for the request layer and `frontend/src/context/` for how auth state is held client-side.
