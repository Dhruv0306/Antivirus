# Deployment

Development happens on Windows; the production target is Linux. This page covers the production path.

## Web app

Build the jar and run it under the `prod` profile:

```bash
mvn clean package
java -jar target/antivirus-*.jar --spring.profiles.active=prod
```

`prod` requires `CORS_ALLOWED_ORIGINS` to be set explicitly with no `localhost` fallback; the app refuses to start otherwise. It also expects `DB_URL` to point at a real database rather than the default in-memory H2 used elsewhere.

## Database role for system-agent

Before deploying system-agent anywhere new, an operator with database admin rights runs this once, manually:

```bash
psql -h <host> -U <admin-user> -d antivirus -f docs/deployment/provision-agent-db-role.sql
```

This grants the `antivirus_agent` role exactly `SELECT` on `blocked_domains` and `SELECT`+`UPDATE` on `agent_status`, nothing else. It's a manual step rather than a Flyway migration on purpose: the web app's own migration identity should never have the ability to grant itself, or anything else, more database privileges than it already has.

## system-agent

Full systemd unit, sudoers entries, and provisioning scripts live in `system-agent/deploy/`; that README is the authoritative reference and is kept current independently of this wiki. A few things worth knowing going in, from hard-won debugging:

- `ReadWritePaths=` in the systemd unit needs the paths to already exist when the service starts. Use a `-` prefix for paths that are genuinely optional.
- `PrivateTmp=yes` and `PrivateHome=yes` hide `/tmp` and `/home` from the service; don't expect files placed there manually to be visible to the agent process.
- `systemd-analyze verify` exits `0` even when there are real problems with the unit file; check stderr, not just the exit code.
- Point `ExecStart=` at `$JAVA_HOME/bin/java`, not `/usr/bin/java`, so the service actually runs under the intended JDK rather than whatever happens to be the system default.

## Releases

Tagged releases (`vX.Y.Z`) trigger `.github/workflows/release.yml`, which builds both jars, pulls the matching version section out of `CHANGELOG.md` for release notes, and publishes a GitHub release with both jars attached. It's idempotent: re-pushing an existing tag, or a workflow re-run, won't overwrite a release that's already there.
