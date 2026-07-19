-- H1: provisions a dedicated, narrowly-scoped database role for the
-- privileged system-agent process.
--
-- WHO RUNS THIS: an operator/DBA with GRANT privileges on the production
-- database, exactly once per environment, as a manual deployment step.
--
-- WHY THIS IS NOT A FLYWAY MIGRATION: Flyway migrations run as the web
-- app's own database user. If that user could grant privileges to a new
-- role, it could just as easily grant itself more privileges, which is
-- itself a privilege-escalation path. Role provisioning has to happen
-- outside the app's own migration identity, by someone who already has
-- elevated DB access.
--
-- SCOPE OF THE GRANT: exactly two tables, read-only on one, read+write on
-- the other. Nothing else. If this role's credentials are ever
-- compromised (e.g. the agent host itself is compromised), the attacker
-- gains: the current list of blocked domains (already public-ish
-- information, it's enforced network-wide) and the ability to write to a
-- status/heartbeat table. They get nothing from app_users (no password
-- hashes), scan_results (no file paths or scan data), or any other table
-- in the schema.
--
-- TARGET DATABASE: this assumes a real multi-user RDBMS in production
-- (PostgreSQL, per the recommendation in DatasourceSafetyConfig and
-- README's Production Deployment section). Local/dev H2 profiles
-- (application-dev.properties, application-local.properties) do not need
-- this script at all, run the agent (if you're testing it locally) against
-- the same H2 file the web app uses, with no separate role, dev-only
-- convenience takes priority there since nothing on a dev machine is
-- actually privileged.
--
-- USAGE:
--   1. Replace CHANGE_ME_STRONG_PASSWORD below with a real generated secret
--      (e.g. `openssl rand -base64 32`) before running this against prod.
--      Do not commit the real password anywhere, including here.
--   2. Run as a superuser or a role with CREATEROLE + GRANT privileges:
--        psql -h <host> -U <admin-user> -d antivirus -f provision-agent-db-role.sql
--   3. Put the resulting username/password into the agent's own config
--      (see system-agent's AgentConfig / agent.properties), never into the
--      web app's configuration.
DO $$ BEGIN IF NOT EXISTS (
    SELECT
    FROM pg_catalog.pg_roles
    WHERE rolname = 'antivirus_agent'
) THEN CREATE ROLE antivirus_agent LOGIN PASSWORD 'CHANGE_ME_STRONG_PASSWORD';
END IF;
END $$;
-- Read-only: the agent only ever needs to know which domains are
-- currently active. It never inserts, updates, or deletes a domain, the
-- web app is the sole writer of intent.
GRANT SELECT ON blocked_domains TO antivirus_agent;
-- Read+write: the agent reports its own status/heartbeat here.
GRANT SELECT,
    UPDATE ON agent_status TO antivirus_agent;
-- Explicit denials, spelled out rather than relying on "no grant means no
-- access" by default, so a future schema change (a new table with an
-- overly permissive default GRANT, e.g. via ALTER DEFAULT PRIVILEGES)
-- doesn't silently widen this role's access without someone noticing it
-- here first.
REVOKE ALL ON app_users
FROM antivirus_agent;
REVOKE ALL ON scan_results
FROM antivirus_agent;
-- Sanity check: run this after the grants above to eyeball the final
-- privilege set before considering the role "provisioned".
--   SELECT grantee, table_name, privilege_type
--   FROM information_schema.role_table_grants
--   WHERE grantee = 'antivirus_agent'
--   ORDER BY table_name, privilege_type;
-- Expected output: exactly (blocked_domains, SELECT), (agent_status, SELECT),
-- (agent_status, UPDATE). Anything else here means this script or the
-- schema's default privileges need a second look before deploying the
-- agent against this database.