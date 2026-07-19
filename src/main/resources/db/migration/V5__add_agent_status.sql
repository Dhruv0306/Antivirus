-- H1: adds the single source of truth for whether the privileged system-agent
-- process can currently enforce hosts-file / dnsmasq blocking.
--
-- The web app no longer probes /etc/hosts or /etc/dnsmasq.d itself (that
-- probing is a privileged filesystem check and belongs entirely to the
-- agent, which is the only process with the OS-level grants to do it
-- meaningfully). Instead the agent updates this row on every poll cycle,
-- and the web app's /api/network-security/status endpoint reads it.
--
-- id is pinned to 1 and enforced as a singleton via the CHECK constraint,
-- there is exactly one agent, so there is exactly one status row.
--
-- Constraint order matters here: H2's MODE=PostgreSQL parser requires
-- DEFAULT to appear before PRIMARY KEY in a column definition (real
-- PostgreSQL is more permissive about ordering; H2's compatibility-mode
-- grammar is stricter). DEFAULT 1 PRIMARY KEY CHECK (id = 1) is the order
-- that parses under both.
CREATE TABLE agent_status (
    id BIGINT DEFAULT 1 PRIMARY KEY CHECK (id = 1),
    hosts_file_writable BOOLEAN NOT NULL DEFAULT FALSE,
    dns_config_writable BOOLEAN NOT NULL DEFAULT FALSE,
    last_heartbeat_at TIMESTAMP NOT NULL,
    last_sync_at TIMESTAMP,
    last_sync_error VARCHAR(500)
);
-- Seed the singleton row so the web app has something to read before the
-- agent has ever run. last_heartbeat_at is set to the current time here
-- only so the column's NOT NULL constraint is satisfiable at insert time;
-- the web app's staleness check (see NetworkSecurityController) treats any
-- heartbeat older than 3x the agent's poll interval as "agent unreachable"
-- regardless of what hosts_file_writable/dns_config_writable say, so a
-- freshly-migrated environment with no agent deployed yet correctly shows
-- as unreachable rather than falsely appearing ready.
INSERT INTO agent_status (
        id,
        hosts_file_writable,
        dns_config_writable,
        last_heartbeat_at
    )
VALUES (1, FALSE, FALSE, CURRENT_TIMESTAMP);