package com.antivirus.agent;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * Writes the agent's own heartbeat/status row (see V5__add_agent_status.sql
 * in the web app). This is the only table the agent's DB role has UPDATE
 * on (see docs/deployment/provision-agent-db-role.sql); the web app reads
 * this row for its /api/network-security/status endpoint but never writes
 * it, this class is the single source of truth for that row.
 */
public final class AgentStatusReporter {

    private static final String UPDATE_SQL =
            "UPDATE agent_status SET " +
                    "hosts_file_writable = ?, " +
                    "dns_config_writable = ?, " +
                    "last_heartbeat_at = CURRENT_TIMESTAMP, " +
                    "last_sync_at = CURRENT_TIMESTAMP, " +
                    "last_sync_error = ? " +
                    "WHERE id = 1";

    /**
     * Reports a successful (or partially successful, if one writer failed
     * but the cycle otherwise completed) sync. {@code lastSyncError} is
     * null on a fully clean cycle.
     */
    public void reportSync(Connection connection, boolean hostsFileWritable, boolean dnsConfigWritable,
            String lastSyncError) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(UPDATE_SQL)) {
            statement.setBoolean(1, hostsFileWritable);
            statement.setBoolean(2, dnsConfigWritable);
            statement.setString(3, lastSyncError);
            statement.executeUpdate();
        }
    }

    private static final String HEARTBEAT_ONLY_SQL =
            "UPDATE agent_status SET last_heartbeat_at = CURRENT_TIMESTAMP WHERE id = 1";

    /**
     * Heartbeat-only update, used when a poll cycle fails before it can
     * determine writability/sync outcome at all (e.g. the DB query itself
     * failed). Keeps last_heartbeat_at fresh, so the web app can still
     * distinguish "agent is running but had a bad cycle" from "agent
     * process is down entirely" (see NetworkSecurityController's planned
     * staleness check in section 6 of the plan).
     */
    public void reportHeartbeatOnly(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(HEARTBEAT_ONLY_SQL)) {
            statement.executeUpdate();
        }
    }
}
