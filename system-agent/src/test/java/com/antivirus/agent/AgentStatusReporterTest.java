package com.antivirus.agent;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AgentStatusReporterTest {

    private Connection connection;
    private final AgentStatusReporter reporter = new AgentStatusReporter();

    @BeforeEach
    void setUp() throws Exception {
        // Isolated in-memory DB per test (unique name), same shape as
        // V5__add_agent_status.sql in the web app, kept in sync manually
        // here since this module intentionally has no dependency on the
        // web app's own Flyway migrations.
        String dbName = "agent_status_test_" + UUID.randomUUID();
        connection = DriverManager.getConnection("jdbc:h2:mem:" + dbName + ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL");
        try (Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE agent_status (
                        id BIGINT DEFAULT 1 PRIMARY KEY CHECK (id = 1),
                        hosts_file_writable BOOLEAN NOT NULL DEFAULT FALSE,
                        dns_config_writable BOOLEAN NOT NULL DEFAULT FALSE,
                        last_heartbeat_at TIMESTAMP NOT NULL,
                        last_sync_at TIMESTAMP,
                        last_sync_error VARCHAR(500)
                    )
                    """);
            statement.execute(
                    "INSERT INTO agent_status (id, hosts_file_writable, dns_config_writable, last_heartbeat_at) " +
                            "VALUES (1, FALSE, FALSE, CURRENT_TIMESTAMP)");
        }
    }

    @AfterEach
    void tearDown() throws Exception {
        connection.close();
    }

    @Test
    void reportSync_ShouldUpdateWritabilityAndClearErrorOnSuccess() throws Exception {
        reporter.reportSync(connection, true, false, null);

        try (Statement statement = connection.createStatement();
                ResultSet rs = statement.executeQuery("SELECT * FROM agent_status WHERE id = 1")) {
            assertTrue(rs.next());
            assertTrue(rs.getBoolean("hosts_file_writable"));
            assertFalse(rs.getBoolean("dns_config_writable"));
            assertNull(rs.getString("last_sync_error"));
            assertNotNull(rs.getTimestamp("last_sync_at"));
            assertNotNull(rs.getTimestamp("last_heartbeat_at"));
        }
    }

    @Test
    void reportSync_ShouldRecordErrorMessageOnFailure() throws Exception {
        reporter.reportSync(connection, false, false, "hosts file write failed: Access is denied");

        try (Statement statement = connection.createStatement();
                ResultSet rs = statement.executeQuery("SELECT * FROM agent_status WHERE id = 1")) {
            assertTrue(rs.next());
            assertEquals("hosts file write failed: Access is denied", rs.getString("last_sync_error"));
        }
    }

    @Test
    void reportHeartbeatOnly_ShouldUpdateHeartbeatWithoutTouchingSyncFields() throws Exception {
        // Seed a prior successful sync first, so we can confirm the
        // heartbeat-only path really does leave these fields alone.
        reporter.reportSync(connection, true, true, null);

        java.sql.Timestamp syncAtBefore;
        try (Statement statement = connection.createStatement();
                ResultSet rs = statement.executeQuery("SELECT last_sync_at FROM agent_status WHERE id = 1")) {
            rs.next();
            syncAtBefore = rs.getTimestamp("last_sync_at");
        }

        Thread.sleep(5); // ensure a measurable timestamp difference if last_heartbeat_at were to change
        reporter.reportHeartbeatOnly(connection);

        try (Statement statement = connection.createStatement();
                ResultSet rs = statement.executeQuery("SELECT * FROM agent_status WHERE id = 1")) {
            assertTrue(rs.next());
            assertEquals(syncAtBefore, rs.getTimestamp("last_sync_at"),
                    "heartbeat-only update must not touch last_sync_at");
            assertTrue(rs.getBoolean("hosts_file_writable"), "heartbeat-only update must not reset writability flags");
        }
    }
}
