package com.antivirus.agent;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The one test in this module that actually exercises the contract
 * between the web app and the agent end to end, per
 * docs/plans/h1-privilege-split-plan.md section 7. Every other test here
 * hand-copies the {@code blocked_domains}/{@code agent_status} schema
 * (see the comments in DomainSyncTaskTest/AgentStatusReporterTest
 * explaining why: this module intentionally has no runtime dependency on
 * the main app's code). That's fine for unit-level coverage but leaves a
 * real gap: if someone changes a migration in the root project without
 * updating this module's understanding of the schema, nothing catches
 * it. This test closes that gap by running the actual Flyway migrations
 * from {@code ../src/main/resources/db/migration}, the real source of
 * truth, not a hand-maintained copy.
 *
 * <p>Sequence: migrate a fresh DB with the real migrations -> insert a
 * domain via raw SQL (simulating exactly what the web app's
 * DomainBlockingServiceImpl.blockDomain() does, an INSERT into
 * blocked_domains) -> run the agent's actual sync cycle against that same
 * DB -> assert the hosts file and agent_status row reflect it. If a
 * future migration ever renames a column or changes a type in a way that
 * breaks the agent's assumptions, this test fails at the migration or
 * the sync step, not silently in production.
 */
class DomainSyncContractTest {

    private static final String MIGRATIONS_LOCATION = "filesystem:../src/main/resources/db/migration";
    // Relative to system-agent/ as the working directory, correct for
    // this module's established build workflow (`cd system-agent &&
    // mvn test`, this module is deliberately not part of the root
    // Maven reactor, see pom.xml's own top-level comment on why). Would
    // break if this module were ever invoked with a different working
    // directory; not expected given how it's built today, but worth
    // knowing if this test ever starts failing with "no migrations found"
    // rather than an actual schema assertion failure.

    private Connection connection;

    @AfterEach
    void tearDown() throws Exception {
        if (connection != null) {
            connection.close();
        }
    }

    private Connection migrateFreshDatabase() {
        String dbName = "contract_test_" + UUID.randomUUID();
        String url = "jdbc:h2:mem:" + dbName + ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL";

        Flyway flyway = Flyway.configure()
                .dataSource(url, "sa", "")
                .locations(MIGRATIONS_LOCATION)
                .load();
        flyway.migrate();

        try {
            return DriverManager.getConnection(url, "sa", "");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to connect to freshly migrated test database", e);
        }
    }

    @Test
    void agentShouldEnforceADomainBlockedThroughTheRealMigratedSchema(@TempDir Path tempDir) throws Exception {
        connection = migrateFreshDatabase();

        // Simulates the web app's write path exactly:
        // DomainBlockingServiceImpl.blockDomain() does this same INSERT
        // (via JPA, but the resulting SQL is equivalent) against the real
        // blocked_domains table this test just created via the real V6
        // migration, not a hand-copied approximation of it.
        try (Statement statement = connection.createStatement()) {
            statement.execute(
                    "INSERT INTO blocked_domains (domain, blocked_at, is_active, reason) " +
                            "VALUES ('malicious.example.com', CURRENT_TIMESTAMP, TRUE, 'contract test')");
        }

        Path hostsFile = tempDir.resolve("hosts");
        Files.writeString(hostsFile, "127.0.0.1 localhost\n");

        Properties props = new Properties();
        AgentConfig config = AgentConfig.fromProperties(props);
        HostsFileWriter hostsFileWriter = new HostsFileWriter(hostsFile.toString());
        DnsmasqWriter dnsmasqWriter = new DnsmasqWriter(tempDir.resolve("dnsmasq.conf").toString(), () -> {
        });
        DomainSyncTask task = new DomainSyncTask(config, hostsFileWriter, dnsmasqWriter, new AgentStatusReporter());

        task.runOnce(connection);

        List<String> hostsLines = Files.readAllLines(hostsFile);
        assertTrue(hostsLines.contains("127.0.0.1 malicious.example.com # ANTIVIRUS_BLOCKED_DOMAIN"),
                "agent should have enforced the domain inserted through the real migrated schema");

        try (Statement statement = connection.createStatement();
                ResultSet rs = statement.executeQuery("SELECT * FROM agent_status WHERE id = 1")) {
            assertTrue(rs.next(), "V5's seeded singleton row should exist");
            assertTrue(rs.getBoolean("hosts_file_writable"));
            assertEquals(null, rs.getString("last_sync_error"));
        }
    }

    @Test
    void agentShouldStopEnforcingADomainRemovedThroughTheRealMigratedSchema(@TempDir Path tempDir) throws Exception {
        connection = migrateFreshDatabase();

        try (Statement statement = connection.createStatement()) {
            statement.execute(
                    "INSERT INTO blocked_domains (domain, blocked_at, is_active) " +
                            "VALUES ('malicious.example.com', CURRENT_TIMESTAMP, TRUE)");
        }

        Path hostsFile = tempDir.resolve("hosts");
        Files.writeString(hostsFile, "127.0.0.1 localhost\n");
        AgentConfig config = AgentConfig.fromProperties(new Properties());
        HostsFileWriter hostsFileWriter = new HostsFileWriter(hostsFile.toString());
        DnsmasqWriter dnsmasqWriter = new DnsmasqWriter(tempDir.resolve("dnsmasq.conf").toString(), () -> {
        });
        DomainSyncTask task = new DomainSyncTask(config, hostsFileWriter, dnsmasqWriter, new AgentStatusReporter());

        task.runOnce(connection);
        assertTrue(Files.readAllLines(hostsFile).stream().anyMatch(l -> l.contains("malicious.example.com")));

        // Simulates DomainBlockingServiceImpl.unblockDomain(), a DELETE,
        // not a soft-delete (see that class's own doc comment on why).
        try (Statement statement = connection.createStatement()) {
            statement.execute("DELETE FROM blocked_domains WHERE domain = 'malicious.example.com'");
        }
        task.runOnce(connection);

        assertTrue(Files.readAllLines(hostsFile).stream().noneMatch(l -> l.contains("malicious.example.com")),
                "agent should remove enforcement once the web app's row is gone");
    }
}
