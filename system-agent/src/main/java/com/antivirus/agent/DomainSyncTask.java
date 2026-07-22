package com.antivirus.agent;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * One poll cycle: read the current active domain list from the database,
 * write it to whichever of hosts-file/dnsmasq are configured and
 * writable, only when something actually changed since the last cycle,
 * and report the outcome via {@link AgentStatusReporter}.
 *
 * <p>Not thread-safe by design, {@link AgentMain} runs this from a single
 * scheduled thread, one cycle at a time, never overlapping.
 */
public final class DomainSyncTask {

    private static final Logger LOGGER = Logger.getLogger(DomainSyncTask.class.getName());
    private static final String SELECT_ACTIVE_DOMAINS_SQL =
            "SELECT domain FROM blocked_domains WHERE is_active = true";

    private final AgentConfig config;
    private final HostsFileWriter hostsFileWriter;
    private final DnsmasqWriter dnsmasqWriter;
    private final AgentStatusReporter statusReporter;

    /**
     * The domain set actually applied to disk as of the last successful
     * write. Null before the first cycle, so the first cycle always
     * writes even if the domain list happens to be empty (an empty hosts
     * file section is itself a meaningful state to apply once, not
     * something to skip just because "nothing changed" from an
     * uninitialized baseline).
     */
    private Set<String> lastAppliedDomains;

    public DomainSyncTask(AgentConfig config, HostsFileWriter hostsFileWriter,
            DnsmasqWriter dnsmasqWriter, AgentStatusReporter statusReporter) {
        this.config = config;
        this.hostsFileWriter = hostsFileWriter;
        this.dnsmasqWriter = dnsmasqWriter;
        this.statusReporter = statusReporter;
    }

    /** Runs exactly one poll-diff-write-report cycle. Never throws, logs and moves on instead. */
    public void runOnce() {
        try (Connection connection = openConnection()) {
            runOnce(connection);
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Sync cycle failed to connect to the database", e);
            // Can't report sync outcome without a connection at all; best
            // effort is simply to try again next cycle. No heartbeat
            // update either in this specific failure mode, a stale
            // heartbeat here correctly signals "agent can't reach the DB"
            // rather than falsely looking healthy.
        }
    }

    /** Package-private overload for tests to inject a connection directly (e.g. an in-memory H2). */
    void runOnce(Connection connection) {
        List<String> activeDomains;
        try {
            activeDomains = queryActiveDomains(connection);
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Failed to query blocked_domains", e);
            reportHeartbeatOnlyQuietly(connection);
            return;
        }

        Set<String> currentDomains = Set.copyOf(activeDomains);
        boolean domainsChanged = lastAppliedDomains == null || !lastAppliedDomains.equals(currentDomains);

        boolean hostsWritable = hostsFileWriter.isWritable();
        boolean dnsEnabled = config.isDnsBlockingEnabled();
        boolean dnsWritable = dnsEnabled && dnsmasqWriter.isWritable();

        String syncError = null;
        boolean appliedSuccessfully = true;

        if (domainsChanged) {
            if (hostsWritable) {
                try {
                    hostsFileWriter.write(activeDomains);
                    LOGGER.info(() -> "hosts file updated with " + activeDomains.size() + " blocked domain(s)");
                } catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Failed to write hosts file", e);
                    hostsWritable = false;
                    syncError = "hosts file write failed: " + e.getMessage();
                    appliedSuccessfully = false;
                }
            }

            if (dnsEnabled && dnsWritable) {
                try {
                    dnsmasqWriter.write(activeDomains);
                    LOGGER.info(() -> "dnsmasq config updated with " + activeDomains.size() + " blocked domain(s)");
                } catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Failed to write dnsmasq config", e);
                    dnsWritable = false;
                    syncError = (syncError == null ? "" : syncError + "; ") + "dnsmasq write failed: " + e.getMessage();
                    appliedSuccessfully = false;
                }
            }

            if (appliedSuccessfully) {
                lastAppliedDomains = currentDomains;
            }
            // On partial/full failure, lastAppliedDomains deliberately
            // stays as it was, so the next cycle sees domainsChanged=true
            // again and retries, rather than silently giving up on a
            // change that never actually made it to disk.
        }

        try {
            statusReporter.reportSync(connection, hostsWritable, dnsWritable, syncError);
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Failed to report sync status", e);
        }
    }

    private List<String> queryActiveDomains(Connection connection) throws SQLException {
        List<String> domains = new ArrayList<>();
        try (Statement statement = connection.createStatement();
                ResultSet resultSet = statement.executeQuery(SELECT_ACTIVE_DOMAINS_SQL)) {
            while (resultSet.next()) {
                domains.add(resultSet.getString("domain"));
            }
        }
        return domains;
    }

    private void reportHeartbeatOnlyQuietly(Connection connection) {
        try {
            statusReporter.reportHeartbeatOnly(connection);
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Failed to report heartbeat", e);
        }
    }

    private Connection openConnection() throws SQLException {
        return DriverManager.getConnection(config.getDbUrl(), config.getDbUser(), config.getDbPassword());
    }
}
