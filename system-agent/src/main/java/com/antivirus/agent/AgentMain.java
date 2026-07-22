package com.antivirus.agent;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Entry point for the standalone system-agent process. No Spring context,
 * no HTTP listener, one scheduled thread running {@link DomainSyncTask}
 * on a fixed interval, that's the entire process. See
 * docs/plans/h1-privilege-split-plan.md for the design this implements
 * and the systemd unit that runs it in production.
 */
public final class AgentMain {

    private static final Logger LOGGER = Logger.getLogger(AgentMain.class.getName());

    private AgentMain() {
    }

    public static void main(String[] args) throws Exception {
        AgentConfig config = AgentConfig.load();

        HostsFileWriter hostsFileWriter = new HostsFileWriter(config.getHostsFilePath());
        DnsmasqWriter dnsmasqWriter = new DnsmasqWriter(config.getDnsmasqConfPath());
        AgentStatusReporter statusReporter = new AgentStatusReporter();
        DomainSyncTask syncTask = new DomainSyncTask(config, hostsFileWriter, dnsmasqWriter, statusReporter);

        int pollIntervalSeconds = config.getPollIntervalSeconds();
        LOGGER.info(() -> "system-agent starting, poll interval " + pollIntervalSeconds + "s, "
                + "dns blocking " + (config.isDnsBlockingEnabled() ? "enabled" : "disabled"));

        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "domain-sync");
            thread.setDaemon(false);
            return thread;
        });

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            LOGGER.info("system-agent shutting down");
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(10, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }, "shutdown-hook"));

        // scheduleAtFixedRate rather than scheduleWithFixedDelay: cycles
        // are expected to be fast (one query, at most two small file
        // writes), fixed-rate keeps the polling interval predictable
        // instead of drifting by however long each cycle happens to take.
        scheduler.scheduleAtFixedRate(() -> {
            try {
                syncTask.runOnce();
            } catch (Exception e) {
                // DomainSyncTask.runOnce() already catches everything it
                // reasonably can; this is a last-resort backstop so an
                // unexpected exception can never silently kill the
                // scheduled task and leave the agent running but doing
                // nothing, with no further log output to explain why.
                LOGGER.log(Level.SEVERE, "Unexpected error in sync cycle", e);
            }
        }, 0, pollIntervalSeconds, TimeUnit.SECONDS);
    }
}
