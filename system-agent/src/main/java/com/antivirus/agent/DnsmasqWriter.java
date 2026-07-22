package com.antivirus.agent;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Writes the active blocked-domain list into a dnsmasq config file and
 * reloads dnsmasq. Extracted from the web app's
 * {@code DnsDomainBlockingService} (see
 * docs/plans/h1-privilege-split-plan.md section 4.3).
 *
 * <p>Unlike the old web-app version, there is no separate
 * {@code dnsBlockingEnabled} flag check inside this class, the caller
 * ({@link DomainSyncTask}, driven by {@link AgentConfig#isDnsBlockingEnabled()})
 * decides whether to call this at all. That's the same "explicit opt-in,
 * not on by accident" property the H2 fix established, just enforced one
 * layer up instead of duplicated in both places.
 */
public final class DnsmasqWriter {

    /** Package-private seam so tests can substitute a no-op instead of a real systemctl call. */
    @FunctionalInterface
    interface ReloadCommand {
        void reload() throws IOException, InterruptedException;
    }

    private final Path dnsmasqConfPath;
    private final ReloadCommand reloadCommand;

    public DnsmasqWriter(String dnsmasqConfPath) {
        this(dnsmasqConfPath, DnsmasqWriter::reloadDnsmasqViaSystemctl);
    }

    /** Test-only constructor: substitute the reload step without touching the real system. */
    DnsmasqWriter(String dnsmasqConfPath, ReloadCommand reloadCommand) {
        this.dnsmasqConfPath = Paths.get(dnsmasqConfPath);
        this.reloadCommand = reloadCommand;
    }

    private static void reloadDnsmasqViaSystemctl() throws IOException, InterruptedException {
        int exitCode = new ProcessBuilder("systemctl", "reload", "dnsmasq").start().waitFor();
        if (exitCode != 0) {
            throw new IOException("systemctl reload dnsmasq exited with status " + exitCode);
        }
    }

    /** Best-effort writability probe: existing file writable, or parent dir writable if it doesn't exist yet. */
    public boolean isWritable() {
        try {
            if (!Files.exists(dnsmasqConfPath)) {
                Path parentDir = dnsmasqConfPath.getParent();
                return parentDir != null && Files.isWritable(parentDir);
            }
            return Files.isWritable(dnsmasqConfPath);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Rewrites the dnsmasq config with one {@code address=/domain/0.0.0.0}
     * line per active domain, then reloads dnsmasq via
     * {@code systemctl reload dnsmasq}. An empty {@code activeDomains}
     * list writes an empty file, effectively clearing all blocks, this
     * replaces the old service's separate {@code restoreDnsConfig()}
     * method, one code path instead of two that both need to stay in sync.
     */
    public void write(List<String> activeDomains) throws IOException, InterruptedException {
        String content = activeDomains.stream()
                .map(domain -> "address=/" + domain + "/0.0.0.0")
                .collect(Collectors.joining("\n"));
        if (!content.isEmpty()) {
            content += "\n";
        }

        Files.writeString(dnsmasqConfPath, content,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        reloadCommand.reload();
    }
}
