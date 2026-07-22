package com.antivirus.agent;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Writes the active blocked-domain list into the system hosts file.
 *
 * <p>Extracted from the web app's {@code DomainBlockingServiceImpl}
 * (see docs/plans/h1-privilege-split-plan.md section 4.3), same marker
 * convention ({@code # ANTIVIRUS_BLOCKED_DOMAIN}) and same
 * backup-before-write / restore-on-failure behavior, so a hosts file this
 * writer touches is indistinguishable from one the old web-app code
 * touched. Only the privileged identity that's allowed to run this code
 * has changed, not what it does to the file.
 */
public final class HostsFileWriter {

    private static final String MARKER = "# ANTIVIRUS_BLOCKED_DOMAIN";

    private final Path hostsPath;
    private final Path backupPath;

    public HostsFileWriter(String hostsFilePath) {
        this.hostsPath = Paths.get(hostsFilePath);
        this.backupPath = Paths.get(hostsFilePath + ".backup");
    }

    /** Best-effort writability probe, mirrors the old service's own check. */
    public boolean isWritable() {
        try {
            return Files.exists(hostsPath) && Files.isWritable(hostsPath);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Rewrites the hosts file: keeps every line that isn't one of ours,
     * appends one {@code 127.0.0.1 <domain> # ANTIVIRUS_BLOCKED_DOMAIN}
     * line per active domain. Backs up the file first; on write failure,
     * restores from that backup rather than leaving a partially-written
     * file in place.
     */
    public void write(List<String> activeDomains) throws IOException {
        List<String> existingLines = Files.readAllLines(hostsPath);

        List<String> systemEntries = existingLines.stream()
                .filter(line -> !line.contains(MARKER))
                .collect(Collectors.toList());

        List<String> blockedEntries = activeDomains.stream()
                .map(domain -> "127.0.0.1 " + domain + " " + MARKER)
                .collect(Collectors.toList());

        systemEntries.addAll(blockedEntries);

        try {
            Files.copy(hostsPath, backupPath, StandardCopyOption.REPLACE_EXISTING);
            Files.write(hostsPath, systemEntries);
        } catch (AccessDeniedException e) {
            throw e;
        } catch (IOException e) {
            try {
                if (Files.exists(backupPath)) {
                    Files.copy(backupPath, hostsPath, StandardCopyOption.REPLACE_EXISTING);
                }
            } catch (IOException restoreEx) {
                // Original write failure is the one worth surfacing;
                // a failed restore attempt is logged by the caller via
                // the original exception's own message/stack, not
                // swallowed silently, but doesn't replace it here.
                e.addSuppressed(restoreEx);
            }
            throw e;
        }
    }
}
