package com.antivirus.agent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HostsFileWriterTest {

    @Test
    void write_ShouldAppendMarkedEntriesAndPreserveExistingLines(@TempDir Path tempDir) throws IOException {
        Path hostsFile = tempDir.resolve("hosts");
        Files.writeString(hostsFile, "127.0.0.1 localhost\n::1 localhost\n");

        HostsFileWriter writer = new HostsFileWriter(hostsFile.toString());
        writer.write(List.of("malicious.example.com", "evil.example.org"));

        List<String> lines = Files.readAllLines(hostsFile);
        assertTrue(lines.contains("127.0.0.1 localhost"));
        assertTrue(lines.contains("::1 localhost"));
        assertTrue(lines.contains("127.0.0.1 malicious.example.com # ANTIVIRUS_BLOCKED_DOMAIN"));
        assertTrue(lines.contains("127.0.0.1 evil.example.org # ANTIVIRUS_BLOCKED_DOMAIN"));
    }

    @Test
    void write_ShouldReplacePreviouslyWrittenEntriesRatherThanDuplicating(@TempDir Path tempDir) throws IOException {
        Path hostsFile = tempDir.resolve("hosts");
        Files.writeString(hostsFile,
                "127.0.0.1 localhost\n127.0.0.1 old.example.com # ANTIVIRUS_BLOCKED_DOMAIN\n");

        HostsFileWriter writer = new HostsFileWriter(hostsFile.toString());
        writer.write(List.of("new.example.com"));

        List<String> lines = Files.readAllLines(hostsFile);
        assertFalse(lines.contains("127.0.0.1 old.example.com # ANTIVIRUS_BLOCKED_DOMAIN"),
                "stale marked entry should have been removed, not left alongside the new one");
        assertTrue(lines.contains("127.0.0.1 new.example.com # ANTIVIRUS_BLOCKED_DOMAIN"));
        assertTrue(lines.contains("127.0.0.1 localhost"));
    }

    @Test
    void write_ShouldCreateBackupBeforeWriting(@TempDir Path tempDir) throws IOException {
        Path hostsFile = tempDir.resolve("hosts");
        String originalContent = "127.0.0.1 localhost\n";
        Files.writeString(hostsFile, originalContent);

        HostsFileWriter writer = new HostsFileWriter(hostsFile.toString());
        writer.write(List.of("malicious.example.com"));

        Path backup = tempDir.resolve("hosts.backup");
        assertTrue(Files.exists(backup), "backup file should have been created");
        assertEquals(originalContent, Files.readString(backup),
                "backup should hold the pre-write content, not the post-write content");
    }

    @Test
    void write_EmptyDomainList_ShouldClearPreviouslyBlockedEntries(@TempDir Path tempDir) throws IOException {
        Path hostsFile = tempDir.resolve("hosts");
        Files.writeString(hostsFile,
                "127.0.0.1 localhost\n127.0.0.1 old.example.com # ANTIVIRUS_BLOCKED_DOMAIN\n");

        HostsFileWriter writer = new HostsFileWriter(hostsFile.toString());
        writer.write(List.of());

        List<String> lines = Files.readAllLines(hostsFile);
        assertFalse(lines.stream().anyMatch(l -> l.contains("ANTIVIRUS_BLOCKED_DOMAIN")));
        assertTrue(lines.contains("127.0.0.1 localhost"));
    }

    @Test
    void isWritable_ShouldReturnFalseForNonExistentFile(@TempDir Path tempDir) {
        Path missing = tempDir.resolve("does-not-exist");
        HostsFileWriter writer = new HostsFileWriter(missing.toString());
        assertFalse(writer.isWritable());
    }

    @Test
    void isWritable_ShouldReturnTrueForWritableExistingFile(@TempDir Path tempDir) throws IOException {
        Path hostsFile = tempDir.resolve("hosts");
        Files.writeString(hostsFile, "127.0.0.1 localhost\n");
        HostsFileWriter writer = new HostsFileWriter(hostsFile.toString());
        assertTrue(writer.isWritable());
    }
}
