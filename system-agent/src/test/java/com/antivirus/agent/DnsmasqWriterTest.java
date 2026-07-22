package com.antivirus.agent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DnsmasqWriterTest {

    @Test
    void write_ShouldWriteOneAddressLinePerDomain(@TempDir Path tempDir) throws Exception {
        Path confPath = tempDir.resolve("antivirus-blocked.conf");
        AtomicInteger reloadCount = new AtomicInteger();
        DnsmasqWriter writer = new DnsmasqWriter(confPath.toString(), reloadCount::incrementAndGet);

        writer.write(List.of("malicious.example.com", "evil.example.org"));

        String content = Files.readString(confPath);
        assertEquals("address=/malicious.example.com/0.0.0.0\naddress=/evil.example.org/0.0.0.0\n", content);
        assertEquals(1, reloadCount.get(), "reload should be invoked exactly once per write");
    }

    @Test
    void write_EmptyDomainList_ShouldWriteEmptyFile(@TempDir Path tempDir) throws Exception {
        Path confPath = tempDir.resolve("antivirus-blocked.conf");
        Files.writeString(confPath, "address=/old.example.com/0.0.0.0\n");
        DnsmasqWriter writer = new DnsmasqWriter(confPath.toString(), () -> {
        });

        writer.write(List.of());

        assertEquals("", Files.readString(confPath));
    }

    @Test
    void write_ShouldPropagateReloadFailureAsIOException(@TempDir Path tempDir) {
        Path confPath = tempDir.resolve("antivirus-blocked.conf");
        DnsmasqWriter writer = new DnsmasqWriter(confPath.toString(), () -> {
            throw new IOException("systemctl reload dnsmasq exited with status 1");
        });

        assertThrows(IOException.class, () -> writer.write(List.of("example.com")));
    }

    @Test
    void isWritable_ShouldReturnTrueWhenParentDirectoryIsWritableAndFileDoesNotExistYet(@TempDir Path tempDir) {
        Path confPath = tempDir.resolve("antivirus-blocked.conf");
        DnsmasqWriter writer = new DnsmasqWriter(confPath.toString(), () -> {
        });
        assertTrue(writer.isWritable());
    }

    @Test
    void isWritable_ShouldReturnFalseWhenParentDirectoryDoesNotExist() {
        DnsmasqWriter writer = new DnsmasqWriter("/definitely/does/not/exist/antivirus-blocked.conf", () -> {
        });
        assertFalse(writer.isWritable());
    }
}
