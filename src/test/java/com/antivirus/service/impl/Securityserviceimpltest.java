package com.antivirus.service.impl;

import com.antivirus.model.ScanResult;
import com.antivirus.repository.ScanResultRepository;
import com.antivirus.service.LogService;
import com.antivirus.service.SystemMonitorService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityServiceImplTest {

    @Mock
    private ScanResultRepository scanResultRepository;

    @Mock
    private SystemMonitorService systemMonitorService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private LogService logService;

    @Mock
    private SecurityContext securityContext;

    @Mock
    private Authentication authentication;

    @InjectMocks
    private SecurityServiceImpl securityService;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.setContext(securityContext);
        lenient().when(securityContext.getAuthentication()).thenReturn(authentication);
        lenient().when(authentication.isAuthenticated()).thenReturn(true);
        lenient().when(authentication.getName()).thenReturn("testuser");
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        deleteRecursively(new File("quarantine"));
    }

    private void deleteRecursively(File file) {
        if (file == null || !file.exists()) {
            return;
        }
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                deleteRecursively(child);
            }
        }
        file.delete();
    }

    // ── scanFile: clean file ────────────────────────────────────────

    @Test
    void scanFile_ShouldReturnCleanVerdictForSafeFile() throws IOException {
        File testFile = tempDir.resolve("safe.txt").toFile();
        Files.writeString(testFile.toPath(), "This is a safe file with ordinary text content.");

        ScanResult result = securityService.scanFile(testFile);

        assertEquals("CLEAN", result.getVerdict());
        assertFalse(result.isInfected());
        assertEquals(0, result.getRiskScore());
        assertEquals("CLEAN", result.getThreatType());
        assertEquals("testuser", result.getOwnerUsername());
        verify(scanResultRepository, times(1)).save(any(ScanResult.class));
        verify(logService, times(1)).logScanResult(any(ScanResult.class));
    }

    // ── scanFile: known-hash match ──────────────────────────────────

    @Test
    void scanFile_ShouldReturnMaliciousForKnownHashMatch() throws IOException {
        // SHA-256 of an empty file is a hardcoded entry in KNOWN_MALWARE_SIGNATURES
        File emptyFile = tempDir.resolve("empty.bin").toFile();
        Files.write(emptyFile.toPath(), new byte[0]);

        ScanResult result = securityService.scanFile(emptyFile);

        assertEquals("MALICIOUS", result.getVerdict());
        assertTrue(result.isInfected());
        assertEquals(100, result.getRiskScore());
        assertEquals("VIRUS", result.getThreatType());
        assertTrue(result.getDetectionSignals().contains("KNOWN_HASH_MATCH"));
        assertEquals("REPORTED", result.getActionTaken());
    }

    // ── scanFile: extension masquerade ──────────────────────────────

    @Test
    void scanFile_ShouldReturnMaliciousForExtensionMasquerade() throws IOException {
        // MZ header (PE executable) disguised behind a non-suspicious .pdf extension
        File disguisedFile = tempDir.resolve("invoice.pdf").toFile();
        byte[] content = new byte[] { 0x4D, 0x5A, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04 };
        Files.write(disguisedFile.toPath(), content);

        ScanResult result = securityService.scanFile(disguisedFile);

        assertEquals("MALICIOUS", result.getVerdict());
        assertTrue(result.isInfected());
        assertTrue(result.getRiskScore() >= 60);
        assertTrue(result.getDetectionSignals().contains("EXTENSION_MASQUERADE"));
    }

    // ── scanFile: ransomware extension + note text combine ─────────

    @Test
    void scanFile_ShouldReturnMaliciousForRansomwareExtensionAndNoteText() throws IOException {
        File ransomwareFile = tempDir.resolve("payload.locked").toFile();
        Files.writeString(ransomwareFile.toPath(),
                "Your files have been encrypted. Send payment to our BTC wallet to recover them.");

        ScanResult result = securityService.scanFile(ransomwareFile);

        assertEquals("MALICIOUS", result.getVerdict());
        assertTrue(result.isInfected());
        assertEquals("RANSOMWARE", result.getThreatType());
        assertTrue(result.getDetectionSignals().contains("RANSOMWARE_EXTENSION"));
        assertTrue(result.getDetectionSignals().contains("RANSOMWARE_NOTE_TEXT"));
    }

    @Test
    void scanFile_ShouldReturnErrorForNonExistentFile() {
        File missing = new File(tempDir.toFile(), "does-not-exist.txt");

        ScanResult result = securityService.scanFile(missing);

        assertEquals("ERROR", result.getThreatType());
        assertEquals("File does not exist", result.getThreatDetails());
        verify(scanResultRepository, times(1)).save(any(ScanResult.class));
    }

    // ── detectMalware / detectTrojan / detectRansomware ─────────────

    @Test
    void detectMalware_ShouldReturnFalseForSafeFile() throws IOException {
        File testFile = tempDir.resolve("safe.txt").toFile();
        Files.writeString(testFile.toPath(), "Nothing suspicious here.");

        assertFalse(securityService.detectMalware(testFile));
    }

    @Test
    void detectRansomware_ShouldReturnTrueForRansomwareExtensionAndNoteText() throws IOException {
        File ransomwareFile = tempDir.resolve("payload.locked").toFile();
        Files.writeString(ransomwareFile.toPath(),
                "Your important files have been encrypted, contact us via .onion for the decrypt key.");

        assertTrue(securityService.detectRansomware(ransomwareFile));
    }

    @Test
    void detectRansomware_ShouldReturnFalseForSafeFile() throws IOException {
        File testFile = tempDir.resolve("safe.txt").toFile();
        Files.writeString(testFile.toPath(), "Nothing suspicious here.");

        assertFalse(securityService.detectRansomware(testFile));
    }

    @Test
    void detectTrojan_ShouldReturnFalseForSafeFile() throws IOException {
        File testFile = tempDir.resolve("safe.txt").toFile();
        Files.writeString(testFile.toPath(), "Nothing suspicious here.");

        assertFalse(securityService.detectTrojan(testFile));
    }

    // ── quarantine / delete ──────────────────────────────────────────

    @Test
    void quarantineScanResult_ShouldMoveFileAndMarkQuarantined() throws IOException {
        File infectedFile = tempDir.resolve("infected.exe").toFile();
        Files.writeString(infectedFile.toPath(), "malicious content");

        ScanResult infectedResult = new ScanResult();
        infectedResult.setId(1L);
        infectedResult.setFilePath(infectedFile.getAbsolutePath());
        infectedResult.setInfected(true);
        infectedResult.setOwnerUsername("testuser");
        when(scanResultRepository.findById(1L)).thenReturn(Optional.of(infectedResult));

        securityService.quarantineScanResult(1L);

        assertEquals("QUARANTINED", infectedResult.getActionTaken());
        assertFalse(infectedFile.exists());
        verify(scanResultRepository, atLeastOnce()).save(infectedResult);
    }

    @Test
    void deleteScanResult_ShouldDeleteFileAndMarkDeleted() throws IOException {
        File infectedFile = tempDir.resolve("infected2.exe").toFile();
        Files.writeString(infectedFile.toPath(), "malicious content");

        ScanResult infectedResult = new ScanResult();
        infectedResult.setId(2L);
        infectedResult.setFilePath(infectedFile.getAbsolutePath());
        infectedResult.setInfected(true);
        infectedResult.setOwnerUsername("testuser");
        when(scanResultRepository.findById(2L)).thenReturn(Optional.of(infectedResult));

        securityService.deleteScanResult(2L);

        assertEquals("DELETED", infectedResult.getActionTaken());
        assertFalse(infectedFile.exists());
        verify(scanResultRepository, atLeastOnce()).save(infectedResult);
    }

    @Test
    void quarantineScanResult_ShouldThrowWhenScanResultNotInfected() {
        ScanResult cleanResult = new ScanResult();
        cleanResult.setId(3L);
        cleanResult.setFilePath("/tmp/whatever.txt");
        cleanResult.setInfected(false);
        when(scanResultRepository.findById(3L)).thenReturn(Optional.of(cleanResult));

        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> securityService.quarantineScanResult(3L));
    }

    @Test
    void deleteScanResult_ShouldThrowWhenScanResultDoesNotExist() {
        when(scanResultRepository.findById(99L)).thenReturn(Optional.empty());

        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> securityService.deleteScanResult(99L));
    }
}
