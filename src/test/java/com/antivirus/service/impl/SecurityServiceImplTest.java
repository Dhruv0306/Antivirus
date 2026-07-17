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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
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
    private ThreatIntelSignatureService threatIntelSignatureService;

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
        securityService.shutdownScanExecutors();
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
        File sampleFile = tempDir.resolve("known-hash.bin").toFile();
        Files.writeString(sampleFile.toPath(), "known-hash-match-fixture");

        // Real hash lookup logic lives in ThreatIntelSignatureService and is
        // covered by its own test class; here we only need scanFile() to
        // honor whatever that service reports.
        when(threatIntelSignatureService.isKnownMalicious(anyString())).thenReturn(true);

        ScanResult result = securityService.scanFile(sampleFile);

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

    // ── C2 fix: admin can act on infected results owned by other users ──
    //
    // /api/antivirus/quarantine and /delete are ADMIN-only routes (see
    // SecurityConfig). Before this fix, loadInfectedScanResult()'s ownership
    // check applied unconditionally, so an admin could only quarantine or
    // delete infected results they had personally scanned, and got a 403 on
    // everyone else's, defeating the reason the endpoint is admin-gated.

    @Test
    void quarantineScanResult_AdminCanQuarantineAnotherUsersInfectedFile() throws IOException {
        File infectedFile = tempDir.resolve("infected-other-user.exe").toFile();
        Files.writeString(infectedFile.toPath(), "malicious content");

        ScanResult infectedResult = new ScanResult();
        infectedResult.setId(4L);
        infectedResult.setFilePath(infectedFile.getAbsolutePath());
        infectedResult.setInfected(true);
        infectedResult.setOwnerUsername("alice"); // owned by a different user
        when(scanResultRepository.findById(4L)).thenReturn(Optional.of(infectedResult));

        // Current caller is "testuser" (see setUp), acting with ROLE_ADMIN
        doReturn(List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")))
                .when(authentication).getAuthorities();

        securityService.quarantineScanResult(4L);

        assertEquals("QUARANTINED", infectedResult.getActionTaken());
        assertFalse(infectedFile.exists());
        verify(scanResultRepository, atLeastOnce()).save(infectedResult);
    }

    @Test
    void getCurrentSystemScanResults_ShouldReturnDefensiveCopyOfSessionResults() throws Exception {
        ScanResult sessionResult = new ScanResult();
        sessionResult.setFilePath("C:\\scan\\session-file.exe");
        sessionResult.setFileName("session-file.exe");
        sessionResult.setScanType("SYSTEM");
        sessionResult.setThreatType("CLEAN");
        sessionResult.setInfected(false);

        java.util.List<ScanResult> liveResults = currentSystemScanResults();
        liveResults.add(sessionResult);

        java.util.List<ScanResult> snapshot = securityService.getCurrentSystemScanResults();

        assertEquals(1, snapshot.size());
        assertEquals("session-file.exe", snapshot.get(0).getFileName());

        snapshot.clear();

        assertEquals(1, currentSystemScanResults().size());
        assertEquals(1, securityService.getCurrentSystemScanResults().size());
    }

    @SuppressWarnings("unchecked")
    private java.util.List<ScanResult> currentSystemScanResults() throws Exception {
        java.lang.reflect.Field field = SecurityServiceImpl.class.getDeclaredField("currentSystemScanResults");
        field.setAccessible(true);
        return (java.util.List<ScanResult>) field.get(securityService);
    }

    @Test
    void quarantineScanResult_NonAdminCannotQuarantineAnotherUsersInfectedFile() {
        ScanResult infectedResult = new ScanResult();
        infectedResult.setId(5L);
        infectedResult.setFilePath("/tmp/other-user-file.exe");
        infectedResult.setInfected(true);
        infectedResult.setOwnerUsername("alice"); // owned by a different user
        when(scanResultRepository.findById(5L)).thenReturn(Optional.of(infectedResult));

        // Current caller is "testuser" (see setUp) with no admin authority
        doReturn(List.of()).when(authentication).getAuthorities();

        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> securityService.quarantineScanResult(5L));
    }

    // ── async directory scan job ──────────────────────────────────────

    @Test
    void directoryScanJob_ShouldCompleteAsynchronouslyAndReportResults() throws Exception {
        Path jobDir = Files.createDirectory(tempDir.resolve("job-input"));
        Files.writeString(jobDir.resolve("clean.txt"), "Nothing suspicious here.");
        Files.writeString(jobDir.resolve("payload.locked"),
                "Your files have been encrypted. Send payment to our BTC wallet to recover them.");

        String jobId = securityService.startDirectoryScanJob(jobDir, "job-input", 2);
        assertNotNull(jobId);

        Map<String, Object> status = pollDirectoryScanJobUntilComplete(jobId);

        assertFalse((boolean) status.get("isRunning"));
        assertFalse((boolean) status.get("failed"));
        assertEquals(2, (int) status.get("totalFiles"));
        assertEquals(2, (int) status.get("processedFiles"));
        assertEquals(1, (int) status.get("infectedFiles"));
        assertEquals(1, (int) status.get("cleanFiles"));
        assertEquals(0, (int) status.get("skippedFiles"));

        @SuppressWarnings("unchecked")
        List<ScanResult> results = (List<ScanResult>) status.get("results");
        assertEquals(2, results.size());

        // The job's temp directory is cleaned up once scanning finishes
        assertFalse(Files.exists(jobDir));
    }

    @Test
    void getDirectoryScanJobStatus_ShouldThrowNotFoundForUnknownJobId() {
        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> securityService.getDirectoryScanJobStatus("does-not-exist"));
    }

    @Test
    void getDirectoryScanJobStatus_ShouldThrowForbiddenForDifferentOwner() throws Exception {
        Path jobDir = Files.createDirectory(tempDir.resolve("job-owner-check"));
        Files.writeString(jobDir.resolve("clean.txt"), "Nothing suspicious here.");

        String jobId = securityService.startDirectoryScanJob(jobDir, "job-owner-check", 1);
        // Let the job fully finish (as "testuser") before switching the
        // mocked identity, so there's no race between the background
        // thread's last authentication.getName() read and this test
        // reassigning that same mock's stub.
        pollDirectoryScanJobUntilComplete(jobId);

        when(authentication.getName()).thenReturn("someoneelse");

        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> securityService.getDirectoryScanJobStatus(jobId));
    }

    private Map<String, Object> pollDirectoryScanJobUntilComplete(String jobId) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 5000;
        do {
            Map<String, Object> status = securityService.getDirectoryScanJobStatus(jobId);
            if (Boolean.FALSE.equals(status.get("isRunning"))) {
                return status;
            }
            Thread.sleep(50);
        } while (System.currentTimeMillis() < deadline);
        throw new AssertionError("Directory scan job " + jobId + " did not complete within timeout");
    }

    @Test
    void getCurrentSystemScanResultsReturnsDefensiveCopy() throws Exception {
        SecurityServiceImpl service = new SecurityServiceImpl();

        com.antivirus.model.ScanResult result = new com.antivirus.model.ScanResult();
        result.setFilePath("C:\\scan\\sample.exe");
        result.setFileName("sample.exe");
        result.setScanType("SYSTEM");
        result.setThreatType("CLEAN");
        result.setInfected(false);

        currentSystemScanResults(service).add(result);

        java.util.List<com.antivirus.model.ScanResult> snapshot = service.getCurrentSystemScanResults();

        org.junit.jupiter.api.Assertions.assertEquals(1, snapshot.size());
        org.junit.jupiter.api.Assertions.assertEquals("sample.exe", snapshot.get(0).getFileName());

        snapshot.clear();

        org.junit.jupiter.api.Assertions.assertEquals(1, currentSystemScanResults(service).size());
        org.junit.jupiter.api.Assertions.assertEquals(1, service.getCurrentSystemScanResults().size());
    }

    @SuppressWarnings("unchecked")
    private static java.util.List<com.antivirus.model.ScanResult> currentSystemScanResults(SecurityServiceImpl service)
            throws Exception {
        java.lang.reflect.Field field = SecurityServiceImpl.class.getDeclaredField("currentSystemScanResults");
        field.setAccessible(true);
        return (java.util.List<com.antivirus.model.ScanResult>) field.get(service);
    }
}
