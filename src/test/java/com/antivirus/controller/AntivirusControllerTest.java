package com.antivirus.controller;

import com.antivirus.config.SecurityConfig;
import com.antivirus.dto.PagedResponse;
import com.antivirus.exception.MultipartUploadExceptionHandler;
import com.antivirus.model.ScanResult;
import com.antivirus.repository.ScanResultRepository;
import com.antivirus.service.LogService;
import com.antivirus.service.SecurityService;
import com.antivirus.service.SystemMonitorService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = AntivirusController.class)
@Import({SecurityConfig.class, MultipartUploadExceptionHandler.class})
@TestPropertySource(properties = "app.cors.allowed-origins=https://test.example.com")
class AntivirusControllerTest {

        @Autowired
        private MockMvc mockMvc;

        @MockitoBean
        private SecurityService securityService;

        @MockitoBean
        private SystemMonitorService systemMonitorService;

        @MockitoBean
        private ScanResultRepository scanResultRepository;

        @MockitoBean
        private LogService logService;

        // ── /scan/file ───────────────────────────────────────────────────

        @Test
        void scanFile_ShouldReturnScanResultForUserRole() throws Exception {
                MockMultipartFile file = new MockMultipartFile(
                                "file", "document.pdf", "application/pdf", "some content".getBytes());

                ScanResult cleanResult = new ScanResult();
                cleanResult.setVerdict("CLEAN");
                cleanResult.setInfected(false);
                when(securityService.scanFile(any())).thenReturn(cleanResult);

                mockMvc.perform(multipart("/api/antivirus/scan/file")
                                .file(file)
                                .with(csrf())
                                .with(user("testuser").roles("USER")))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.verdict").value("CLEAN"));
        }

        @Test
        void scanFile_ShouldReturnBadRequestForBlankFilename() throws Exception {
                MockMultipartFile file = new MockMultipartFile(
                                "file", "", "text/plain", "some content".getBytes());

                mockMvc.perform(multipart("/api/antivirus/scan/file")
                                .file(file)
                                .with(csrf())
                                .with(user("testuser").roles("USER")))
                                .andExpect(status().isBadRequest());
        }

        @Test
        void scanFile_ShouldReturnBadRequestForUnsupportedContentType() throws Exception {
                MockMultipartFile file = new MockMultipartFile(
                                "file", "archive.rar", "application/x-unknown", "some content".getBytes());

                mockMvc.perform(multipart("/api/antivirus/scan/file")
                                .file(file)
                                .with(csrf())
                                .with(user("testuser").roles("USER")))
                                .andExpect(status().isBadRequest());
        }

        @Test
        void scanFile_ShouldReturnForbiddenWithoutAuthentication() throws Exception {
                MockMultipartFile file = new MockMultipartFile(
                                "file", "document.pdf", "application/pdf", "some content".getBytes());

                mockMvc.perform(multipart("/api/antivirus/scan/file")
                                .file(file)
                                .with(csrf()))
                                .andExpect(status().is3xxRedirection());
        }

        // ── /history (ADMIN only) ────────────────────────────────────────

        @Test
        void getScanHistory_ShouldReturnForbiddenForUserRole() throws Exception {
                mockMvc.perform(get("/api/antivirus/history").with(user("testuser").roles("USER")))
                                .andExpect(status().isForbidden());
        }

        @Test
        void getScanHistory_ShouldReturnOkForAdminRole() throws Exception {
                ScanResult scanResult = new ScanResult();
                scanResult.setVerdict("CLEAN");
                PagedResponse<ScanResult> page = PagedResponse.from(
                                new PageImpl<>(List.of(scanResult), PageRequest.of(0, 10), 1));
                when(securityService.getScanHistory(0, 10)).thenReturn(page);

                mockMvc.perform(get("/api/antivirus/history").with(user("admin").roles("ADMIN")))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.content").isArray())
                                .andExpect(jsonPath("$.totalElements").value(1));
        }

        // ── /history/me (USER or ADMIN) ──────────────────────────────────

        @Test
        void getMyHistory_ShouldReturnOwnedHistoryForUserRole() throws Exception {
                ScanResult scanResult = new ScanResult();
                scanResult.setVerdict("CLEAN");
                when(scanResultRepository.findByOwnerUsernameOrderByScanDateTimeDesc(
                                org.mockito.ArgumentMatchers.eq("testuser"), any()))
                                .thenReturn(new PageImpl<>(List.of(scanResult)));

                mockMvc.perform(get("/api/antivirus/history/me").with(user("testuser").roles("USER")))
                                .andExpect(status().isOk());
        }

        // ── /scan/system (ADMIN only) ────────────────────────────────────

        @Test
        void performSystemScan_ShouldReturnAcceptedForAdminRole() throws Exception {
                mockMvc.perform(post("/api/antivirus/scan/system")
                                .with(csrf())
                                .with(user("admin").roles("ADMIN")))
                                .andExpect(status().isAccepted())
                                .andExpect(jsonPath("$.started").value(true));

                verify(securityService, times(1)).performSystemScan();
        }

        @Test
        void performSystemScan_ShouldReturnForbiddenForUserRole() throws Exception {
                // System scan has no USER-facing route on the frontend (wrapped in
                // AdminRoute), and this stays ADMIN-only via the /api/antivirus/**
                // catch-all in SecurityConfig.
                mockMvc.perform(post("/api/antivirus/scan/system")
                                .with(csrf())
                                .with(user("testuser").roles("USER")))
                                .andExpect(status().isForbidden());
        }

        @Test
        void getSystemScanStatus_ShouldReturnRunningStateAndFilesScanned() throws Exception {
                when(securityService.isSystemScanRunning()).thenReturn(true);
                when(securityService.getSystemScanFilesScanned()).thenReturn(42);

                mockMvc.perform(get("/api/antivirus/scan/system/status").with(user("admin").roles("ADMIN")))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.isRunning").value(true))
                                .andExpect(jsonPath("$.filesScanned").value(42));
        }

        // ── /scan/directory (USER + ADMIN) ───────────────────────────────

        @Test
        void scanDirectory_ShouldReturnAcceptedWithJobIdForUserRole() throws Exception {
                MockMultipartFile file = new MockMultipartFile(
                                "files", "notes.txt", "text/plain", "hello".getBytes());
                when(securityService.startDirectoryScanJob(any(), org.mockito.ArgumentMatchers.eq("my-folder"),
                                org.mockito.ArgumentMatchers.eq(1)))
                                .thenReturn("job-123");

                mockMvc.perform(multipart("/api/antivirus/scan/directory")
                                .file(file)
                                .param("directoryName", "my-folder")
                                .param("recursive", "true")
                                .with(csrf())
                                .with(user("testuser").roles("USER")))
                                .andExpect(status().isAccepted())
                                .andExpect(jsonPath("$.jobId").value("job-123"))
                                .andExpect(jsonPath("$.uploadedFiles").value(1));
        }

        @Test
        void scanDirectory_ShouldReturnBadRequestWhenNoFilesProvided() throws Exception {
                mockMvc.perform(multipart("/api/antivirus/scan/directory")
                                .param("directoryName", "empty-folder")
                                .with(csrf())
                                .with(user("testuser").roles("USER")))
                                .andExpect(status().isBadRequest());
        }

        // ── /scan/directory/status/{jobId} (USER + ADMIN) ────────────────
        //
        // Regression coverage for a real bug: this endpoint was added
        // alongside the async directory-scan job feature but the
        // SecurityConfig rule for it was initially missing, so it fell
        // through to the ADMIN-only "/api/antivirus/**" catch-all. Since
        // directory scan itself is a regular-user feature (no AdminRoute
        // wrapper on the frontend, POST .../scan/directory is USER-allowed),
        // that meant a non-admin user could start a scan but would get 403
        // the moment the frontend tried to poll for its result.

        @Test
        void getDirectoryScanStatus_ShouldReturnOkForUserRole() throws Exception {
                Map<String, Object> jobStatus = new HashMap<>();
                jobStatus.put("jobId", "job-123");
                jobStatus.put("isRunning", false);
                jobStatus.put("totalFiles", 2);
                jobStatus.put("processedFiles", 2);
                when(securityService.getDirectoryScanJobStatus("job-123")).thenReturn(jobStatus);

                mockMvc.perform(get("/api/antivirus/scan/directory/status/job-123")
                                .with(user("testuser").roles("USER")))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.jobId").value("job-123"))
                                .andExpect(jsonPath("$.isRunning").value(false));
        }

        @Test
        void getDirectoryScanStatus_ShouldReturnOkForAdminRole() throws Exception {
                Map<String, Object> jobStatus = new HashMap<>();
                jobStatus.put("jobId", "job-456");
                jobStatus.put("isRunning", true);
                when(securityService.getDirectoryScanJobStatus("job-456")).thenReturn(jobStatus);

                mockMvc.perform(get("/api/antivirus/scan/directory/status/job-456")
                                .with(user("admin").roles("ADMIN")))
                                .andExpect(status().isOk());
        }

        @Test
        void getDirectoryScanStatus_ShouldReturnForbiddenWithoutAuthentication() throws Exception {
                mockMvc.perform(get("/api/antivirus/scan/directory/status/job-123"))
                                .andExpect(status().is3xxRedirection());
        }

        @Test
        void getSystemScanResultsReturnsOnlyCurrentSessionResults() throws Exception {
                com.antivirus.controller.AntivirusController controller = new com.antivirus.controller.AntivirusController();
                com.antivirus.service.SecurityService securityService = org.mockito.Mockito
                                .mock(com.antivirus.service.SecurityService.class);
                com.antivirus.service.SystemMonitorService systemMonitorService = org.mockito.Mockito
                                .mock(com.antivirus.service.SystemMonitorService.class);
                com.antivirus.repository.ScanResultRepository scanResultRepository = org.mockito.Mockito
                                .mock(com.antivirus.repository.ScanResultRepository.class);
                com.antivirus.service.LogService logService = org.mockito.Mockito
                                .mock(com.antivirus.service.LogService.class);

                inject(controller, "securityService", securityService);
                inject(controller, "systemMonitorService", systemMonitorService);
                inject(controller, "scanResultRepository", scanResultRepository);
                inject(controller, "logService", logService);

                com.antivirus.model.ScanResult result = new com.antivirus.model.ScanResult();
                result.setFilePath("C:\\scan\\sample.exe");
                result.setFileName("sample.exe");
                result.setScanType("SYSTEM");
                result.setThreatType("CLEAN");
                result.setInfected(false);

                org.mockito.Mockito.when(securityService.getCurrentSystemScanResults())
                                .thenReturn(java.util.List.of(result));

                org.springframework.test.web.servlet.MockMvc mockMvc = org.springframework.test.web.servlet.setup.MockMvcBuilders
                                .standaloneSetup(controller).build();

                mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                                .get("/api/antivirus/scan/system/results"))
                                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status()
                                                .isOk())
                                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                                                .jsonPath("$[0].fileName")
                                                .value("sample.exe"))
                                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                                                .jsonPath("$[0].scanType")
                                                .value("SYSTEM"));
        }

        @Test
        void stopSystemScanReturnsAcknowledgementAndRunningState() throws Exception {
                com.antivirus.controller.AntivirusController controller = new com.antivirus.controller.AntivirusController();
                com.antivirus.service.SecurityService securityService = org.mockito.Mockito
                                .mock(com.antivirus.service.SecurityService.class);
                com.antivirus.service.SystemMonitorService systemMonitorService = org.mockito.Mockito
                                .mock(com.antivirus.service.SystemMonitorService.class);
                com.antivirus.repository.ScanResultRepository scanResultRepository = org.mockito.Mockito
                                .mock(com.antivirus.repository.ScanResultRepository.class);
                com.antivirus.service.LogService logService = org.mockito.Mockito
                                .mock(com.antivirus.service.LogService.class);

                inject(controller, "securityService", securityService);
                inject(controller, "systemMonitorService", systemMonitorService);
                inject(controller, "scanResultRepository", scanResultRepository);
                inject(controller, "logService", logService);

                org.mockito.Mockito.when(securityService.isSystemScanRunning()).thenReturn(false);

                org.springframework.test.web.servlet.MockMvc mockMvc = org.springframework.test.web.servlet.setup.MockMvcBuilders
                                .standaloneSetup(controller).build();

                mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                                .post("/api/antivirus/scan/system/stop"))
                                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status()
                                                .isOk())
                                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                                                .jsonPath("$.stopRequested")
                                                .value(true))
                                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                                                .jsonPath("$.isRunning")
                                                .value(false));

                org.mockito.Mockito.verify(securityService).stopSystemScan();
        }

        private static void inject(Object target, String fieldName, Object value) throws Exception {
                java.lang.reflect.Field field = target.getClass().getDeclaredField(fieldName);
                field.setAccessible(true);
                field.set(target, value);
        }
}
