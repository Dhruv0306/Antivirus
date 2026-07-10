package com.antivirus.controller;

import com.antivirus.config.SecurityConfig;
import com.antivirus.dto.PagedResponse;
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

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = AntivirusController.class)
@Import(SecurityConfig.class)
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
}