package com.antivirus.controller;

import com.antivirus.config.SecurityConfig;
import com.antivirus.service.CompositeDomainBlockingService;
import com.antivirus.service.DnsDomainBlockingService;
import com.antivirus.service.DomainBlockingService;
import com.antivirus.service.NetworkSecurityService;
import com.antivirus.service.ProxyDomainBlockingService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = NetworkSecurityController.class)
@Import(SecurityConfig.class)
@TestPropertySource(properties = "app.cors.allowed-origins=https://test.example.com")
class NetworkSecurityControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private NetworkSecurityService networkSecurityService;

    @MockitoBean
    private CompositeDomainBlockingService domainBlockingService;

    @MockitoBean
    private DomainBlockingService hostsFileDomainBlockingService;

    @MockitoBean
    private ProxyDomainBlockingService proxyDomainBlockingService;

    @MockitoBean
    private DnsDomainBlockingService dnsDomainBlockingService;

    // ── /block ───────────────────────────────────────────────────────

    @Test
    void blockDomain_ShouldReturnSuccessForValidDomain() throws Exception {
        when(hostsFileDomainBlockingService.isHostsFileAccessible()).thenReturn(true);
        when(hostsFileDomainBlockingService.isAdmin()).thenReturn(true);

        mockMvc.perform(post("/api/network-security/block")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"domain\":\"malicious-site.com\",\"reason\":\"Known malware host\"}")
                .with(csrf())
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        verify(hostsFileDomainBlockingService, times(1))
                .blockDomain("malicious-site.com", "Known malware host");
    }

    @Test
    void blockDomain_ShouldReturnBadRequestForInvalidDomain() throws Exception {
        mockMvc.perform(post("/api/network-security/block")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"domain\":\"not a valid domain\"}")
                .with(csrf())
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error").value("Invalid domain name"));

        verify(hostsFileDomainBlockingService, never()).blockDomain(anyString(), anyString());
    }

    @Test
    void blockDomain_ShouldReturnBadRequestForMissingDomainField() throws Exception {
        mockMvc.perform(post("/api/network-security/block")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
                .with(csrf())
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    void blockDomain_ShouldReturnForbiddenForUserRole() throws Exception {
        mockMvc.perform(post("/api/network-security/block")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"domain\":\"malicious-site.com\"}")
                .with(csrf())
                .with(user("testuser").roles("USER")))
                .andExpect(status().isForbidden());
    }

    @Test
    void blockDomain_ShouldIncludeWarningWhenHostsFileNotAccessible() throws Exception {
        when(hostsFileDomainBlockingService.isHostsFileAccessible()).thenReturn(false);

        mockMvc.perform(post("/api/network-security/block")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"domain\":\"malicious-site.com\"}")
                .with(csrf())
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.warning").exists());
    }

    // ── /unblock ─────────────────────────────────────────────────────

    @Test
    void unblockDomain_ShouldReturnSuccessForValidDomain() throws Exception {
        when(hostsFileDomainBlockingService.isHostsFileAccessible()).thenReturn(true);
        when(hostsFileDomainBlockingService.isAdmin()).thenReturn(true);

        mockMvc.perform(post("/api/network-security/unblock")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"domain\":\"malicious-site.com\"}")
                .with(csrf())
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        verify(hostsFileDomainBlockingService, times(1)).unblockDomain("malicious-site.com");
    }

    @Test
    void unblockDomain_ShouldReturnBadRequestForInvalidDomain() throws Exception {
        mockMvc.perform(post("/api/network-security/unblock")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"domain\":\"\"}")
                .with(csrf())
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false));

        verify(hostsFileDomainBlockingService, never()).unblockDomain(anyString());
    }

    // ── /proxy/start, /proxy/stop ─────────────────────────────────────

    @Test
    void startProxyServer_ShouldReturnPortAndInstructionsOnSuccess() throws Exception {
        doNothing().when(proxyDomainBlockingService).startProxyServer();
        when(proxyDomainBlockingService.getProxyPort()).thenReturn(8899);
        when(proxyDomainBlockingService.getProxyInstructions())
                .thenReturn(Map.of("windows", "...", "macos", "...", "linux", "..."));

        mockMvc.perform(post("/api/network-security/proxy/start")
                .with(csrf())
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.port").value(8899))
                .andExpect(jsonPath("$.instructions").exists());
    }

    @Test
    void startProxyServer_ShouldReturnBadRequestWhenStartFails() throws Exception {
        doThrow(new RuntimeException("port already in use"))
                .when(proxyDomainBlockingService).startProxyServer();

        mockMvc.perform(post("/api/network-security/proxy/start")
                .with(csrf())
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    void stopProxyServer_ShouldReturnSuccessOnStop() throws Exception {
        doNothing().when(proxyDomainBlockingService).stopProxyServer();

        mockMvc.perform(post("/api/network-security/proxy/stop")
                .with(csrf())
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        verify(proxyDomainBlockingService, times(1)).stopProxyServer();
    }

    @Test
    void proxyEndpoints_ShouldReturnForbiddenForUserRole() throws Exception {
        mockMvc.perform(post("/api/network-security/proxy/start")
                .with(csrf())
                .with(user("testuser").roles("USER")))
                .andExpect(status().isForbidden());
    }
}