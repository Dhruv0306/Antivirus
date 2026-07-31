package com.antivirus.controller;

import com.antivirus.config.SecurityConfig;
import com.antivirus.model.AgentStatus;
import com.antivirus.repository.AgentStatusRepository;
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
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * As of the H1 privilege split (see
 * docs/plans/h1-privilege-split-plan.md section 6), this controller no
 * longer talks to DomainBlockingService's old isHostsFileAccessible()/
 * isAdmin() probes (both removed, that logic moved to the privileged
 * system-agent) or to the now-deleted CompositeDomainBlockingService/
 * DnsDomainBlockingService. Every agent-derived assertion here goes
 * through a mocked AgentStatusRepository instead, exactly what the
 * controller itself now reads.
 */
@WebMvcTest(controllers = NetworkSecurityController.class)
@Import(SecurityConfig.class)
@TestPropertySource(properties = "app.cors.allowed-origins=https://test.example.com")
class NetworkSecurityControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private NetworkSecurityService networkSecurityService;

    @MockitoBean
    private DomainBlockingService domainBlockingService;

    @MockitoBean
    private ProxyDomainBlockingService proxyDomainBlockingService;

    @MockitoBean
    private AgentStatusRepository agentStatusRepository;

    // AgentStatus deliberately has no public setters (read-only from the
    // web app's side by design), so tests build real instances via
    // ReflectionTestUtils rather than mock(AgentStatus.class). This also
    // sidesteps a real UnfinishedStubbingException Mockito threw when
    // mocking this @Entity class directly in this test context, a plain
    // data holder with no behavior to stub doesn't need mocking at all,
    // a real instance with real field values is simpler and just as
    // faithful a test.
    private AgentStatus agentStatusWith(LocalDateTime lastHeartbeatAt, boolean hostsFileWritable,
            boolean dnsConfigWritable) {
        AgentStatus status = new AgentStatus();
        ReflectionTestUtils.setField(status, "lastHeartbeatAt", lastHeartbeatAt);
        ReflectionTestUtils.setField(status, "hostsFileWritable", hostsFileWritable);
        ReflectionTestUtils.setField(status, "dnsConfigWritable", dnsConfigWritable);
        return status;
    }

    private AgentStatus reachableAndWritable() {
        return agentStatusWith(LocalDateTime.now(), true, true);
    }

    private AgentStatus reachableButNotWritable() {
        return agentStatusWith(LocalDateTime.now(), false, false);
    }

    private AgentStatus stale() {
        // Well past the controller's 90s staleness threshold.
        return agentStatusWith(LocalDateTime.now().minusHours(1), true, true);
    }

    // ── /status ──────────────────────────────────────────────────────

    @Test
    void getStatus_ShouldReportAgentReachableAndWritableFieldsFromAgentStatus() throws Exception {
        when(agentStatusRepository.findById(1L)).thenReturn(Optional.of(reachableAndWritable()));

        mockMvc.perform(get("/api/network-security/status")
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.agentReachable").value(true))
                .andExpect(jsonPath("$.hostsFileAccessible").value(true))
                .andExpect(jsonPath("$.hasAdminPrivileges").value(true))
                .andExpect(jsonPath("$.dnsConfigAccessible").value(true))
                .andExpect(jsonPath("$.warning").doesNotExist());
    }

    @Test
    void getStatus_ShouldFailClosedWhenAgentStatusRowIsMissing() throws Exception {
        when(agentStatusRepository.findById(1L)).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/network-security/status")
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.agentReachable").value(false))
                .andExpect(jsonPath("$.hostsFileAccessible").value(false))
                .andExpect(jsonPath("$.dnsConfigAccessible").value(false))
                .andExpect(jsonPath("$.warning").exists());
    }

    @Test
    void getStatus_ShouldTreatStaleHeartbeatAsUnreachableRegardlessOfStoredWritability() throws Exception {
        when(agentStatusRepository.findById(1L)).thenReturn(Optional.of(stale()));

        // A stale heartbeat must override the stored hosts_file_writable=true
        // rather than trust it, that's the entire point of the staleness check.
        mockMvc.perform(get("/api/network-security/status")
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.agentReachable").value(false))
                .andExpect(jsonPath("$.hostsFileAccessible").value(false))
                .andExpect(jsonPath("$.warning").exists());
    }

    // ── /block ───────────────────────────────────────────────────────

    @Test
    void blockDomain_ShouldReturnSuccessForValidDomain() throws Exception {
        when(agentStatusRepository.findById(1L)).thenReturn(Optional.of(reachableAndWritable()));

        mockMvc.perform(post("/api/network-security/block")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"domain\":\"malicious-site.com\",\"reason\":\"Known malware host\"}")
                .with(csrf())
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.warning").doesNotExist());

        verify(domainBlockingService, times(1))
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

        verify(domainBlockingService, never()).blockDomain(anyString(), anyString());
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
    void blockDomain_ShouldIncludeWarningWhenAgentUnreachable() throws Exception {
        when(agentStatusRepository.findById(1L)).thenReturn(Optional.empty());

        mockMvc.perform(post("/api/network-security/block")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"domain\":\"malicious-site.com\"}")
                .with(csrf())
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.warning").exists());
    }

    @Test
    void blockDomain_ShouldIncludeWarningWhenAgentReachableButHostsFileNotWritable() throws Exception {
        when(agentStatusRepository.findById(1L)).thenReturn(Optional.of(reachableButNotWritable()));

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
        when(agentStatusRepository.findById(1L)).thenReturn(Optional.of(reachableAndWritable()));

        mockMvc.perform(post("/api/network-security/unblock")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"domain\":\"malicious-site.com\"}")
                .with(csrf())
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        verify(domainBlockingService, times(1)).unblockDomain("malicious-site.com");
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

        verify(domainBlockingService, never()).unblockDomain(anyString());
    }

    // ── /blocking-methods ────────────────────────────────────────────

    @Test
    void getAlternativeDomainBlockingMethods_ShouldMarkHostsAndDnsUnavailableWhenAgentUnreachable() throws Exception {
        when(agentStatusRepository.findById(1L)).thenReturn(Optional.empty());
        when(proxyDomainBlockingService.isProxyRunning()).thenReturn(false);
        when(proxyDomainBlockingService.getProxyPort()).thenReturn(8899);

        // Proxy blocking needs no privilege and must stay available
        // regardless of agent reachability.
        mockMvc.perform(get("/api/network-security/blocking-methods")
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.hostsFileMethod.available").value(false))
                .andExpect(jsonPath("$.dnsMethod.available").value(false))
                .andExpect(jsonPath("$.proxyMethod.available").value(true))
                .andExpect(jsonPath("$.recommendation").exists());
    }

    @Test
    void getAlternativeDomainBlockingMethods_ShouldMarkHostsAndDnsAvailableWhenAgentHealthy() throws Exception {
        when(agentStatusRepository.findById(1L)).thenReturn(Optional.of(reachableAndWritable()));
        when(proxyDomainBlockingService.isProxyRunning()).thenReturn(true);
        when(proxyDomainBlockingService.getProxyPort()).thenReturn(8899);

        mockMvc.perform(get("/api/network-security/blocking-methods")
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.hostsFileMethod.available").value(true))
                .andExpect(jsonPath("$.dnsMethod.available").value(true))
                .andExpect(jsonPath("$.recommendation").doesNotExist());
    }

    // ── /dns/update ──────────────────────────────────────────────────

    @Test
    void updateDnsConfig_ShouldReportAgentDerivedStatusRatherThanWritingAnything() throws Exception {
        when(agentStatusRepository.findById(1L)).thenReturn(Optional.of(reachableAndWritable()));

        mockMvc.perform(post("/api/network-security/dns/update")
                .with(csrf())
                .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.agentReachable").value(true))
                .andExpect(jsonPath("$.dnsConfigAccessible").value(true));
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
