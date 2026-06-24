import { useState } from "react";

// ── DATA ────────────────────────────────────────────────────────────────────

const FIXED = [
  { id: "C-02", text: "Hardcoded credentials removed — both dev/prod properties now require explicit env vars with no fallback" },
  { id: "C-03", text: "Base64 sessionStorage replaced with CSRF-token form login; only display username stored" },
  { id: "C-04", text: "CSRF re-enabled with CookieCsrfTokenRepository; token sent on all mutating requests" },
  { id: "C-05", text: "VITE_API_PASSWORD/USERNAME purged from frontend bundle and env files entirely" },
  { id: "H-01", text: "ScanResult.getFilePath() annotated @JsonIgnore; getFileName() exposes display-safe name only" },
  { id: "H-02", text: "Per-IP+username rate limiter added at Ordered.HIGHEST_PRECEDENCE on /api/auth/login" },
  { id: "H-04", text: "Port scan parallelised with 8-thread bounded pool + 2 s CompletableFuture timeout" },
  { id: "H-05", text: "Temp file suffix now uses UUID only; ALLOWED_CONTENT_TYPES allowlist enforced before disk write" },
  { id: "H-06", text: "Full security header suite: CSP, HSTS (1 yr, includeSubDomains), X-Frame-Options, X-Content-Type-Options, Referrer-Policy" },
  { id: "H-07", text: "NetworkSecurity.js replaced raw axios + localhost hardcodes with shared authenticated networkSecurityApi client" },
  { id: "H-08", text: "Exception messages no longer forwarded to API response bodies; opaque messages returned" },
  { id: "M-05", text: "LogService now has MAX_LOG_FILE_SIZE_BYTES (10 MB) with 7-backup rotation via Files.move" },
  { id: "M-06", text: "Background network monitor converted from raw Thread to @Scheduled(fixedDelay=5000)" },
  { id: "M-07", text: "spring.jpa.hibernate.ddl-auto: none (base) / validate (prod) / update (dev only)" },
  { id: "M-08", text: "SystemScan uses interval + clearInterval return in useEffect; Dashboard polling cleaned up" },
  { id: "M-09", text: "logger.js utility noops in production; Vite esbuild.drop strips console.* from prod bundle" },
  { id: "M-10", text: "errors.js toUserMessage() centralises safe error mapping; most components use it" },
  { id: "L-06", text: "H2 console requires ADMIN role via @Profile(dev) @Order(1) security chain; base & prod disable it" },
];

const UNVERIFIABLE = [
  { id: "C-01", text: "SHA-256 / MD5 hash mismatch — SecurityServiceImpl.java is absent from this dump; cannot confirm resolved" },
  { id: "H-03", text: "Unbounded ArrayList in performSystemScan — SecurityServiceImpl.java absent" },
  { id: "H-09", text: "@Transactional on performSystemScan exhausting HikariCP pool — SecurityServiceImpl.java absent" },
  { id: "M-01", text: "pattern.matches() instead of find() — SecurityServiceImpl.java absent" },
  { id: "M-02", text: "Files.readAllBytes() on 100 MB uploads — SecurityServiceImpl.java absent" },
  { id: "M-03", text: "No ZIP-bomb protection — SecurityServiceImpl.java absent" },
  { id: "L-01", text: "authenticateUser/authorizeUser stub returning false — SecurityServiceImpl.java absent" },
];

const newFindings = [
  {
    id: "N-01",
    severity: "High",
    title: "Rate limiter bypassed by spoofing X-Forwarded-For header",
    location: "src/main/java/com/antivirus/config/SecurityConfig.java — resolveRateLimitKey() (~L250)",
    description: "resolveRateLimitKey() fully trusts the X-Forwarded-For header from the incoming request without any allowlist, trusted-proxy validation, or sanity check. The rate-limit map key is built as clientIp + '|' + username. An attacker simply rotates their X-Forwarded-For value on every request (e.g. X-Forwarded-For: 1.0.0.1, 1.0.0.2 …) to always hit a fresh bucket. The HMAC-style AttemptWindow is never exhausted. The brand-new rate limiter is a no-op against any attacker aware of this header.",
    impact: "Unlimited brute-force login attempts. The entire H-02 remediation is ineffective until this is fixed.",
    remediation: `// SecurityConfig.java — only trust X-Forwarded-For when the
// real TCP peer is a known trusted proxy (load balancer, Nginx).
// Simplest fix: never trust the header at all if not behind a proxy.

@Value("\${app.trusted-proxy-ips:}")
private String trustedProxyIps;          // empty = not behind a proxy

private String resolveRateLimitKey(HttpServletRequest request) {
    String remoteAddr = request.getRemoteAddr();

    // Only honour X-Forwarded-For when the TCP peer is a known proxy
    Set<String> trustedProxies = Set.of(
        trustedProxyIps.split(",")).stream()
            .map(String::trim).filter(s -> !s.isEmpty())
            .collect(Collectors.toSet());

    String clientIp = remoteAddr;
    if (trustedProxies.contains(remoteAddr)) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            // Take the first (leftmost) IP and validate format
            String candidate = xff.split(",")[0].trim();
            if (candidate.matches("^[\\d.:a-fA-F]+$")) {
                clientIp = candidate;
            }
        }
    }

    String username = Optional.ofNullable(request.getParameter("username"))
        .filter(u -> !u.isBlank())
        .orElse("unknown");

    return clientIp + "|" + username.toLowerCase();
}`
  },
  {
    id: "N-02",
    severity: "High",
    title: "DNS blocking corrupts all name resolution instead of blocking per-domain",
    location: "src/main/java/com/antivirus/service/DnsDomainBlockingService.java — updateDnsConfig() (~L7213)",
    description: "updateDnsConfig() rewrites /etc/resolv.conf to contain lines such as 'nameserver 0.0.0.0 # Blocked: malware.example.com'. resolv.conf nameserver entries are global — they specify which DNS server to use for ALL queries, not individual domain overrides. Writing 0.0.0.0 as a nameserver causes ALL DNS lookups on the system to fail, not just the targeted domain. On a production Linux server this kills all outbound connectivity, database connections, and health checks in seconds.",
    impact: "Complete DNS outage for the entire server OS when updateDnsConfig() is triggered. Also clobbers legitimate nameservers with no recovery path if the backup is also corrupt.",
    remediation: `// DNS-level per-domain blocking is not achievable via resolv.conf.
// The correct Linux approach is a local dnsmasq/unbound entry:
//   address=/malware.example.com/0.0.0.0
//
// If dnsmasq is available, write to /etc/dnsmasq.d/antivirus-blocked.conf:

private static final String DNSMASQ_CONF =
    "/etc/dnsmasq.d/antivirus-blocked.conf";

public void updateDnsConfig() {
    List<BlockedDomain> domains =
        blockedDomainRepository.findByActiveTrue();

    // Build dnsmasq address= directives — one per domain
    String content = domains.stream()
        .map(d -> "address=/" + d.getDomain() + "/0.0.0.0")
        .collect(Collectors.joining("\\n")) + "\\n";

    try {
        Files.writeString(Paths.get(DNSMASQ_CONF), content,
            StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        // Reload dnsmasq without restart
        new ProcessBuilder("systemctl", "reload", "dnsmasq").start().waitFor();
    } catch (IOException | InterruptedException e) {
        logger.error("Failed to update dnsmasq config", e);
    }
}
// NOTE: if dnsmasq is not available, disable this service and
// use only the proxy/hosts-file blocking methods.`
  },
  {
    id: "N-03",
    severity: "High",
    title: "Proxy SSRF — CONNECT and HTTP forward tunnel to internal/loopback addresses",
    location: "src/main/java/com/antivirus/service/ProxyDomainBlockingService.java — handleConnect() (~L7930), isDomainBlocked() (~L8060)",
    description: "isDomainBlocked() only looks up domain names in the database. An attacker who proxies CONNECT 127.0.0.1:6379 HTTP/1.1 or CONNECT 192.168.1.1:22 HTTP/1.1 bypasses the domain check entirely (IP addresses won't be in the blocked-domains table) and reaches internal services directly. handleConnect() then calls new Socket().connect(new InetSocketAddress(request.host(), request.port())) unconditionally. An authenticated user can use the antivirus proxy as a pivot to scan or attack any service reachable from the server — Redis, the H2 database, Kubernetes API, cloud metadata endpoints (169.254.169.254).",
    impact: "Authenticated users can reach any TCP service on localhost or internal network, bypassing firewalls. Metadata endpoint exposure in cloud deployments (AWS/GCP/Azure).",
    remediation: `// ProxyDomainBlockingService.java — add an IP blocklist before connecting

private static final Set<String> BLOCKED_IP_PREFIXES = Set.of(
    "127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "169.254.", "::1", "fd", "fc"
);

private boolean isPrivateOrLoopback(String host) {
    String h = host.toLowerCase(Locale.ROOT);
    if (h.equals("localhost")) return true;
    // Try resolving to catch DNS-rebinding — use cached InetAddress
    try {
        InetAddress addr = InetAddress.getByName(h);
        String ip = addr.getHostAddress();
        return BLOCKED_IP_PREFIXES.stream().anyMatch(ip::startsWith)
            || addr.isLoopbackAddress()
            || addr.isSiteLocalAddress()
            || addr.isLinkLocalAddress();
    } catch (UnknownHostException e) {
        return true; // fail-closed: block unresolvable hosts
    }
}

// In handleClientConnection(), after isDomainBlocked() check:
if (isPrivateOrLoopback(request.host())) {
    sendBlockedResponse(clientSocket);
    logger.warn("SSRF attempt blocked: {}:{}", request.host(), request.port());
    return;
}`
  },
  {
    id: "N-04",
    severity: "Medium",
    title: "CSRF token persisted to sessionStorage — readable by XSS",
    location: "frontend/src/api/client.js — writeStoredCsrfCredentials() (~L1468), setCsrfCredentials() (~L1478)",
    description: "setCsrfCredentials() writes the CSRF token (headerName, parameterName, token) to sessionStorage under 'auth_csrf_credentials'. The in-memory variable runtimeCsrf already serves all legitimate uses (it's checked first in getCsrfCredentials). The sessionStorage copy only exists to survive page refreshes, but at the cost of XSS-readability — any script on the same origin can call sessionStorage.getItem('auth_csrf_credentials') to extract the current CSRF token, allowing CSRF attacks despite the cookie-based protection.",
    impact: "XSS on any page of the SPA can steal the CSRF token and execute authenticated state-changing requests (firewall toggle, domain block, file quarantine/delete).",
    remediation: `// client.js — remove sessionStorage persistence of the CSRF token.
// On page refresh, the login flow already re-fetches CSRF from /api/auth/csrf.
// Keeping only the in-memory variable is sufficient.

// REMOVE writeStoredCsrfCredentials / readStoredCsrfCredentials / clearStoredCsrfCredentials
// and the sessionStorage calls from setCsrfCredentials / clearCsrfCredentials.

let runtimeCsrf = null;  // ← in-memory only, not persisted

export function setCsrfCredentials(csrf) {
    runtimeCsrf = csrf;   // no sessionStorage write
}

export function clearCsrfCredentials() {
    runtimeCsrf = null;   // no sessionStorage clear needed
}

function getCsrfCredentials() {
    // Fall back to reading XSRF-TOKEN cookie — already in place as secondary
    return runtimeCsrf;
}
// If the app needs to survive a page refresh while staying logged in,
// detect 401 on the first API call and redirect to login — which already
// happens in the response interceptor.`
  },
  {
    id: "N-05",
    severity: "Medium",
    title: "AttemptWindow map grows unboundedly under brute-force attack",
    location: "src/main/java/com/antivirus/config/SecurityConfig.java — authAttemptWindows field (~L5510), cleanupExpiredAttemptWindows() (~L5590)",
    description: "authAttemptWindows is a ConcurrentHashMap with no size cap. cleanupExpiredAttemptWindows() removes expired entries (1-minute windows) but is only called after a successful request passes through the filter. A distributed brute-force attack with N different spoofed IPs creates N map entries simultaneously. With a 1-minute window and 1000 req/s attack across unique IPs, 60,000 AttemptWindow objects accumulate before any expire — each holding a synchronized Instant + int. At scale this causes GC pressure and eventually OOM.",
    impact: "Memory exhaustion DoS under distributed brute-force attack. Attacker causes OOM crash without ever triggering the rate limit.",
    remediation: `// Use a bounded LinkedHashMap with LRU eviction instead of ConcurrentHashMap.
// Or use Caffeine/Guava Cache which supports size-based and time-based eviction.

// In pom.xml:
// <dependency>
//   <groupId>com.github.ben-manes.caffeine</groupId>
//   <artifactId>caffeine</artifactId>
// </dependency>

// SecurityConfig.java
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Cache;

private final Cache<String, AttemptWindow> authAttemptWindows =
    Caffeine.newBuilder()
        .maximumSize(50_000)                    // hard cap
        .expireAfterWrite(2, TimeUnit.MINUTES)  // auto-evict expired windows
        .build();

// Replace authAttemptWindows.computeIfAbsent with:
AttemptWindow window = authAttemptWindows.get(
    rateLimitKey, key -> new AttemptWindow());

// Remove cleanupExpiredAttemptWindows() — Caffeine handles this automatically.`
  },
  {
    id: "N-06",
    severity: "Medium",
    title: "Proxy relay() creates unbounded raw threads outside the bounded ExecutorService",
    location: "src/main/java/com/antivirus/service/ProxyDomainBlockingService.java — relay() (~L8016)",
    description: "The proxy's executorService is bounded to MAX_PROXY_THREADS = 50. However, relay() creates 2 new raw daemon Thread objects per proxied connection entirely outside this pool. With 50 concurrent connections, 100+ additional threads exist outside any lifecycle management. On heavy load the JVM thread count grows to 50 (pool) + 50*2 (relay threads) = 150+, bypassing the configured limit and causing excessive context switching or OOM in constrained environments.",
    impact: "Thread exhaustion and JVM OOM under proxy load. Effective thread limit is 3x the configured maximum.",
    remediation: `// ProxyDomainBlockingService.java — use a dedicated relay thread pool
// instead of creating raw threads per connection.

private static final ExecutorService RELAY_EXECUTOR =
    Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "proxy-relay");
        t.setDaemon(true);
        return t;
    });
// Or better — a bounded pool with a queue:
// Executors.newFixedThreadPool(MAX_PROXY_THREADS * 2, ...)

private void relay(Socket client, Socket remote) {
    Future<?> c2r = RELAY_EXECUTOR.submit(() -> pump(client, remote));
    Future<?> r2c = RELAY_EXECUTOR.submit(() -> pump(remote, client));
    try {
        c2r.get();
        r2c.get();
    } catch (Exception e) {
        Thread.currentThread().interrupt();
        c2r.cancel(true);
        r2c.cancel(true);
    }
}`
  },
  {
    id: "N-07",
    severity: "Medium",
    title: "SystemScan.js passes undefined variable to toUserMessage() in elevation path",
    location: "frontend/src/components/SystemScan.js — handleScan() (~L4810)",
    description: "In the administrator-privileges warning block, the code calls setError(toUserMessage(error)) where error is the useState variable (currently null), not a caught exception. toUserMessage(null) returns USER_MESSAGES.default = 'An unexpected error occurred.' — completely overriding the intended elevation warning message with a misleading generic error. The user sees 'An unexpected error occurred' when they should see 'Administrator Privileges Required'. Additionally, the catch block still uses err.response.data.message directly for certain cases, partially reverting the M-10 fix.",
    impact: "Broken UX for the privilege-escalation flow. Also a partial regression of the M-10 error-normalization fix: raw server messages can reach the UI through the catch block path.",
    remediation: `// SystemScan.js — fix the elevation check to use a hardcoded message,
// and fix the catch block to use toUserMessage consistently.

const handleScan = async () => {
    try {
        ...
        if (result.threatType === 'WARNING' &&
            result.threatDetails?.includes('Administrator privileges required')) {
            setNeedsElevation(true);
            // Use a hardcoded safe message — there is no Error object here
            setError('Administrator privileges are required to perform a full system scan.');
            return;
        }
        ...
    } catch (err) {
        logError('Scan error:', err);
        // ALWAYS use toUserMessage — never touch err.response.data.message
        setError(toUserMessage(err));
    } finally {
        setScanning(false);
        setProgress(100);
    }
};`
  },
  {
    id: "N-08",
    severity: "Low",
    title: "getCurrentActiveConnections() returns network interface address count, not TCP connections",
    location: "src/main/java/com/antivirus/service/impl/NetworkSecurityServiceImpl.java — getCurrentActiveConnections() (~L8570)",
    description: "getNetworkInterfaces().asIterator().next().getInterfaceAddresses().size() returns the number of IP addresses bound to the first network interface (typically 2: one IPv4 + one IPv6). This is a constant value — it never reflects real TCP connection counts. The dashboard metric 'Active Connections' will always display 1 or 2 regardless of actual network load, making it useless for intrusion detection.",
    impact: "Dashboard metric is always a small constant. Provides false assurance and makes real connection-count anomaly detection impossible.",
    remediation: `// NetworkSecurityServiceImpl.java — use /proc/net/tcp for Linux,
// or netstat via ProcessBuilder for cross-platform.
// For a JVM-only approach, use JMX connection pool metrics.

private int getCurrentActiveConnections() {
    // Cross-platform: count established TCP sessions from OS
    try {
        ProcessBuilder pb;
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            pb = new ProcessBuilder("netstat", "-n");
        } else {
            pb = new ProcessBuilder("ss", "-tn", "state", "established");
        }
        pb.redirectErrorStream(true);
        Process process = pb.start();
        long count = new BufferedReader(
            new InputStreamReader(process.getInputStream()))
            .lines()
            .filter(l -> l.contains("ESTABLISHED") || (!System.getProperty("os.name").toLowerCase().contains("win") && !l.startsWith("Netid")))
            .count();
        process.waitFor(1, TimeUnit.SECONDS);
        return (int) count;
    } catch (Exception e) {
        logger.debug("Could not read active connections", e);
        return activeConnections.get(); // fall back to manual counter
    }
}`
  },
];

const remainingFindings = [
  {
    id: "O-01",
    severity: "Low",
    title: "isAdmin() still performs a live filesystem check on every call",
    location: "src/main/java/com/antivirus/service/impl/DomainBlockingServiceImpl.java — isAdmin() (~L8329)",
    description: "The previous audit recommended returning the cached hasAdminPrivileges field. The fix was applied to refreshPrivilegeCheck() (added correctly) but isAdmin() itself still calls canModifyHostsFile(Paths.get(hostsFilePath)) — a live Files.isWritable() check — on every invocation. /api/network-security/status calls isAdmin() and isHostsFileAccessible() on every request. On a filesystem with slow permissions checks this adds unnecessary latency and the returned value may differ from hasAdminPrivileges, creating inconsistency.",
    remediation: `// DomainBlockingServiceImpl.java — return the cached field
@Override
public boolean isAdmin() {
    return hasAdminPrivileges;  // ← cached from construction; refreshed by refreshPrivilegeCheck()
}
// refreshPrivilegeCheck() already exists for explicit re-checks — leave it as-is.`
  },
  {
    id: "O-02",
    severity: "Low",
    title: "@SuppressWarnings(\"null\") retained on both upload handler methods",
    location: "src/main/java/com/antivirus/controller/AntivirusController.java — scanFile() (~L5655), scanDirectory() (~L5760)",
    description: "Both methods still carry @SuppressWarnings(\"null\"), suppressing the compiler's null-safety analysis on the exact code paths that handle untrusted file uploads. The null checks added within these methods reduce practical risk, but leaving the suppression in place hides any future null-related code changes silently.",
    remediation: `// Remove @SuppressWarnings("null") from both methods.
// The explicit null guards inside the methods make the annotation unnecessary.
// @SuppressWarnings("null") <-- DELETE this line
@PostMapping("/scan/file")
public ResponseEntity<?> scanFile(@RequestParam("file") MultipartFile file) { ... }

// @SuppressWarnings("null") <-- DELETE this line
@PostMapping("/scan/directory")
public ResponseEntity<?> scanDirectory(...) { ... }`
  },
  {
    id: "O-03",
    severity: "Low",
    title: "LogService debug-logs the raw absolute file path from @JsonIgnore-protected field",
    location: "src/main/java/com/antivirus/service/LogService.java — logScanResult() (~L7318)",
    description: "logger.debug(\"Successfully logged scan result for file: {}\", result.getFilePath()) calls the @JsonIgnore-protected getFilePath() getter. In a verbose logging environment (logging.level.com.antivirus=DEBUG in application-dev.properties), this writes the full server-side absolute temp path to the log file — the exact data @JsonIgnore was added to protect. The path is now controlled by API responses but still leaks to log files.",
    remediation: `// LogService.java — log only the display-safe filename
logger.debug("Successfully logged scan result for file: {}",
    result.getFileName());  // ← getFileName() not getFilePath()`
  },
  {
    id: "O-04",
    severity: "Low",
    title: "toggleFirewall/toggleWebProtection activeThreats counter can underflow to negative",
    location: "src/main/java/com/antivirus/service/impl/NetworkSecurityServiceImpl.java — toggleFirewall() (~L8450), toggleWebProtection() (~L8461)",
    description: "Both methods call activeThreats.decrementAndGet() when enabling protection without a lower-bound guard. If the firewall is enabled twice without being disabled first, activeThreats goes negative (-1, -2…). The counter is serialised into NetworkScanResult and returned to the frontend, producing negative 'active threats' counts in the dashboard.",
    remediation: `// NetworkSecurityServiceImpl.java — use updateAndGet with a floor of 0
@Override
public void toggleFirewall(Boolean enabled) {
    boolean was = this.firewallEnabled;
    this.firewallEnabled = enabled != null ? enabled : !was;
    if (!was && this.firewallEnabled) {
        activeThreats.updateAndGet(v -> Math.max(0, v - 1)); // enabling: safe decrement
    } else if (was && !this.firewallEnabled) {
        activeThreats.incrementAndGet(); // disabling: increment
    }
    // No change if toggle didn't change the state
}`
  },
];

const SEVERITY_CONFIG = {
  High:   { color: "#854F0B", bg: "#FAEEDA", border: "#EF9F27" },
  Medium: { color: "#185FA5", bg: "#E6F1FB", border: "#85B7EB" },
  Low:    { color: "#3B6D11", bg: "#EAF3DE", border: "#97C459" },
};

function Badge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity];
  return (
    <span style={{
      background: cfg.bg, color: cfg.color,
      border: `0.5px solid ${cfg.border}`,
      borderRadius: 6, fontSize: 11, fontWeight: 500,
      padding: "2px 8px", whiteSpace: "nowrap",
    }}>{severity}</span>
  );
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(false);
  const cfg = SEVERITY_CONFIG[f.severity];
  return (
    <div style={{
      background: "var(--color-background-primary)",
      border: "0.5px solid var(--color-border-tertiary)",
      borderLeft: `3px solid ${cfg.border}`,
      borderRadius: 10, marginBottom: 8, overflow: "hidden",
    }}>
      <button onClick={() => setOpen(v => !v)} style={{
        display: "flex", alignItems: "center", gap: 10,
        width: "100%", background: "none", border: "none",
        padding: "12px 16px", cursor: "pointer", textAlign: "left",
      }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: cfg.color, fontWeight: 500, minWidth: 38 }}>{f.id}</span>
        <Badge severity={f.severity} />
        <span style={{ flex: 1, fontSize: 14, fontWeight: 500, color: "var(--color-text-primary)", marginLeft: 4 }}>{f.title}</span>
        <i className={`ti ${open ? "ti-chevron-up" : "ti-chevron-down"}`} style={{ fontSize: 16, color: "var(--color-text-secondary)" }} />
      </button>
      {open && (
        <div style={{ padding: "0 16px 16px", borderTop: "0.5px solid var(--color-border-tertiary)" }}>
          <Sec label="Location"><code style={{ fontSize: 12, background: "var(--color-background-secondary)", padding: "6px 10px", borderRadius: 6, display: "block", whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--color-text-secondary)" }}>{f.location}</code></Sec>
          <Sec label="Description"><p style={{ margin: 0, fontSize: 14, color: "var(--color-text-secondary)", lineHeight: 1.65 }}>{f.description}</p></Sec>
          {f.impact && <Sec label="Impact"><p style={{ margin: 0, fontSize: 14, color: cfg.color, lineHeight: 1.65, fontWeight: 500 }}>{f.impact}</p></Sec>}
          <Sec label="Remediation"><pre style={{ margin: 0, fontSize: 12, background: "var(--color-background-secondary)", padding: "12px 14px", borderRadius: 8, overflow: "auto", whiteSpace: "pre", color: "var(--color-text-primary)", lineHeight: 1.6, fontFamily: "var(--font-mono)" }}>{f.remediation}</pre></Sec>
        </div>
      )}
    </div>
  );
}

function Sec({ label, children }) {
  return (
    <div style={{ marginTop: 12 }}>
      <p style={{ margin: "0 0 6px", fontSize: 11, fontWeight: 500, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</p>
      {children}
    </div>
  );
}

export default function AuditPart3() {
  const [tab, setTab] = useState("new");

  return (
    <div style={{ padding: "1.5rem 0", maxWidth: 720, margin: "0 auto" }}>
      <div style={{ marginBottom: "1.5rem" }}>
        <p style={{ margin: "0 0 4px", fontSize: 11, fontWeight: 500, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Security audit — part 3</p>
        <p style={{ margin: "0 0 0.5rem", fontSize: 20, fontWeight: 500, color: "var(--color-text-primary)" }}>Remediation verification & new findings</p>
        <p style={{ margin: 0, fontSize: 13, color: "var(--color-text-secondary)" }}>
          Updated codebase review against all 31 prior findings · {FIXED.length} confirmed fixed · 7 unverifiable (SecurityServiceImpl absent) · {newFindings.length} new · {remainingFindings.length} still open
        </p>
      </div>

      {/* Score cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: "1.5rem" }}>
        {[
          { n: FIXED.length, label: "Fixed", color: "#3B6D11", bg: "#EAF3DE", border: "#97C459" },
          { n: 7, label: "Unverifiable", color: "#854F0B", bg: "#FAEEDA", border: "#EF9F27" },
          { n: newFindings.length, label: "New findings", color: "#185FA5", bg: "#E6F1FB", border: "#85B7EB" },
          { n: remainingFindings.length, label: "Still open", color: "#5C5C8A", bg: "#F0EFF9", border: "#B0ACDE" },
        ].map(c => (
          <div key={c.label} style={{ background: c.bg, border: `0.5px solid ${c.border}`, borderRadius: 10, padding: "12px 14px" }}>
            <p style={{ margin: "0 0 2px", fontSize: 22, fontWeight: 500, color: c.color }}>{c.n}</p>
            <p style={{ margin: 0, fontSize: 12, color: c.color }}>{c.label}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 0, marginBottom: "1.5rem", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
        {[["new", `New Findings (${newFindings.length})`], ["open", `Still Open (${remainingFindings.length})`], ["fixed", `Confirmed Fixed (${FIXED.length})`], ["unverifiable", "Unverifiable (7)"]].map(([key, label]) => (
          <button key={key} onClick={() => setTab(key)} style={{
            padding: "8px 14px", fontSize: 13, fontWeight: 500,
            background: "none", border: "none",
            borderBottom: tab === key ? "2px solid var(--color-text-primary)" : "2px solid transparent",
            color: tab === key ? "var(--color-text-primary)" : "var(--color-text-secondary)",
            cursor: "pointer", marginBottom: -1, whiteSpace: "nowrap",
          }}>{label}</button>
        ))}
      </div>

      {tab === "new" && (
        <div>
          <div style={{ background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: 10, padding: "12px 16px", marginBottom: "1.5rem", fontSize: 13, lineHeight: 1.7, color: "var(--color-text-secondary)" }}>
            <strong style={{ color: "var(--color-text-primary)", fontWeight: 500 }}>Summary — </strong>
            Three high-severity issues require immediate attention: the new rate limiter is completely bypassable via X-Forwarded-For spoofing (N-01), the DNS blocking service corrupts system-wide DNS rather than blocking individual domains (N-02), and the proxy has an SSRF path to internal services via IP-based CONNECT requests (N-03). Four medium findings follow covering CSRF token storage, the rate-limiter memory leak, proxy thread exhaustion, and a regression in SystemScan.js error handling.
          </div>
          {newFindings.map(f => <FindingCard key={f.id} f={f} />)}
        </div>
      )}

      {tab === "open" && (
        <div>
          <div style={{ background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: 10, padding: "12px 16px", marginBottom: "1.5rem", fontSize: 13, lineHeight: 1.7, color: "var(--color-text-secondary)" }}>
            <strong style={{ color: "var(--color-text-primary)", fontWeight: 500 }}>Four low-severity items — </strong>
            all carried forward from previous audits, none of them blocking deployment but each adding up to code quality and correctness debt.
          </div>
          {remainingFindings.map(f => <FindingCard key={f.id} f={f} />)}
        </div>
      )}

      {tab === "fixed" && (
        <div>
          <div style={{ background: "#EAF3DE", border: "0.5px solid #97C459", borderRadius: 10, padding: "12px 16px", marginBottom: "1.5rem", fontSize: 13, lineHeight: 1.7, color: "#3B6D11" }}>
            <strong>18 of 31 prior findings confirmed resolved</strong> — the authentication overhaul (CSRF, session cookies, rate limiting), security headers, temp file handling, log rotation, and production console stripping are all correctly implemented.
          </div>
          {FIXED.map(f => (
            <div key={f.id} style={{ display: "flex", gap: 10, padding: "10px 14px", background: "var(--color-background-primary)", border: "0.5px solid var(--color-border-tertiary)", borderLeft: "3px solid #97C459", borderRadius: 10, marginBottom: 8 }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#3B6D11", fontWeight: 500, minWidth: 38 }}>{f.id}</span>
              <span style={{ fontSize: 13, color: "var(--color-text-secondary)", lineHeight: 1.55 }}>{f.text}</span>
            </div>
          ))}
        </div>
      )}

      {tab === "unverifiable" && (
        <div>
          <div style={{ background: "#FAEEDA", border: "0.5px solid #EF9F27", borderRadius: 10, padding: "12px 16px", marginBottom: "1.5rem", fontSize: 13, lineHeight: 1.7, color: "#854F0B" }}>
            <strong>SecurityServiceImpl.java is absent from this codebase dump.</strong> The AntivirusController still autowires SecurityService — Spring Boot would refuse to start without an implementation bean, so the file must exist but was not included. The 7 findings below cannot be marked resolved or open until the file is shared. Request a fresh dump that includes <code style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java</code> to close this gap.
          </div>
          {UNVERIFIABLE.map(f => (
            <div key={f.id} style={{ display: "flex", gap: 10, padding: "10px 14px", background: "var(--color-background-primary)", border: "0.5px solid var(--color-border-tertiary)", borderLeft: "3px solid #EF9F27", borderRadius: 10, marginBottom: 8 }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#854F0B", fontWeight: 500, minWidth: 38 }}>{f.id}</span>
              <span style={{ fontSize: 13, color: "var(--color-text-secondary)", lineHeight: 1.55 }}>{f.text}</span>
            </div>
          ))}
        </div>
      )}

      <div style={{ marginTop: "2rem", borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: "1rem", fontSize: 12, color: "var(--color-text-tertiary)" }}>
        Part 3 of 3 — expand any finding for location, impact, and exact remediation code.
      </div>
    </div>
  );
}