import { useState } from "react";

const findings = [
  {
    id: "C-01",
    severity: "Critical",
    title: "Hash algorithm mismatch renders signature DB useless",
    location: "src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java — KNOWN_MALWARE_SIGNATURES (~L8406), calculateFileHash (~L8527)",
    description: "KNOWN_MALWARE_SIGNATURES is seeded with MD5 hex digests (32 chars), but calculateFileHash() computes SHA-256 (64 chars). The two sets can never intersect — known-malware signatures will never trigger, silently neutering the primary detection path.",
    impact: "Every file is scanned against signatures that can never match. All virus-signature-based detection is a no-op.",
    remediation: `// Choose one algorithm and use it throughout.
// Option A — switch signatures to SHA-256 (recommended):
private static final Set<String> KNOWN_MALWARE_SIGNATURES = new HashSet<>(Arrays.asList(
    // 64-char SHA-256 hashes
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
));

private String calculateFileHash(File file) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    try (InputStream is = Files.newInputStream(file.toPath())) {
        byte[] buffer = new byte[8192];
        int read;
        while ((read = is.read(buffer)) > 0) {
            md.update(buffer, 0, read);
        }
    }
    return bytesToHex(md.digest());
}`,
  },
  {
    id: "C-02",
    severity: "Critical",
    title: "Hardcoded admin credentials in default Spring profile",
    location: "src/main/resources/application.properties (L~9721), src/main/resources/application-dev.properties (L~9691), src/main/resources/application.properties (spring.profiles.default=dev at L~9714)",
    description: "application.properties defaults to app.admin.password=${ADMIN_PASSWORD:admin123}. application-dev.properties hardcodes admin/admin123 in plain text. spring.profiles.default=dev means any deployment that omits SPRING_PROFILES_ACTIVE uses dev credentials. The DB password also defaults to 'password'.",
    impact: "Any deployment without explicit environment-variable overrides exposes the admin panel with a publicly known, trivially guessable credential. H2 console is also enabled.",
    remediation: `# application.properties — remove insecure fallbacks entirely
# Force explicit configuration; fail fast if missing
app.admin.username=\${ADMIN_USERNAME}
app.admin.password=\${ADMIN_PASSWORD}
spring.datasource.password=\${DB_PASSWORD}

# Do NOT ship a default active profile; require explicit activation
# Remove: spring.profiles.default=dev

# application-dev.properties — use a pre-hashed bcrypt value
app.admin.username=dev-admin
app.admin.password={bcrypt}\$2a\$12\$randomsalthere/hashedpassword

# Startup validation bean to fail fast
@Component
public class CredentialValidator {
    @Value("\${app.admin.password}") String pw;
    @PostConstruct
    public void validate() {
        if (pw.equals("admin123") || pw.equals("password"))
            throw new IllegalStateException("Insecure default credentials detected — refusing to start");
    }
}`,
  },
  {
    id: "C-03",
    severity: "Critical",
    title: "Credentials stored as Base64 in sessionStorage (effectively plaintext)",
    location: "frontend/src/context/AuthContext.js (~L26-29), frontend/src/api/client.js (~L22-32)",
    description: "The login flow calls btoa(username + ':' + password) and stores the result in sessionStorage under 'auth_token'. Base64 is an encoding, not encryption. Any XSS payload, browser extension, or malicious script on the page can call atob(sessionStorage.getItem('auth_token')) and recover the plaintext password instantly. client.js also falls back to reading VITE_API_USERNAME/PASSWORD from the compiled bundle.",
    impact: "Credential theft via XSS, browser extension, or compromised third-party script. Passwords are never safe in client-side JS storage.",
    remediation: `// AuthContext.js — store only a server-issued session token, not the password
const login = useCallback(async (username, password) => {
    try {
        // POST credentials to a /api/auth/login endpoint that returns
        // an opaque short-lived session token (not the password)
        const { data } = await axios.post('/api/auth/login',
            { username, password },
            { withCredentials: true }   // server sets HttpOnly cookie
        );
        // Store only a non-secret display value, never the password
        sessionStorage.setItem('auth_user', data.username);
        setUser(data.username);
        setIsAuthenticated(true);
        return { success: true };
    } catch (error) { /* ... */ }
}, []);

// On the Spring side: replace HTTP Basic with a proper session cookie
// SecurityConfig.java
http
    .formLogin(form -> form
        .loginProcessingUrl("/api/auth/login")
        .successHandler(jsonSuccessHandler())
        .failureHandler(jsonFailureHandler()))
    .logout(logout -> logout.logoutUrl("/api/auth/logout"))
    .sessionManagement(s -> s
        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
        .maximumSessions(1));`,
  },
  {
    id: "C-04",
    severity: "Critical",
    title: "CSRF protection globally disabled",
    location: "src/main/java/com/antivirus/config/SecurityConfig.java (~L35)",
    description: ".csrf(csrf -> csrf.disable()) disables Spring Security's CSRF token enforcement for all endpoints. An attacker can craft a malicious page that silently submits state-changing requests (quarantine, delete, system scan, firewall toggle) from any origin the victim visits while logged in.",
    impact: "Cross-site request forgery against all POST/DELETE endpoints including /quarantine, /delete, /scan/system, /firewall/toggle.",
    remediation: `// SecurityConfig.java — re-enable CSRF with cookie-based token
// (works with SPA clients that can read the XSRF-TOKEN cookie)
http
    .csrf(csrf -> csrf
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        .ignoringRequestMatchers("/actuator/health")
    )
    // ...

// frontend/src/api/client.js — send the token on mutating requests
client.interceptors.request.use((config) => {
    const csrfToken = document.cookie
        .split('; ')
        .find(row => row.startsWith('XSRF-TOKEN='))
        ?.split('=')[1];
    if (csrfToken && ['post','put','delete','patch']
            .includes(config.method?.toLowerCase())) {
        config.headers['X-XSRF-TOKEN'] = decodeURIComponent(csrfToken);
    }
    return config;
});`,
  },
  {
    id: "C-05",
    severity: "Critical",
    title: "Frontend API credentials compiled into the JS bundle",
    location: "frontend/.env.example (~L3-4), frontend/src/api/client.js (~L35-41), frontend/src/context/AuthContext.js (~L45-49)",
    description: "VITE_API_USERNAME and VITE_API_PASSWORD are Vite public env-vars — they are inlined into the compiled JS bundle at build time and are readable by any visitor using DevTools or by fetching the .js asset directly. AuthContext.js also calls login() with these values on page load if no session exists, meaning every page load sends the hardcoded credentials to the server.",
    impact: "Credentials visible to all users. An attacker extracts username/password from the JS bundle and authenticates independently.",
    remediation: `// Remove VITE_API_PASSWORD from all .env files entirely.
// Credentials must never live in the frontend bundle.

// frontend/src/context/AuthContext.js
// Remove the auto-login effect entirely:
// useEffect(() => {
//   if (!hasStoredSession() && VITE_API_USERNAME && VITE_API_PASSWORD) {
//     login(VITE_API_USERNAME, VITE_API_PASSWORD);  // <-- DELETE THIS
//   }
// }, [login]);

// Users must always provide credentials themselves through the Login form.
// VITE_API_URL is the only frontend env var that should exist.`,
  },
  {
    id: "H-01",
    severity: "High",
    title: "Absolute server file paths returned to clients in scan results",
    location: "src/main/java/com/antivirus/model/ScanResult.java (filePath field), src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java (~L8467)",
    description: "ScanResult.filePath stores the absolute server-side path (e.g. /tmp/scan_12345_malware.exe or /home/app/quarantine/...). This field is serialized and returned to the frontend in every scan response. It exposes the server's directory layout, OS type, username, and temp-file naming conventions to all authenticated users.",
    impact: "Information disclosure aids subsequent attacks (directory traversal, path prediction, privilege escalation planning).",
    remediation: `// ScanResult.java — add a display-safe field and @JsonIgnore the raw path
@Entity
public class ScanResult {
    @Column(nullable = false)
    @JsonIgnore              // never serialize raw absolute path
    private String filePath;

    @Transient
    @JsonProperty("fileName")
    public String getDisplayName() {
        if (filePath == null) return null;
        return Paths.get(filePath).getFileName().toString();
    }
}

// For scan history queries that need to re-locate files on disk,
// keep the raw path in the DB but never expose it in the API response.`,
  },
  {
    id: "H-02",
    severity: "High",
    title: "No rate limiting on authentication endpoint (brute-force possible)",
    location: "src/main/java/com/antivirus/config/SecurityConfig.java (entire file)",
    description: "Spring Security's httpBasic() is configured without any request throttling. An attacker can make unlimited login attempts per second, making dictionary and credential-stuffing attacks trivial against the single admin account.",
    impact: "Complete authentication bypass via brute-force or credential stuffing. A 6-character lowercase password is crackable in seconds.",
    remediation: `// Add spring-boot-starter-cache + Bucket4j (or resilience4j) to pom.xml
// SecurityConfig.java — add a per-IP rate-limit filter before auth
@Bean
public FilterRegistrationBean<RateLimitFilter> rateLimitFilter() {
    FilterRegistrationBean<RateLimitFilter> bean = new FilterRegistrationBean<>();
    bean.setFilter(new RateLimitFilter(10, Duration.ofMinutes(1)));
    bean.addUrlPatterns("/api/**");
    bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
    return bean;
}

// RateLimitFilter.java (simplified)
public class RateLimitFilter extends OncePerRequestFilter {
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final int capacity;
    private final Duration refillPeriod;

    @Override
    protected void doFilterInternal(HttpServletRequest req,
            HttpServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        String ip = req.getRemoteAddr();
        Bucket bucket = buckets.computeIfAbsent(ip, k ->
            Bucket.builder()
                .addLimit(Bandwidth.simple(capacity, refillPeriod))
                .build());
        if (bucket.tryConsume(1)) {
            chain.doFilter(req, res);
        } else {
            res.setStatus(429);
            res.getWriter().write("Too many requests");
        }
    }
}`,
  },
  {
    id: "H-03",
    severity: "High",
    title: "Unbounded system scan causes OOM and response DoS",
    location: "src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java — performSystemScan() (~L8592) and scanDirectory() (~L8643)",
    description: "performSystemScan() accumulates all ScanResult objects into a single in-memory ArrayList with no bound check. On a typical server with hundreds of thousands of files, this fills the JVM heap. Results are then returned in a single synchronous HTTP response. There is also no total scan-time limit.",
    impact: "A single POST /api/antivirus/scan/system call can exhaust JVM heap and crash the process, or produce a response so large it times out. Effectively a self-inflicted DoS.",
    remediation: `// Use a streaming/paginated approach — persist results as found, stream IDs
@PostMapping("/scan/system")
public ResponseEntity<Map<String, Object>> startSystemScan() {
    String jobId = UUID.randomUUID().toString();
    executor.submit(() -> securityService.performSystemScan(jobId));
    return ResponseEntity.accepted()
        .body(Map.of("jobId", jobId, "status", "STARTED",
                     "pollUrl", "/api/antivirus/scan/system/" + jobId + "/status"));
}

// SecurityServiceImpl — cap in-memory buffer, persist eagerly
private static final int SCAN_RESULT_FLUSH_BATCH = 200;
private static final int MAX_SCAN_RESULTS = 50_000;

// Inside scanDirectory recursion:
if (results.size() >= SCAN_RESULT_FLUSH_BATCH) {
    scanResultRepository.saveAll(results);
    results.clear();
}
if (scannedFiles.get() >= MAX_SCAN_RESULTS) {
    logger.warn("Scan result cap reached, stopping early");
    stopSystemScan.set(true);
    return;
}`,
  },
  {
    id: "H-04",
    severity: "High",
    title: "Port scanning blocks the HTTP request thread for up to 21 seconds",
    location: "src/main/java/com/antivirus/service/impl/NetworkSecurityServiceImpl.java — scanNetwork() (~L8062), isPortOpen() (~L8233), COMMON_PORTS array (~L8051)",
    description: "scanNetwork() scans 21 ports sequentially with a 1,000 ms connect timeout each. This is called synchronously on the Tomcat worker thread processing the API request. If all ports are closed the caller waits 21 seconds minimum; partially open networks can exceed 30 seconds. This blocks Tomcat threads from serving other requests.",
    impact: "2–3 concurrent POST /api/network-security/scan requests can exhaust Tomcat's default 200-thread pool, making the API unavailable for all users.",
    remediation: `// NetworkSecurityServiceImpl.java — parallel port scan with bounded concurrency
private static final ExecutorService PORT_SCAN_EXECUTOR =
    Executors.newFixedThreadPool(8, r -> {
        Thread t = new Thread(r, "port-scan");
        t.setDaemon(true);
        return t;
    });

private List<String> getOpenPorts() {
    List<CompletableFuture<Optional<String>>> futures =
        IntStream.of(COMMON_PORTS)
            .mapToObj(port -> CompletableFuture.supplyAsync(
                () -> isPortOpen("localhost", port)
                    ? Optional.of(String.valueOf(port))
                    : Optional.<String>empty(),
                PORT_SCAN_EXECUTOR))
            .toList();

    return futures.stream()
        .map(f -> {
            try { return f.get(2, TimeUnit.SECONDS); }
            catch (Exception e) { return Optional.<String>empty(); }
        })
        .filter(Optional::isPresent)
        .map(Optional::get)
        .toList();
}`,
  },
  {
    id: "H-05",
    severity: "High",
    title: "User-controlled filename embedded in temp-file suffix",
    location: "src/main/java/com/antivirus/controller/AntivirusController.java — scanFile() (~L5403)",
    description: "File.createTempFile(\"scan_\", \"_\" + file.getOriginalFilename()) passes the attacker-controlled original filename directly as the temp-file suffix. Java's createTempFile enforces no constraints on the suffix — an attacker sending a file named ../../../../etc/cron.d/payload or a 4096-character name can cause unexpected behavior or filesystem errors that leak information via the logged absolute path.",
    impact: "Directory traversal attempt in suffix, path-length exceptions, or information disclosure via error messages. Also affects createTempDirectory in scanDirectory().",
    remediation: `// AntivirusController.java — use a UUID-only suffix, never user input
@PostMapping("/scan/file")
public ResponseEntity<?> scanFile(@RequestParam("file") MultipartFile file) {
    // Validate content-type against a strict allowlist before touching the file
    String ct = file.getContentType();
    if (ct == null || !ALLOWED_CONTENT_TYPES.contains(ct)) {
        return ResponseEntity.badRequest().body("Unsupported file type");
    }

    // Never use user-supplied name in temp path
    Path tempFile = Files.createTempFile("scan_", "_" + UUID.randomUUID());
    try {
        file.transferTo(tempFile);
        ScanResult result = securityService.scanFile(tempFile.toFile());
        return ResponseEntity.ok(result);
    } finally {
        Files.deleteIfExists(tempFile);
    }
}

private static final Set<String> ALLOWED_CONTENT_TYPES = Set.of(
    "application/octet-stream", "application/pdf",
    "application/zip", "text/plain", "image/jpeg", "image/png"
    // extend as needed
);`,
  },
  {
    id: "H-06",
    severity: "High",
    title: "Missing HTTP security headers (CSP, HSTS, X-Frame-Options)",
    location: "src/main/java/com/antivirus/config/SecurityConfig.java (no header config present)",
    description: "The application returns no Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, or Referrer-Policy headers. This leaves the browser without guidance for mitigating XSS, clickjacking, MIME sniffing, and protocol downgrade attacks.",
    impact: "XSS via injected scripts, clickjacking against the dashboard, MIME sniffing exploits, and HTTP downgrade attacks.",
    remediation: `// SecurityConfig.java — add comprehensive security headers
http.headers(headers -> headers
    .contentSecurityPolicy(csp -> csp
        .policyDirectives(
            "default-src 'self'; " +
            "script-src 'self'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data:; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none';"
        ))
    .frameOptions(frame -> frame.deny())
    .contentTypeOptions(Customizer.withDefaults())
    .httpStrictTransportSecurity(hsts -> hsts
        .includeSubDomains(true)
        .maxAgeInSeconds(31536000))
    .referrerPolicy(ref -> ref
        .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
);`,
  },
  {
    id: "M-01",
    severity: "Medium",
    title: "Regex scanner uses .matches() (full-string), missing .find() semantics — high false-negative rate",
    location: "src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java — containsSuspiciousPatterns() (~L8680), MALICIOUS_PATTERNS (~L8412)",
    description: "containsSuspiciousPatterns() calls pattern.matcher(line).matches() which requires the ENTIRE line to match the regex. Patterns without leading/trailing .* (e.g. Pattern.compile(\"(?i).*\\\\bunescape\\\\b.*\")) will therefore never match. Conversely, patterns like '(?i).*decode.*' will trigger on any line containing the word 'decode' — including legitimate Java decoder calls — causing high false positives in benign JARs.",
    impact: "Both extremes: detection misses on real malware, plus false positives on clean files like jackson-databind, base64-utils, or any file containing 'exec' as a substring.",
    remediation: `// Use find() instead of matches() for substring-based detection
// And tighten patterns to reduce false positives

private static final List<Pattern> MALICIOUS_PATTERNS = List.of(
    // Use word boundaries and specific context to reduce FPs
    Pattern.compile("(?i)\\beval\\s*\\(\\s*(?:unescape|atob|String\\.fromCharCode)"),
    Pattern.compile("(?i)\\bshell_exec\\s*\\("),
    Pattern.compile("(?i)\\bRuntime\\.getRuntime\\(\\)\\.exec\\s*\\("),
    Pattern.compile("(?i)powershell[^\\n]{0,80}(?:-enc|-EncodedCommand|-w\\s+hidden)"),
    Pattern.compile("(?i)\\bkeylog(?:ger)?\\b")
    // ... use precise, context-aware patterns
);

private boolean containsSuspiciousPatterns(byte[] content) {
    String contentStr = new String(content, StandardCharsets.UTF_8);
    for (String line : contentStr.split("\\n")) {
        for (Pattern pattern : MALICIOUS_PATTERNS) {
            if (pattern.matcher(line).find()) {  // find(), not matches()
                logger.debug("Suspicious pattern matched: {}", pattern.pattern());
                return true;
            }
        }
    }
    return containsSuspiciousBytes(content);
}`,
  },
  {
    id: "M-02",
    severity: "Medium",
    title: "Files.readAllBytes() on files up to 100 MB — per-request OOM risk",
    location: "src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java — scanFile() (~L8500)",
    description: "scanFile() calls Files.readAllBytes(file.toPath()) on files up to the 100 MB limit, loading the entire file into a byte[] on the JVM heap. For directory scans, this happens per file inside the request thread. With the 100 MB upload limit and concurrent requests, this can exhaust heap memory.",
    impact: "OOM errors under concurrent scan load; potential service crash.",
    remediation: `// Stream through the file for pattern matching instead of loading all at once
private boolean containsSuspiciousPatterns(File file) throws IOException {
    long limit = 10 * 1024 * 1024L; // scan first 10 MB max
    try (InputStream is = new BufferedInputStream(
            new FileInputStream(file), 65536)) {
        byte[] buffer = new byte[65536];
        int read;
        long totalRead = 0;
        StringBuilder lineBuffer = new StringBuilder();
        while ((read = is.read(buffer)) != -1 && totalRead < limit) {
            totalRead += read;
            String chunk = new String(buffer, 0, read, StandardCharsets.UTF_8);
            lineBuffer.append(chunk);
            // Check accumulated content periodically
            if (checkPatterns(lineBuffer.toString())) return true;
            // Keep only the last partial line to avoid missing cross-boundary matches
            int lastNl = lineBuffer.lastIndexOf("\\n");
            if (lastNl > 0) lineBuffer.delete(0, lastNl);
        }
        return checkBinaryHeader(file);
    }
}`,
  },
  {
    id: "M-03",
    severity: "Medium",
    title: "ZIP scanner has no decompression-bomb protection",
    location: "src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java — containsMaliciousZipContent() (~L8568)",
    description: "containsMaliciousZipContent() iterates ZipEntry objects but never limits total decompressed size or entry count. A ZIP bomb (e.g. 42.zip: 42 KB compressed → 4.5 PB decompressed) would cause the calling thread to read ZipEntry metadata indefinitely — and if any code reads entry contents, it would exhaust memory.",
    impact: "DoS via crafted ZIP archive. Scan endpoint hangs indefinitely or crashes the JVM.",
    remediation: `private static final int MAX_ZIP_ENTRIES = 1000;
private static final long MAX_UNCOMPRESSED_SIZE = 500 * 1024 * 1024L; // 500 MB

private boolean containsMaliciousZipContent(File file) {
    int entryCount = 0;
    long totalUncompressed = 0;

    try (ZipInputStream zis = new ZipInputStream(
            new BufferedInputStream(new FileInputStream(file)))) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            entryCount++;
            if (entryCount > MAX_ZIP_ENTRIES) {
                logger.warn("ZIP bomb suspected: entry count exceeds {}", MAX_ZIP_ENTRIES);
                return true;
            }
            totalUncompressed += entry.getSize();
            if (totalUncompressed > MAX_UNCOMPRESSED_SIZE) {
                logger.warn("ZIP bomb suspected: uncompressed size exceeds {} bytes", MAX_UNCOMPRESSED_SIZE);
                return true;
            }
            if (SUSPICIOUS_EXTENSIONS.contains(
                    getFileExtension(new File(entry.getName())))) {
                return true;
            }
            zis.closeEntry();
        }
    } catch (Exception e) {
        return false;
    }
    return false;
}`,
  },
  {
    id: "M-04",
    severity: "Medium",
    title: "Insecure Direct Object Reference on quarantine and delete endpoints",
    location: "src/main/java/com/antivirus/controller/AntivirusController.java — /quarantine (~L5507), /delete (~L5513); SecurityServiceImpl.java — loadInfectedScanResult() (~L8794)",
    description: "Both endpoints accept a scanResultId query parameter and only verify that the record is marked infected — there is no check that the authenticated user owns or is authorized to act on that specific record. Since there is only one admin role, all admin users can quarantine or delete any scan result by guessing or enumerating IDs.",
    impact: "Authenticated users can destroy or move any scan record. In a multi-tenant deployment this would be a full IDOR.",
    remediation: `// AntivirusController.java — log the actor for audit purposes
@PostMapping("/quarantine")
public ResponseEntity<Void> quarantineFile(
        @RequestParam Long scanResultId,
        Authentication auth) {
    logger.info("Quarantine requested for scanResultId={} by user={}",
        scanResultId, auth.getName());
    securityService.quarantineScanResult(scanResultId);
    return ResponseEntity.ok().build();
}

// For future multi-user scenarios, check ownership in loadInfectedScanResult:
private ScanResult loadInfectedScanResult(Long id, String requestingUser) {
    ScanResult result = scanResultRepository.findById(id)
        .orElseThrow(() -> new ResponseStatusException(NOT_FOUND));
    if (!result.getOwner().equals(requestingUser))
        throw new ResponseStatusException(FORBIDDEN, "Not your scan result");
    if (!result.isInfected())
        throw new ResponseStatusException(FORBIDDEN, "File is not infected");
    return result;
}`,
  },
  {
    id: "M-05",
    severity: "Medium",
    title: "Log file grows without bound — no size limit or rotation",
    location: "src/main/java/com/antivirus/service/LogService.java — logScanResult() (~L7024)",
    description: "Every call to logScanResult() appends a Base64-encoded JSON record to logs/scan_history.log with no cap on file size and no log rotation. A busy scanning environment can produce thousands of records per hour. In addition, the log file is Base64-encoded but not encrypted — it stores full file paths, threat details, and timestamps on disk without access controls.",
    impact: "Disk exhaustion, DoS through log flooding. Sensitive path information persisted indefinitely.",
    remediation: `// Use SLF4J/Logback's built-in rolling policy instead of manual file writes.
// application.properties:
logging.file.name=logs/scan-history.log
logging.logback.rollingpolicy.max-file-size=10MB
logging.logback.rollingpolicy.max-history=7
logging.logback.rollingpolicy.total-size-cap=100MB

// LogService.java — replace manual file I/O with a dedicated logger
@Service
public class LogService {
    // Use a separate named logger for structured audit events
    private static final Logger auditLog =
        LoggerFactory.getLogger("com.antivirus.audit");

    public void logScanResult(ScanResult result) {
        if (result == null) return;
        // Log only non-sensitive summary fields — never raw file paths
        auditLog.info("scan_result type={} infected={} action={}",
            result.getThreatType(), result.isInfected(), result.getActionTaken());
    }
}`,
  },
  {
    id: "M-06",
    severity: "Medium",
    title: "Background monitoring thread bypasses Spring lifecycle management",
    location: "src/main/java/com/antivirus/service/impl/NetworkSecurityServiceImpl.java — startNetworkMonitoring() (~L8205)",
    description: "startNetworkMonitoring() creates a raw daemon Thread with a while(true) loop. This thread is invisible to Spring's task scheduler, cannot be monitored, and is not subject to graceful shutdown. If an unchecked exception escapes the loop body (other than InterruptedException), the thread dies silently and monitoring stops without any alert.",
    impact: "Silent monitoring failure; thread leak on application restart in a non-graceful shutdown; no testability.",
    remediation: `// NetworkSecurityServiceImpl.java — replace with @Scheduled
// Remove startNetworkMonitoring() and its @PostConstruct call.

@Scheduled(fixedDelay = 5000, initialDelay = 5000)
public void scheduledNetworkMonitor() {
    try {
        updateActiveConnections(getCurrentActiveConnections());
        checkSuspiciousActivities();
        cleanupOldConnections();
    } catch (Exception e) {
        // Spring's scheduler will restart on next tick; log and continue
        logger.error("Network monitor tick failed", e);
    }
}

// AntivirusApplication.java — already has @EnableScheduling, no change needed`,
  },
  {
    id: "L-01",
    severity: "Low",
    title: "authenticateUser() and authorizeUser() always return false — dead security code",
    location: "src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java (~L8456-8462)",
    description: "Both SecurityService interface methods are implemented as return false. They are declared as part of the X.800 security architecture but are never called for actual access control — everything relies on Spring Security. While not directly exploitable, this creates a false impression of a working service-layer auth mechanism and confusion for future developers.",
    impact: "Code confusion, maintainability risk, potential for future code to incorrectly rely on these methods.",
    remediation: `// Either implement properly or remove from the interface.
// Option A — delegate to Spring Security context:
@Override
public boolean authenticateUser(String username, String password) {
    try {
        Authentication auth = authManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password));
        return auth.isAuthenticated();
    } catch (AuthenticationException e) {
        return false;
    }
}

// Option B — remove from the SecurityService interface entirely
// and delete both stub implementations.`,
  },
  {
    id: "L-02",
    severity: "Low",
    title: "manifest.json leaks technology fingerprint",
    location: "frontend/public/manifest.json (entire file)",
    description: "The manifest still contains the default Create React App template strings: short_name: 'React App', name: 'Create React App Sample'. This reveals the underlying framework and toolchain to any reconnaissance scan.",
    impact: "Low-level information disclosure useful in fingerprinting for targeted CVE exploitation.",
    remediation: `{
  "short_name": "Antivirus",
  "name": "Antivirus Security Dashboard",
  "icons": [
    { "src": "favicon.ico", "sizes": "64x64 32x32 24x24 16x16", "type": "image/x-icon" }
  ],
  "start_url": ".",
  "display": "standalone",
  "theme_color": "#000000",
  "background_color": "#ffffff"
}`,
  },
  {
    id: "L-03",
    severity: "Low",
    title: "@SuppressWarnings(\"null\") on security-critical code paths",
    location: "src/main/java/com/antivirus/controller/AntivirusController.java (~L5393, L5486)",
    description: "@SuppressWarnings(\"null\") is applied to both scanFile() and scanDirectory(), suppressing the compiler's null-safety analysis. These are the primary entry points for user file uploads. Ignoring null warnings here can hide NPE paths where MultipartFile.getOriginalFilename() returns null.",
    impact: "Hidden NullPointerExceptions; null filenames can slip through and cause unexpected behavior in PathSecurityUtil or temp-file creation.",
    remediation: `// Remove @SuppressWarnings("null") and handle nulls explicitly
@PostMapping("/scan/file")
public ResponseEntity<?> scanFile(@RequestParam("file") MultipartFile file) {
    if (file == null || file.isEmpty()) {
        return ResponseEntity.badRequest().body("No file provided");
    }

    String originalFilename = file.getOriginalFilename();
    if (originalFilename == null || originalFilename.isBlank()) {
        return ResponseEntity.badRequest().body("File has no name");
    }

    // proceed with validated, non-null filename
}`,
  },
  {
    id: "L-04",
    severity: "Low",
    title: "robots.txt allows all crawlers, including vulnerability scanners",
    location: "frontend/public/robots.txt",
    description: "The robots.txt has Disallow: (empty), which means all paths are allowed for all crawlers. For a security-sensitive admin dashboard that should only be accessible to known users, this provides zero friction to automated scanners.",
    impact: "Minor — automated scanners will freely discover API paths and endpoints, assisting reconnaissance.",
    remediation: `# frontend/public/robots.txt
User-agent: *
Disallow: /
# The dashboard is a private tool, not a public website.`,
  },
];

const SEVERITY_CONFIG = {
  Critical: { color: "#A32D2D", bg: "#FCEBEB", border: "#F09595", icon: "ti-shield-x" },
  High: { color: "#854F0B", bg: "#FAEEDA", border: "#EF9F27", icon: "ti-alert-triangle" },
  Medium: { color: "#185FA5", bg: "#E6F1FB", border: "#85B7EB", icon: "ti-alert-circle" },
  Low: { color: "#3B6D11", bg: "#EAF3DE", border: "#97C459", icon: "ti-info-circle" },
};

const counts = findings.reduce((acc, f) => {
  acc[f.severity] = (acc[f.severity] || 0) + 1;
  return acc;
}, {});

function Badge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity];
  return (
    <span style={{
      background: cfg.bg,
      color: cfg.color,
      border: `0.5px solid ${cfg.border}`,
      borderRadius: 6,
      fontSize: 11,
      fontWeight: 500,
      padding: "2px 8px",
      whiteSpace: "nowrap",
    }}>
      {severity}
    </span>
  );
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(false);
  const cfg = SEVERITY_CONFIG[f.severity];
  return (
    <div style={{
      background: "var(--color-background-primary)",
      border: `0.5px solid var(--color-border-tertiary)`,
      borderLeft: `3px solid ${cfg.border}`,
      borderRadius: 10,
      marginBottom: 8,
      overflow: "hidden",
    }}>
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          width: "100%",
          background: "none",
          border: "none",
          padding: "12px 16px",
          cursor: "pointer",
          textAlign: "left",
        }}
      >
        <span style={{
          fontFamily: "var(--font-mono)",
          fontSize: 11,
          color: cfg.color,
          fontWeight: 500,
          minWidth: 38,
        }}>{f.id}</span>
        <Badge severity={f.severity} />
        <span style={{
          flex: 1,
          fontSize: 14,
          fontWeight: 500,
          color: "var(--color-text-primary)",
          marginLeft: 4,
        }}>{f.title}</span>
        <i className={`ti ${open ? "ti-chevron-up" : "ti-chevron-down"}`}
          style={{ fontSize: 16, color: "var(--color-text-secondary)", flexShrink: 0 }}
          aria-hidden="true" />
      </button>

      {open && (
        <div style={{ padding: "0 16px 16px", borderTop: "0.5px solid var(--color-border-tertiary)" }}>
          <Section label="Location">
            <code style={{
              fontSize: 12,
              background: "var(--color-background-secondary)",
              padding: "6px 10px",
              borderRadius: 6,
              display: "block",
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              color: "var(--color-text-secondary)",
            }}>{f.location}</code>
          </Section>
          <Section label="Description">
            <p style={{ margin: 0, fontSize: 14, color: "var(--color-text-secondary)", lineHeight: 1.65 }}>{f.description}</p>
          </Section>
          <Section label="Impact">
            <p style={{ margin: 0, fontSize: 14, color: cfg.color, lineHeight: 1.65, fontWeight: 500 }}>{f.impact}</p>
          </Section>
          <Section label="Remediation">
            <pre style={{
              margin: 0,
              fontSize: 12,
              background: "var(--color-background-secondary)",
              padding: "12px 14px",
              borderRadius: 8,
              overflow: "auto",
              whiteSpace: "pre",
              color: "var(--color-text-primary)",
              lineHeight: 1.6,
              fontFamily: "var(--font-mono)",
            }}>{f.remediation}</pre>
          </Section>
        </div>
      )}
    </div>
  );
}

function Section({ label, children }) {
  return (
    <div style={{ marginTop: 12 }}>
      <p style={{
        margin: "0 0 6px",
        fontSize: 11,
        fontWeight: 500,
        color: "var(--color-text-tertiary)",
        textTransform: "uppercase",
        letterSpacing: "0.06em",
      }}>{label}</p>
      {children}
    </div>
  );
}

export default function AuditReport() {
  const [filter, setFilter] = useState("All");
  const categories = ["All", "Critical", "High", "Medium", "Low"];

  const visible = filter === "All"
    ? findings
    : findings.filter(f => f.severity === filter);

  return (
    <div style={{ padding: "1.5rem 0", maxWidth: 720, margin: "0 auto" }}>
      <h2 className="sr-only" style={{ position: "absolute", width: 1, height: 1, overflow: "hidden" }}>
        Security audit report for dhruv0306/antivirus — 22 findings across 4 severity levels
      </h2>

      <div style={{ marginBottom: "1.5rem" }}>
        <p style={{ margin: "0 0 4px", fontSize: 11, fontWeight: 500, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Application security audit</p>
        <p style={{ margin: "0 0 1rem", fontSize: 20, fontWeight: 500, color: "var(--color-text-primary)" }}>dhruv0306 / antivirus</p>
        <p style={{ margin: 0, fontSize: 13, color: "var(--color-text-secondary)" }}>
          Spring Boot 3.4.5 backend + React 18 / Vite frontend &nbsp;·&nbsp; {findings.length} findings
        </p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: "1.5rem" }}>
        {["Critical", "High", "Medium", "Low"].map(s => {
          const cfg = SEVERITY_CONFIG[s];
          return (
            <div key={s} style={{
              background: cfg.bg,
              border: `0.5px solid ${cfg.border}`,
              borderRadius: 10,
              padding: "12px 14px",
            }}>
              <p style={{ margin: "0 0 2px", fontSize: 22, fontWeight: 500, color: cfg.color }}>{counts[s] || 0}</p>
              <p style={{ margin: 0, fontSize: 12, color: cfg.color }}>{s}</p>
            </div>
          );
        })}
      </div>

      <div style={{
        background: "var(--color-background-secondary)",
        border: "0.5px solid var(--color-border-tertiary)",
        borderRadius: 10,
        padding: "12px 16px",
        marginBottom: "1.5rem",
        fontSize: 13,
        lineHeight: 1.7,
        color: "var(--color-text-secondary)",
      }}>
        <strong style={{ color: "var(--color-text-primary)", fontWeight: 500 }}>Executive summary — </strong>
        The codebase has five critical issues that must be addressed before any production deployment.
        The most severe is a hash-algorithm mismatch that silently disables all virus-signature detection.
        Authentication relies on Base64-encoded credentials in sessionStorage with CSRF disabled and no rate
        limiting, creating a trivially exploitable auth surface. The dev Spring profile is the default,
        meaning any deployment without an explicit environment override ships with well-known credentials
        and an exposed H2 console. Seven high-severity issues follow, covering information disclosure,
        resource exhaustion, and missing browser security headers. Six medium and four low findings
        cover detection reliability, OOM risks, and code quality. Every finding below includes an exact
        remediation with corrected code.
      </div>

      <div style={{ display: "flex", gap: 6, marginBottom: "1rem", flexWrap: "wrap" }}>
        {categories.map(c => {
          const active = filter === c;
          const cfg = c !== "All" ? SEVERITY_CONFIG[c] : null;
          return (
            <button
              key={c}
              onClick={() => setFilter(c)}
              style={{
                padding: "4px 12px",
                fontSize: 12,
                fontWeight: 500,
                borderRadius: 20,
                border: active
                  ? `1.5px solid ${cfg ? cfg.border : "var(--color-border-primary)"}`
                  : "0.5px solid var(--color-border-tertiary)",
                background: active && cfg ? cfg.bg : "var(--color-background-primary)",
                color: active && cfg ? cfg.color : "var(--color-text-secondary)",
                cursor: "pointer",
              }}
            >
              {c}{c !== "All" ? ` (${counts[c] || 0})` : ` (${findings.length})`}
            </button>
          );
        })}
      </div>

      <div>
        {visible.map(f => <FindingCard key={f.id} f={f} />)}
      </div>

      <div style={{
        marginTop: "2rem",
        borderTop: "0.5px solid var(--color-border-tertiary)",
        paddingTop: "1rem",
        fontSize: 12,
        color: "var(--color-text-tertiary)",
      }}>
        Click any finding to expand the description, impact, and remediation code.
      </div>
    </div>
  );
}