import { useState } from "react";

const remaining = [
  {
    id: "S-01",
    severity: "Low",
    title: "5 logger calls still use string concatenation (+) instead of SLF4J {} params",
    locations: [
      "DomainBlockingServiceImpl.java:L8394  — logger.error(\"...domain: \" + domain, e)",
      "DomainBlockingServiceImpl.java:L8415  — logger.error(\"...domain: \" + normalizedDomain, e)",
      "SecurityServiceImpl.java:L9897       — logger.error(\"...file: \" + file.getName(), e)",
      "SecurityServiceImpl.java:L9943       — logger.warn(\"...found in \" + file.getName())",
      "SecurityServiceImpl.java:L9954       — logger.error(\"...for file: \" + file.getName(), e)",
    ],
    fix: `// Replace every + concatenation with {} placeholders — five changes:
// DomainBlockingServiceImpl.java L8394
logger.error("Failed to update hosts file for domain: {}", domain, e);
// DomainBlockingServiceImpl.java L8415
logger.error("Failed to update hosts file while unblocking domain: {}", normalizedDomain, e);
// SecurityServiceImpl.java L9897
logger.error("Error during malware detection for file: {}", file.getName(), e);
// SecurityServiceImpl.java L9943
logger.warn("Potential rootkit detected: Kernel manipulation pattern found in {}", file.getName());
// SecurityServiceImpl.java L9954
logger.error("Error during rootkit detection for file: {}", file.getName(), e);`,
  },
  {
    id: "S-02",
    severity: "Medium",
    title: "LogService.readAllLogLines() loads all 8 rotating log files into heap — up to 80 MB per /history call",
    locations: ["LogService.java — readAllLogLines() (~L7513)"],
    fix: `// LogService.java — read only the CURRENT log file tail; skip backups.
// getLastFiveScanResults() only needs 5 entries; there is no reason to
// load all 7 backups for them.
private List<String> readAllLogLines() throws IOException {
    List<String> lines = new ArrayList<>();
    Path currentLog = Paths.get(LOG_DIRECTORY).resolve(LOG_FILE);

    // Read current log only — if it has fewer than 5 entries, that is fine.
    if (Files.exists(currentLog)) {
        lines = Files.readAllLines(currentLog, StandardCharsets.UTF_8);
    }

    // Only fall back to the most-recent backup if current log is empty.
    if (lines.isEmpty()) {
        Path backup = currentLog.resolveSibling(LOG_FILE + ".1");
        if (Files.exists(backup)) {
            lines = Files.readAllLines(backup, StandardCharsets.UTF_8);
        }
    }
    return lines;
}`,
  },
  {
    id: "S-03",
    severity: "Medium",
    title: "hasRansomwareBehavior() calls parentDir.listFiles() for every scanned file — O(n²) on large directories",
    locations: ["SecurityServiceImpl.java — hasRansomwareBehavior() (~L9810)"],
    fix: `// SecurityServiceImpl.java — cache the directory listing per scan invocation.
// Add to the class:
private final ThreadLocal<Map<String, File[]>> dirListingCache =
    ThreadLocal.withInitial(HashMap::new);

private boolean hasRansomwareBehavior(File file) {
    File parentDir = file.getParentFile();
    if (parentDir == null || !parentDir.exists()) return false;

    // Use cached listing — ONE listFiles() call per directory, not per file.
    File[] files = dirListingCache.get()
        .computeIfAbsent(parentDir.getAbsolutePath(), k -> parentDir.listFiles());
    if (files == null) return false;

    int encryptedCount = 0;
    boolean hasRansomNote = false;
    for (File f : files) {
        String name = f.getName().toLowerCase();
        if ((name.contains("readme") && name.contains("txt")) ||
                name.contains("how_to_decrypt") ||
                name.contains("recovery") ||
                name.contains("help_decrypt")) {
            hasRansomNote = true;
        }
        String ext = getFileExtension(f).toLowerCase();
        if (ext.length() > 4 && !ext.equals(".jpeg") && !ext.equals(".html")) {
            encryptedCount++;
        }
    }
    return hasRansomNote && encryptedCount > 5;
}

// Clear the cache before each scanDirectory(String, boolean) call:
// At the top of scanDirectory(String, boolean):
dirListingCache.get().clear();
// In the finally block:
dirListingCache.remove();`,
  },
  {
    id: "S-04",
    severity: "Low",
    title: "scanDirectory(String, boolean) walks the filesystem tree twice — doubles I/O",
    locations: ["SecurityServiceImpl.java — scanDirectory(String, boolean) (~L9982, L9989)"],
    fix: `// Remove the first Files.walk() count pass entirely.
// Track progress with the atomic counter in the forEach instead.

// DELETE these lines (~L9982-9989):
// try (Stream<Path> paths = recursive ? Files.walk(dir) : Files.list(dir)) {
//     totalFiles.set((int) paths.filter(...).count());
// }

// In the SECOND walk's forEach, update progress relative to scanned count:
int processed = processedFiles.incrementAndGet();
if (processed % 50 == 0) {
    logger.info("Scanned {} files, {} infected so far", processed, infectedFiles.get());
}
// Remove the logProgress(processed, totalFiles.get(), ...) calls that need totalFiles.`,
  },
  {
    id: "S-05",
    severity: "Low",
    title: "application-prod.properties CORS fallback still lists localhost dev origins",
    locations: ["application-prod.properties (~L10404)"],
    fix: `# application-prod.properties — no localhost fallback in production.
# If CORS_ALLOWED_ORIGINS is unset, fail fast rather than accepting dev origins.
app.cors.allowed-origins=\${CORS_ALLOWED_ORIGINS}

# Add to SecurityConfig.java @PostConstruct:
@PostConstruct
public void validateConfig() {
    if (allowedOrigins == null || allowedOrigins.isBlank()
            || allowedOrigins.contains("localhost")) {
        throw new IllegalStateException(
            "CORS_ALLOWED_ORIGINS must be set to a real domain in production " +
            "(e.g. https://app.example.com). Do not use localhost.");
    }
}`,
  },
  {
    id: "S-06",
    severity: "Low",
    title: "application-local.properties: H2 AUTO_SERVER=TRUE opens unauthenticated TCP port; empty DB password",
    locations: ["application-local.properties (~L10333)"],
    fix: `# application-local.properties — remove AUTO_SERVER=TRUE and set a local password.
# Use /h2-console (already enabled) to access the DB in a browser instead.
spring.datasource.url=jdbc:h2:file:./data/antivirus_local;MODE=PostgreSQL
spring.datasource.username=sa
spring.datasource.password=localdevonly   # any non-empty value prevents unauthenticated TCP access`,
  },
];

const SEVERITY = {
  Medium: { color: "#185FA5", bg: "#E6F1FB", border: "#85B7EB" },
  Low:    { color: "#3B6D11", bg: "#EAF3DE", border: "#97C459" },
};

function Card({ f }) {
  const [open, setOpen] = useState(false);
  const c = SEVERITY[f.severity];
  return (
    <div style={{ background: "var(--color-background-primary)", border: "0.5px solid var(--color-border-tertiary)", borderLeft: `3px solid ${c.border}`, borderRadius: 10, marginBottom: 8, overflow: "hidden" }}>
      <button onClick={() => setOpen(v => !v)} style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", background: "none", border: "none", padding: "11px 16px", cursor: "pointer", textAlign: "left" }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: c.color, fontWeight: 700, minWidth: 38 }}>{f.id}</span>
        <span style={{ background: c.bg, color: c.color, border: `0.5px solid ${c.border}`, borderRadius: 6, fontSize: 11, fontWeight: 500, padding: "2px 8px" }}>{f.severity}</span>
        <span style={{ flex: 1, fontSize: 13, fontWeight: 500, color: "var(--color-text-primary)", marginLeft: 4 }}>{f.title}</span>
        <i className={`ti ${open ? "ti-chevron-up" : "ti-chevron-down"}`} style={{ fontSize: 15, color: "var(--color-text-secondary)", flexShrink: 0 }} />
      </button>
      {open && (
        <div style={{ padding: "0 16px 16px", borderTop: "0.5px solid var(--color-border-tertiary)" }}>
          <div style={{ marginTop: 12 }}>
            <p style={{ margin: "0 0 5px", fontSize: 10, fontWeight: 700, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.07em" }}>Locations</p>
            {f.locations.map((l, i) => <code key={i} style={{ fontSize: 12, background: "var(--color-background-secondary)", padding: "4px 10px", borderRadius: 5, display: "block", marginBottom: 3, color: "var(--color-text-secondary)", fontFamily: "var(--font-mono)", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{l}</code>)}
          </div>
          <div style={{ marginTop: 12 }}>
            <p style={{ margin: "0 0 5px", fontSize: 10, fontWeight: 700, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.07em" }}>Fix</p>
            <pre style={{ margin: 0, fontSize: 12, background: "var(--color-background-secondary)", padding: "11px 14px", borderRadius: 8, overflow: "auto", whiteSpace: "pre", color: "var(--color-text-primary)", lineHeight: 1.6, fontFamily: "var(--font-mono)" }}>{f.fix}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

const commitMessage = `security: apply all audit remediations across 5 rounds (Parts 1–5)

════════════════════════════════════════════════════════════════════
CRITICAL — Authentication & credential overhaul
════════════════════════════════════════════════════════════════════
C-01  Fix hash-algorithm mismatch: KNOWN_MALWARE_SIGNATURES and
      calculateFileHash() now consistently use SHA-256 (64-char hex).
      Previous MD5 mismatch silently disabled all signature detection.
C-02  Remove hardcoded admin credentials: all profiles now require
      explicit ADMIN_USERNAME / ADMIN_PASSWORD env vars with no
      fallback; startup fails if defaults are detected.
C-03  Replace Base64 sessionStorage auth with CSRF-token form login.
      Only the display username is stored; credentials never touch
      client-side storage.
C-04  Re-enable CSRF protection using CookieCsrfTokenRepository;
      CSRF token sent on all mutating requests via Axios interceptor.
C-05  Remove VITE_API_PASSWORD and VITE_API_USERNAME from all .env
      files and the compiled frontend bundle entirely.

════════════════════════════════════════════════════════════════════
HIGH — Information disclosure, DoS, input handling
════════════════════════════════════════════════════════════════════
H-01  Add @JsonIgnore to ScanResult.getFilePath(); expose only
      getFileName() (display-safe) in API responses.
H-02  Add per-IP+username rate limiter (Caffeine, 10 req/min) on
      POST /api/auth/login at Ordered.HIGHEST_PRECEDENCE.
H-03  Cap system scan at MAX_SYSTEM_SCAN_RESULTS=2000 and 5-minute
      deadline; AtomicBoolean guards against concurrent runs.
H-04  Parallelise port scan: PORT_SCAN_EXECUTOR (8 threads) with
      CompletableFuture and 2-second per-port timeout.
H-05  Temp file suffix now uses UUID only; ALLOWED_CONTENT_TYPES
      allowlist enforced before any disk write.
H-06  Add full security header suite: CSP, HSTS (1 yr, includeSubDomains),
      X-Frame-Options: DENY, X-Content-Type-Options, Referrer-Policy.
H-07  Replace raw axios + hardcoded localhost URLs in NetworkSecurity.js
      with shared authenticated antivirusApi / networkSecurityApi client.
H-08  Replace all exception.getMessage() in API responses with
      SAFE_ERROR_MESSAGES map (opaque codes only).
H-09  Remove @Transactional from performSystemScan(); saveResultsInBatches()
      persists in batches of 100 after scan completes.

════════════════════════════════════════════════════════════════════
MEDIUM — Scanner reliability, resource exhaustion, session security
════════════════════════════════════════════════════════════════════
M-01  Fix pattern scanner: .find() replaces .matches() for substring
      detection; MALICIOUS_PATTERNS tightened with word boundaries.
M-02  Cap file reads at MAX_PATTERN_SCAN_BYTES (10 MB) using a
      streaming BufferedReader window in containsSuspiciousPatterns().
M-03  Add ZIP-bomb guards: MAX_ZIP_ENTRIES=1000,
      MAX_ZIP_UNCOMPRESSED_BYTES=500 MB.
M-04  loadInfectedScanResult() enforces owner equality check;
      quarantine and delete endpoints log the actor identity.
M-05  LogService: MAX_LOG_FILE_SIZE_BYTES=10 MB with 7-backup
      rolling rotation via Files.move().
M-06  Replace background raw Thread in network monitor with
      @Scheduled(fixedDelay=5000); Spring manages lifecycle.
M-07  Set ddl-auto=none (base/prod) and validate (prod) with
      ddl-auto=update restricted to dev profile only.
M-08  Add AbortController to all polling useEffect hooks; clearInterval
      on unmount prevents state updates on unmounted components.
M-09  Add logger.js utility that noops in production; configure Vite
      esbuild.drop=['console','debugger'] in production mode.
M-10  Centralise error mapping in errors.js toUserMessage(); all
      components use it — raw server strings no longer reach the UI.

════════════════════════════════════════════════════════════════════
NETWORK SECURITY — Proxy, rate-limiter, CSRF, DNS
════════════════════════════════════════════════════════════════════
N-01  resolveRateLimitKey(): only trust X-Forwarded-For from
      explicitly configured TRUSTED_PROXY_IPS; prevents rate-limit bypass.
N-02  DnsDomainBlockingService: write dnsmasq address= directives to
      /etc/dnsmasq.d/ instead of clobbering /etc/resolv.conf nameservers.
N-03  Proxy SSRF guard: isPrivateOrLoopback() blocks CONNECT to
      127.x, RFC-1918, link-local, and unresolvable hosts.
N-04  CSRF token kept in runtimeCsrf (in-memory only); sessionStorage
      writes removed entirely to prevent XSS token theft.
N-05  Replace unbounded ConcurrentHashMap with Caffeine cache
      (maximumSize=50,000, expireAfterWrite=2 min) for attempt windows.
N-06  Proxy relay(): replace raw Thread creation with managed
      relayExecutor (CachedThreadPool) for proper lifecycle control.
N-07  SystemScan.js elevation path uses hardcoded safe message;
      catch block always calls toUserMessage(err) — no raw data.message.
N-08  getCurrentActiveConnections() uses ss/netstat for real TCP
      connection counts instead of returning interface address size.

════════════════════════════════════════════════════════════════════
CODE QUALITY / REGRESSION FIXES
════════════════════════════════════════════════════════════════════
O-01/ DomainBlockingServiceImpl constructor: set hasAdminPrivileges
R-01  via canModifyHostsFile() directly, not via isAdmin(), fixing
      bootstrap circular-read that permanently disabled hosts blocking.
O-02  Remove @SuppressWarnings("null") from AntivirusController
      upload handlers; use explicit Objects.requireNonNull() guards.
O-04  toggleFirewall/toggleWebProtection: Math.max(0, v-1) prevents
      activeThreats counter underflow to negative values.
O-05  LogService.logScanResult(): log result.getFileName() not
      getFilePath() to avoid absolute paths in debug output.
R-02  Remove hasSuspiciousNetworkBehavior(); detectTrojan() now
      delegates to containsSuspiciousPatterns() — eliminates ~100%
      false-positive rate on config/source/HTML files.
R-03  detectRansomware() and detectTrojan() delegate to bounded
      scanWithPatterns(); unbounded BufferedReader loops removed.
R-04  KNOWN_MALWARE_SIGNATURES: HashSet replaced with
      ConcurrentHashMap.newKeySet() — eliminates race condition
      between concurrent scan threads and updateVirusDefinitions().
R-05  detectRootkit(): remove Files.isHidden() and zero-byte checks
      (flagged dotfiles and empty lock files as rootkits); exclude
      /proc/ and /sys/ via isFileExcluded() instead.
R-06  calculateFileHash(): MD5 → SHA-256; KNOWN_MALWARE_SIGNATURES
      updated to 64-char SHA-256 hashes.
R-07  Remove @SuppressWarnings("null") from saveScanResult() and
      loadInfectedScanResult() in SecurityServiceImpl.
R-08  updateVirusDefinitions(): return HTTP 501 NOT_IMPLEMENTED
      instead of silently adding a 26-char non-matching placeholder.

════════════════════════════════════════════════════════════════════
FRONTEND & BUILD PIPELINE
════════════════════════════════════════════════════════════════════
F-01  DirectoryScan.js catch block: replace manual error extraction
      with toUserMessage(err) — consistent with all other components.
F-02  Add OWASP Dependency-Check Maven plugin (failBuildOnCVSS=7)
      and owasp-suppressions.xml to build pipeline.
F-03  Add Flyway dependency; V1__initial_schema.sql migration created;
      prod uses ddl-auto=none with spring.flyway.enabled=true.
F-04  Dashboard.js: split single useEffect into two — status polling
      (no deps) and scan history (pagination deps); history now
      auto-loads on mount and on page/size change.
F-05  Dashboard.js: expose fetchStatus via triggerRefreshRef;
      remove duplicate fetchSystemStatus() without AbortController.
F-06  vite.config.js: use defineConfig(({ mode }) => ...) callback
      form so esbuild.drop is resolved from Vite's own mode flag.
L-02  manifest.json: replace Create React App template strings with
      "Antivirus Security Dashboard".
L-04  robots.txt: add Disallow: / to block all crawlers from the
      private admin dashboard.
L-06  H2 console: require ADMIN role via @Profile("dev") @Order(1)
      security chain; disabled in base and prod properties.

════════════════════════════════════════════════════════════════════
OUTSTANDING (tracked — not yet resolved)
════════════════════════════════════════════════════════════════════
S-01  LOW  : 5 logger calls still use + concatenation (should be {})
              SecurityServiceImpl L9897/9943/9954,
              DomainBlockingServiceImpl L8394/8415
S-02  MED  : LogService.readAllLogLines() loads all 8 backup files
              into heap (~80 MB); fix: read current log only
S-03  MED  : hasRansomwareBehavior() calls parentDir.listFiles()
              per file; fix: cache per-directory listing with ThreadLocal
S-04  LOW  : scanDirectory(String,boolean) walks tree twice;
              fix: remove count pass, track with AtomicInteger
S-05  LOW  : application-prod.properties CORS fallback lists
              localhost origins; fix: no fallback, fail-fast on blank
S-06  LOW  : application-local.properties AUTO_SERVER=TRUE and
              empty DB password; fix: remove flag, set local password`;

export default function FinalAudit() {
  const [tab, setTab] = useState("open");
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(commitMessage);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ padding: "1.5rem 0", maxWidth: 720, margin: "0 auto" }}>
      <div style={{ marginBottom: "1.5rem" }}>
        <p style={{ margin: "0 0 4px", fontSize: 11, fontWeight: 700, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.07em" }}>Security audit — final verification</p>
        <p style={{ margin: "0 0 0.5rem", fontSize: 20, fontWeight: 500, color: "var(--color-text-primary)" }}>dhruv0306 / antivirus — complete audit close-out</p>
        <p style={{ margin: 0, fontSize: 13, color: "var(--color-text-secondary)" }}>
          All Criticals & Highs resolved · 6 Low/Medium items remain · commit message ready
        </p>
      </div>

      {/* Summary tiles */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: "1.5rem" }}>
        {[
          { n: "37+", label: "Issues resolved", color: "#3B6D11", bg: "#EAF3DE", border: "#97C459" },
          { n: 6,     label: "Still open (Low/Med)", color: "#185FA5", bg: "#E6F1FB", border: "#85B7EB" },
          { n: 0,     label: "Criticals / Highs open", color: "#854F0B", bg: "#FAEEDA", border: "#EF9F27" },
        ].map(t => (
          <div key={t.label} style={{ background: t.bg, border: `0.5px solid ${t.border}`, borderRadius: 10, padding: "12px 14px" }}>
            <p style={{ margin: "0 0 2px", fontSize: 22, fontWeight: 500, color: t.color }}>{t.n}</p>
            <p style={{ margin: 0, fontSize: 12, color: t.color }}>{t.label}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", borderBottom: "0.5px solid var(--color-border-tertiary)", marginBottom: "1.5rem" }}>
        {[["open", "Remaining Open (6)"], ["commit", "Commit Message"]].map(([key, label]) => (
          <button key={key} onClick={() => setTab(key)} style={{ padding: "8px 14px", fontSize: 13, fontWeight: 500, background: "none", border: "none", borderBottom: tab === key ? "2px solid var(--color-text-primary)" : "2px solid transparent", color: tab === key ? "var(--color-text-primary)" : "var(--color-text-secondary)", cursor: "pointer", marginBottom: -1, whiteSpace: "nowrap" }}>
            {label}
          </button>
        ))}
      </div>

      {tab === "open" && (
        <div>
          <div style={{ background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: 10, padding: "11px 14px", marginBottom: "1.25rem", fontSize: 13, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
            <strong style={{ color: "var(--color-text-primary)" }}>No Criticals or Highs remain.</strong> The 6 items below are 4 Low and 2 Medium quality/performance issues. They do not block deployment but should be addressed in the next sprint before the codebase grows around them.
          </div>
          {remaining.map(f => <Card key={f.id} f={f} />)}
        </div>
      )}

      {tab === "commit" && (
        <div>
          <div style={{ background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: 10, padding: "11px 14px", marginBottom: "1rem", fontSize: 13, color: "var(--color-text-secondary)", lineHeight: 1.7, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span><strong style={{ color: "var(--color-text-primary)" }}>Merge commit for security/critical-fixes → main.</strong> Covers all 37+ resolved findings from audit Parts 1–5. Outstanding items listed in OUTSTANDING section.</span>
            <button onClick={handleCopy} style={{ flexShrink: 0, marginLeft: 12, padding: "6px 14px", fontSize: 12, fontWeight: 600, borderRadius: 8, border: "0.5px solid var(--color-border-primary)", background: copied ? "#EAF3DE" : "var(--color-background-primary)", color: copied ? "#3B6D11" : "var(--color-text-primary)", cursor: "pointer", whiteSpace: "nowrap" }}>
              {copied ? "✓ Copied" : "Copy"}
            </button>
          </div>
          <pre style={{ margin: 0, fontSize: 12, background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", padding: "14px 16px", borderRadius: 10, overflow: "auto", whiteSpace: "pre", color: "var(--color-text-primary)", lineHeight: 1.65, fontFamily: "var(--font-mono)" }}>{commitMessage}</pre>
        </div>
      )}

      <div style={{ marginTop: "2rem", borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: "1rem", fontSize: 12, color: "var(--color-text-tertiary)" }}>
        Final verification — expand remaining findings for exact line numbers and drop-in fixes. Commit message covers all resolved work across Parts 1–5.
      </div>
    </div>
  );
}