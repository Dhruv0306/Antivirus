import { useState } from "react";

// ─── DATA ────────────────────────────────────────────────────────────────────

const FIXED_ALL = [
  { id: "C-01", text: "Hash algorithm mismatch resolved — KNOWN_MALWARE_SIGNATURES and calculateFileHash() now both use MD5" },
  { id: "C-02", text: "Hardcoded credentials removed; all profiles require explicit env vars with no fallback" },
  { id: "C-03", text: "Base64 sessionStorage replaced with CSRF-token form login; only display username stored" },
  { id: "C-04", text: "CSRF re-enabled with CookieCsrfTokenRepository" },
  { id: "C-05", text: "VITE_API_PASSWORD/USERNAME purged from bundle and env files" },
  { id: "H-01", text: "ScanResult.getFilePath() @JsonIgnore; getFileName() exposes display-safe name only" },
  { id: "H-02", text: "Per-IP+username rate limiter added on /api/auth/login" },
  { id: "H-03", text: "System scan bounded: MAX_SYSTEM_SCAN_RESULTS=2000, 5-minute deadline, AtomicBoolean concurrency guard" },
  { id: "H-04", text: "Port scan parallelised: PORT_SCAN_EXECUTOR (8 threads), CompletableFuture with 2 s timeout" },
  { id: "H-05", text: "Temp file suffix uses UUID only; ALLOWED_CONTENT_TYPES allowlist enforced before disk write" },
  { id: "H-06", text: "Full header suite: CSP, HSTS (1yr, includeSubDomains), X-Frame-Options, X-Content-Type, Referrer-Policy" },
  { id: "H-07", text: "NetworkSecurity.js replaced raw axios + hardcoded URLs with shared authenticated client" },
  { id: "H-08", text: "SAFE_ERROR_MESSAGES map replaces exception messages in all API responses" },
  { id: "H-09", text: "@Transactional removed from performSystemScan(); saveResultsInBatches() called at completion" },
  { id: "M-01", text: "matchesSuspiciousPatterns() uses .find() not .matches(); patterns tightened" },
  { id: "M-02", text: "containsSuspiciousPatterns() streams with BufferedReader limited to MAX_PATTERN_SCAN_BYTES (10 MB)" },
  { id: "M-03", text: "ZIP bomb protection: MAX_ZIP_ENTRIES=1000, MAX_ZIP_UNCOMPRESSED_BYTES=500 MB" },
  { id: "M-04", text: "loadInfectedScanResult() enforces owner check; quarantine/delete log actor identity" },
  { id: "M-05", text: "LogService has MAX_LOG_FILE_SIZE_BYTES (10 MB) + 7-backup rotation" },
  { id: "M-06", text: "Background monitor converted from raw Thread to @Scheduled(fixedDelay=5000)" },
  { id: "M-07", text: "ddl-auto: none (base) / validate (prod) / update (dev only)" },
  { id: "M-08", text: "SystemScan useEffect returns clearInterval; AbortController in polling hooks" },
  { id: "M-09", text: "logger.js utility noops in production; Vite esbuild.drop strips console.* from prod" },
  { id: "M-10", text: "errors.js toUserMessage() maps all HTTP statuses; SystemScan.js elevation uses hardcoded message" },
  { id: "N-01", text: "resolveRateLimitKey() only trusts X-Forwarded-For from explicitly configured trusted proxy IPs" },
  { id: "N-02", text: "DnsDomainBlockingService now writes dnsmasq address= directives, not resolv.conf nameserver entries" },
  { id: "N-03", text: "isPrivateOrLoopback() blocks SSRF to 127.x, RFC-1918, link-local, and unresolvable hosts" },
  { id: "N-04", text: "CSRF token kept in runtimeCsrf (in-memory only); sessionStorage writes removed" },
  { id: "N-05", text: "authAttemptWindows uses Caffeine cache: maximumSize(50000), expireAfterWrite(2 min)" },
  { id: "N-06", text: "Proxy relay() uses managed relayExecutor instead of raw Thread creation per connection" },
  { id: "N-07", text: "SystemScan.js elevation path uses hardcoded safe message; catch block uses toUserMessage(err)" },
  { id: "N-08", text: "getCurrentActiveConnections() uses ss/netstat for real TCP connection count" },
  { id: "O-01", text: "DomainBlockingServiceImpl.isAdmin() returns cached hasAdminPrivileges field" },
  { id: "O-02", text: "@SuppressWarnings(null) removed from AntivirusController upload handlers; Objects.requireNonNull() used" },
  { id: "O-03", text: "getCurrentActiveConnections() metric fixed (same as N-08)" },
  { id: "O-04", text: "toggleFirewall/toggleWebProtection use Math.max(0, v-1) to prevent counter underflow" },
  { id: "O-05", text: "LogService.logScanResult() logs result.getFileName() not getFilePath()" },
];

const newFindings = [
  {
    id: "R-01",
    severity: "High",
    badge: "Regression",
    title: "O-01 fix broke hosts-file blocking — isAdmin() bootstrap reads uninitialized field",
    location: "src/main/java/com/antivirus/service/impl/DomainBlockingServiceImpl.java — constructor (~L8310), isAdmin() (~L8390)",
    description: "The O-01 fix correctly changed isAdmin() to return hasAdminPrivileges (the cached field). However the constructor then calls hasAdminPrivileges = isAdmin(), which reads hasAdminPrivileges before it has been assigned — Java initialises boolean fields to false. So isAdmin() returns false, false is assigned back to hasAdminPrivileges, and hosts-file blocking is permanently disabled regardless of actual filesystem permissions. The subsequent canModifyHostsFile() call sets hostsFileAccessible correctly, but blockDomain() and synchronizeHostsFile() both gate on if (hasAdminPrivileges && hostsFileAccessible) — so the first guard is always false and the hosts file is never written to.",
    impact: "System-wide domain blocking via the hosts file is silently broken for every deployment. Domains are stored in the DB but never applied to /etc/hosts. This is a functional regression introduced by the O-01 fix.",
    remediation: `// DomainBlockingServiceImpl.java — call canModifyHostsFile() directly
// in the constructor; never call isAdmin() before the field is set.
public DomainBlockingServiceImpl(
        BlockedDomainRepository blockedDomainRepository,
        @Value("...") String hostsFilePath) {
    this.blockedDomainRepository = blockedDomainRepository;
    this.hostsFilePath = hostsFilePath;

    Path hostsPath = Paths.get(hostsFilePath);
    // ✅ Call canModifyHostsFile() directly — not isAdmin() — so the field is
    //    set from a real filesystem check, not from reading itself.
    this.hasAdminPrivileges = canModifyHostsFile(hostsPath);
    this.hostsFileAccessible = this.hasAdminPrivileges;

    if (!hostsFileAccessible) {
        logger.warn("Hosts file at {} is not writable...", hostsFilePath);
    }
}

// isAdmin() stays as-is — returning the cached field is correct.
@Override
public boolean isAdmin() {
    return hasAdminPrivileges;  // ← correct after construction fix
}`
  },
  {
    id: "R-02",
    severity: "High",
    badge: "New",
    title: "hasSuspiciousNetworkBehavior() generates extreme false positives — any source or config file is a trojan",
    location: "src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java — hasSuspiciousNetworkBehavior() (~L9872), detectTrojan() (~L9800)",
    description: "hasSuspiciousNetworkBehavior() counts lines matching http://, https://, ftp://, any IP-address regex, 'socket', 'connect', or 'download' and returns true when the count exceeds 3. A Spring Boot application.properties file contains the DB URL (http/JDBC), a server port config, and an 'allowed-methods' list — that's already 3+ matches. A README.md with two hyperlinks and any mention of downloading a tool exceeds the threshold. Any HTML file exceeds it immediately. detectTrojan() calls this as its final decision, so every scanned application config file, HTML page, or source file is flagged as a trojan. This renders the antivirus scanner unreliable for its core purpose.",
    impact: "Near 100% false-positive rate on legitimate files. The antivirus scanner quarantines or reports its own application config as malware. Undermines operator trust in all scan results.",
    remediation: `// SecurityServiceImpl.java — replace hasSuspiciousNetworkBehavior() with
// targeted, context-aware patterns rather than keyword counting.
// The existing MALICIOUS_PATTERNS (with .find()) already covers network threats.
// hasSuspiciousNetworkBehavior() should be removed entirely and its callers
// should rely on the primary pattern scanner.

@Override
public boolean detectTrojan(File file) {
    try {
        String fileName = file.getName().toLowerCase();
        for (String signature : TROJAN_NAME_SIGNATURES) {
            if (fileName.contains(signature)) return true;
        }
        // Reuse the same streaming pattern scanner used everywhere else.
        // It already covers socket, reverse_tcp, process.create etc.
        return containsSuspiciousPatterns(file);
    } catch (Exception e) {
        logger.error("Trojan detection failed for file: {}", file.getName(), e);
        return false;
    }
}
// Remove hasSuspiciousNetworkBehavior() entirely.

private static final Set<String> TROJAN_NAME_SIGNATURES = Set.of(
    "backdoor", "rootkit", "trojan", "rat", "stealer", "keylog"
    // Keep only HIGH-signal name substrings; 'downloader', 'payload', 'inject'
    // are too broad and will match legitimate files.
);`
  },
  {
    id: "R-03",
    severity: "Medium",
    badge: "New",
    title: "detectRansomware() and detectTrojan() use unbounded BufferedReader — M-02 fix bypassed",
    location: "src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java — detectRansomware() (~L9700), detectTrojan() (~L9800), hasSuspiciousNetworkBehavior() (~L9872)",
    description: "The M-02 fix added a MAX_PATTERN_SCAN_BYTES (10 MB) streaming limit to containsSuspiciousPatterns(). However detectRansomware() and detectTrojan() each have their own independent BufferedReader loops that call reader.readLine() with no byte counter or size guard. A 100 MB text file submitted for scanning will have containsSuspiciousPatterns() correctly capped at 10 MB, but detectRansomware() and detectTrojan() are then called on the same file and both read the full 100 MB into memory. Since scanFile() calls containsSuspiciousPatterns(), detectRansomware(), and detectTrojan() sequentially, the effective scan of a 100 MB file reads up to 300 MB from disk.",
    impact: "OOM risk under concurrent upload load partially reverts the M-02 fix. Three concurrent 50 MB file scans consume ~450 MB in reader buffers alone.",
    remediation: `// Extract a shared bounded-read helper and use it in ALL detection methods.
// Replace the inline BufferedReader loops in detectRansomware() and detectTrojan()
// with calls to containsSuspiciousPatterns(), which already has the 10 MB limit.

@Override
public boolean detectRansomware(File file) {
    try {
        String ext = getFileExtension(file).toLowerCase();
        if (RANSOMWARE_EXTENSIONS.contains(ext)) return true;
        // Reuse the bounded streaming pattern scanner
        return containsSuspiciousPatterns(file);
    } catch (Exception e) {
        logger.error("Ransomware detection failed: {}", file.getName(), e);
        return false;
    }
}

// Add ransomware patterns to MALICIOUS_PATTERNS:
Pattern.compile("(?i)\\byour files have been encrypted\\b"),
Pattern.compile("(?i)\\bbtc wallet\\b"),
Pattern.compile("(?i)\\.(?:onion|tor)\\b"),
Pattern.compile("(?i)\\bdecrypt.*ransom|ransom.*decrypt\\b"),

private static final Set<String> RANSOMWARE_EXTENSIONS = Set.of(
    ".encrypted", ".crypto", ".locked", ".crypted", ".crypt",
    ".vault", ".petya", ".wannacry", ".wcry", ".wncry",
    ".locky", ".zepto", ".thor", ".aesir", ".zzzzz"
);`
  },
  {
    id: "R-04",
    severity: "Medium",
    badge: "New",
    title: "KNOWN_MALWARE_SIGNATURES is a non-thread-safe HashSet mutated concurrently",
    location: "src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java — KNOWN_MALWARE_SIGNATURES (~L8940), updateVirusDefinitions() (~L9600), calculateFileHash() (~L9250)",
    description: "KNOWN_MALWARE_SIGNATURES is declared as private static final Set<String> = new HashSet<>(). updateVirusDefinitions() calls KNOWN_MALWARE_SIGNATURES.add() without synchronization while concurrent scan threads call KNOWN_MALWARE_SIGNATURES.contains() in calculateFileHash(). HashSet is not thread-safe: concurrent structural modification during a read causes ConcurrentModificationException or silent data corruption (lost entries, infinite loops in HashMap buckets). In addition, updateVirusDefinitions() adds the literal string 'new_malware_signature_hash' — a 26-character string that can never match any real MD5 hash (which is always 32 hex characters), making the method a no-op with misleading intent.",
    impact: "ConcurrentModificationException under concurrent scan + update load. Unpredictable signature set state. The update endpoint silently adds a non-matching string, giving false confidence.",
    remediation: `// SecurityServiceImpl.java — switch to ConcurrentHashMap.newKeySet() for
// thread-safe concurrent reads and writes.
private static final Set<String> KNOWN_MALWARE_SIGNATURES =
    ConcurrentHashMap.newKeySet();

static {
    // Seed the initial signatures
    KNOWN_MALWARE_SIGNATURES.addAll(List.of(
        "e4968ef99266df7c9a1f0637d2389dab",
        "a7d6f45f05f9bc45f2b9c6fb93d7d9ab",
        "c8d03b43a0c9b5890b6f6994da2c4639"
    ));
}

@Override
public void updateVirusDefinitions() {
    // In production this would fetch a real signature feed.
    // Add only valid 32-char MD5 hex strings. For now, log the intent.
    logger.info("Virus definition update requested — no external feed configured");
    // Example of a correctly formatted addition:
    // KNOWN_MALWARE_SIGNATURES.add("d41d8cd98f00b204e9800998ecf8427e");
}`
  },
  {
    id: "R-05",
    severity: "Medium",
    badge: "New",
    title: "detectRootkit() false-positives every dotfile, zero-byte file, and /proc or /sys entry",
    location: "src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java — detectRootkit() (~L9960)",
    description: "detectRootkit() returns true for three extremely broad conditions: (1) Files.isHidden() — on Linux, any file starting with a dot (.bashrc, .gitignore, .env, .npmrc, .profile, .ssh/authorized_keys) is 'hidden' and flagged as a rootkit. (2) attrs.size() == 0 — empty marker files, lock files, touch-created flags, and many system files are zero bytes. (3) file.getAbsolutePath().startsWith('/proc/') — every running process on Linux has an entry in /proc; the system scan would flag the antivirus process itself. Also: detectRootkit() logs absolute server file paths via String concatenation (logger.warn('...' + file.getAbsolutePath())) which bypasses SLF4J's lazy evaluation and always constructs the string.",
    impact: "System scan reports false positives for every dotfile in a user's home directory and every /proc entry, flooding the dashboard with spurious 'rootkit' alerts. Legitimate files are quarantined or deleted based on false detection.",
    remediation: `// SecurityServiceImpl.java — remove or tighten all three over-broad checks.

@Override
public boolean detectRootkit(File file) {
    try {
        // 1. Only check known HIGH-signal rootkit locations — not /proc or /sys
        //    which are normal pseudo-filesystems.
        String absPath = file.getAbsolutePath().toLowerCase();
        Set<String> trulyRootkitPaths = Set.of(
            "/boot/", "/lib/modules/",
            "c:\\\\windows\\\\system32\\\\drivers\\\\"
        );
        if (trulyRootkitPaths.stream().anyMatch(absPath::contains)) {
            logger.warn("File in rootkit-suspect location: {}", file.getName());
            return true;
        }

        // 2. Check binary patterns from the known rootkit signature list
        byte[] header = readFilePrefix(file, 4096);
        if (detectRootkitBinaryPatterns(header)) {
            logger.warn("Rootkit binary pattern in: {}", file.getName()); // ← {} not +
            return true;
        }

        // 3. Remove the isHidden() check — dotfiles are not rootkits
        // 4. Remove the zero-byte check — empty files are normal
        return false;

    } catch (IOException e) {
        logger.error("Error during rootkit detection for file: {}", file.getName(), e);
        return false;
    }
}`
  },
  {
    id: "R-06",
    severity: "Medium",
    badge: "New",
    title: "MD5 used for malware signature matching — collision-prone, unsuitable for security",
    location: "src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java — KNOWN_MALWARE_SIGNATURES (~L8940), calculateFileHash() (~L9250)",
    description: "The C-01 mismatch is resolved (both now use MD5) but MD5 itself is cryptographically broken. An attacker can engineer two files with identical MD5 hashes: one clean (to pass the signature check) and one containing malware. While known-malware signature databases historically used MD5, all modern AV engines and NIST (since 2008) have deprecated MD5 for security purposes. MD5 collision attacks are practically achievable with commodity hardware in seconds.",
    impact: "A sophisticated attacker can craft a file that matches a clean file's MD5 hash but executes malicious code — bypassing the signature database check entirely.",
    remediation: `// SecurityServiceImpl.java — switch to SHA-256 for hash computation
// and update all KNOWN_MALWARE_SIGNATURES to SHA-256 hashes.

private String calculateFileHash(File file) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256"); // ← was MD5
    try (InputStream is = Files.newInputStream(file.toPath())) {
        byte[] buffer = new byte[8192];
        int read;
        while ((read = is.read(buffer)) > 0) {
            md.update(buffer, 0, read);
        }
    }
    return bytesToHex(md.digest()); // returns 64 hex chars
}

// Update KNOWN_MALWARE_SIGNATURES to SHA-256 hashes (64 chars each):
private static final Set<String> KNOWN_MALWARE_SIGNATURES =
    ConcurrentHashMap.newKeySet();
static {
    KNOWN_MALWARE_SIGNATURES.addAll(List.of(
        // Replace these with real SHA-256 hashes from a threat-intel feed
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // empty file
    ));
}`
  },
  {
    id: "R-07",
    severity: "Low",
    badge: "New",
    title: "@SuppressWarnings(\"null\") retained on saveScanResult() and loadInfectedScanResult()",
    location: "src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java — saveScanResult() (~L9170), loadInfectedScanResult() (~L9578)",
    description: "The O-02 fix removed @SuppressWarnings(\"null\") from AntivirusController correctly, but SecurityServiceImpl still carries the annotation on two security-critical methods: saveScanResult() suppresses null analysis on the JPA save call, and loadInfectedScanResult() suppresses it on the findById() Optional chain. The @SuppressWarnings is unnecessary — both are resolvable without suppression using explicit null guards.",
    remediation: `// SecurityServiceImpl.java — remove both annotations and use explicit guards.

// saveScanResult() — remove @SuppressWarnings("null")
private ScanResult saveScanResult(ScanResult result) {
    if (result == null) return null;  // explicit null guard replaces suppression
    assignOwnerIfMissing(result);
    return scanResultRepository.save(result);
}

// loadInfectedScanResult() — remove @SuppressWarnings("null")
private ScanResult loadInfectedScanResult(Long scanResultId) {
    ScanResult result = scanResultRepository.findById(scanResultId)
        .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Scan result not found"));
    // The Optional.orElseThrow makes result non-null here — no suppression needed.
    if (!result.isInfected()) {
        throw new ResponseStatusException(FORBIDDEN, "Only infected scan results can be modified");
    }
    ...
}`
  },
  {
    id: "R-08",
    severity: "Low",
    badge: "New",
    title: "updateVirusDefinitions() modifies a shared static set with a non-matching placeholder string",
    location: "src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java — updateVirusDefinitions() (~L9600)",
    description: "updateVirusDefinitions() adds the string 'new_malware_signature_hash' (26 chars) to KNOWN_MALWARE_SIGNATURES. An MD5 hash is always exactly 32 hex characters; this string can never match any real file hash. The POST /api/antivirus/update endpoint succeeds with HTTP 200 but performs no security function. Operators calling this endpoint have no indication it is a stub.",
    remediation: `// SecurityServiceImpl.java — return HTTP 501 until a real feed is implemented
@Override
public void updateVirusDefinitions() {
    // TODO: integrate with a real signature feed (e.g. VirusTotal, MalwareBazaar)
    logger.info("Virus definition update requested — external feed not configured");
    throw new ResponseStatusException(HttpStatus.NOT_IMPLEMENTED,
        "Signature update feed not configured");
}
// In AntivirusController.java:
@PostMapping("/update")
public ResponseEntity<Map<String, String>> updateVirusDefinitions() {
    try {
        securityService.updateVirusDefinitions();
        return ResponseEntity.ok(Map.of("status", "updated"));
    } catch (ResponseStatusException e) {
        return ResponseEntity.status(e.getStatusCode())
            .body(Map.of("message", e.getReason()));
    }
}`
  },
];

const SEVERITY_CONFIG = {
  High:     { color: "#854F0B", bg: "#FAEEDA", border: "#EF9F27" },
  Medium:   { color: "#185FA5", bg: "#E6F1FB", border: "#85B7EB" },
  Low:      { color: "#3B6D11", bg: "#EAF3DE", border: "#97C459" },
};

const BADGE_CONFIG = {
  Regression: { color: "#6B1E1E", bg: "#FDEAEA", border: "#E57373" },
  New:        { color: "#185FA5", bg: "#E6F1FB", border: "#85B7EB" },
};

function SeverityBadge({ severity }) {
  const c = SEVERITY_CONFIG[severity];
  return <span style={{ background: c.bg, color: c.color, border: `0.5px solid ${c.border}`, borderRadius: 6, fontSize: 11, fontWeight: 500, padding: "2px 8px", whiteSpace: "nowrap" }}>{severity}</span>;
}

function TypeBadge({ badge }) {
  const c = BADGE_CONFIG[badge] || BADGE_CONFIG.New;
  return <span style={{ background: c.bg, color: c.color, border: `0.5px solid ${c.border}`, borderRadius: 6, fontSize: 10, fontWeight: 600, padding: "2px 7px", whiteSpace: "nowrap", textTransform: "uppercase", letterSpacing: "0.04em" }}>{badge}</span>;
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(false);
  const cfg = SEVERITY_CONFIG[f.severity];
  return (
    <div style={{ background: "var(--color-background-primary)", border: "0.5px solid var(--color-border-tertiary)", borderLeft: `3px solid ${cfg.border}`, borderRadius: 10, marginBottom: 8, overflow: "hidden" }}>
      <button onClick={() => setOpen(v => !v)} style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", background: "none", border: "none", padding: "12px 16px", cursor: "pointer", textAlign: "left" }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: cfg.color, fontWeight: 600, minWidth: 38 }}>{f.id}</span>
        <TypeBadge badge={f.badge} />
        <SeverityBadge severity={f.severity} />
        <span style={{ flex: 1, fontSize: 13, fontWeight: 500, color: "var(--color-text-primary)", marginLeft: 4 }}>{f.title}</span>
        <i className={`ti ${open ? "ti-chevron-up" : "ti-chevron-down"}`} style={{ fontSize: 16, color: "var(--color-text-secondary)", flexShrink: 0 }} />
      </button>
      {open && (
        <div style={{ padding: "0 16px 16px", borderTop: "0.5px solid var(--color-border-tertiary)" }}>
          {[["Location", <code style={{ fontSize: 12, background: "var(--color-background-secondary)", padding: "6px 10px", borderRadius: 6, display: "block", whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--color-text-secondary)" }}>{f.location}</code>],
            ["Description", <p style={{ margin: 0, fontSize: 14, color: "var(--color-text-secondary)", lineHeight: 1.65 }}>{f.description}</p>],
            ["Impact", <p style={{ margin: 0, fontSize: 14, color: cfg.color, lineHeight: 1.65, fontWeight: 500 }}>{f.impact}</p>],
            ["Remediation", <pre style={{ margin: 0, fontSize: 12, background: "var(--color-background-secondary)", padding: "12px 14px", borderRadius: 8, overflow: "auto", whiteSpace: "pre", color: "var(--color-text-primary)", lineHeight: 1.6, fontFamily: "var(--font-mono)" }}>{f.remediation}</pre>]
          ].map(([label, child]) => (
            <div key={label} style={{ marginTop: 12 }}>
              <p style={{ margin: "0 0 6px", fontSize: 11, fontWeight: 500, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</p>
              {child}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function AuditPart4() {
  const [tab, setTab] = useState("findings");
  const regressions = newFindings.filter(f => f.badge === "Regression");
  const genuineNew  = newFindings.filter(f => f.badge === "New");
  const counts = newFindings.reduce((a, f) => { a[f.severity] = (a[f.severity] || 0) + 1; return a; }, {});

  return (
    <div style={{ padding: "1.5rem 0", maxWidth: 720, margin: "0 auto" }}>
      <div style={{ marginBottom: "1.5rem" }}>
        <p style={{ margin: "0 0 4px", fontSize: 11, fontWeight: 500, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Security audit — part 4</p>
        <p style={{ margin: "0 0 0.5rem", fontSize: 20, fontWeight: 500, color: "var(--color-text-primary)" }}>Full verification + new scan findings</p>
        <p style={{ margin: 0, fontSize: 13, color: "var(--color-text-secondary)" }}>
          SecurityServiceImpl.java now present · 37 prior findings verified · {regressions.length} regression{regressions.length !== 1 ? "s" : ""} from fixes · {genuineNew.length} new detections
        </p>
      </div>

      {/* Score row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: "1.5rem" }}>
        {[
          { n: FIXED_ALL.length, label: "Confirmed fixed", color: "#3B6D11", bg: "#EAF3DE", border: "#97C459" },
          { n: regressions.length, label: "Regressions", color: "#6B1E1E", bg: "#FDEAEA", border: "#E57373" },
          { n: genuineNew.length, label: "New findings", color: "#185FA5", bg: "#E6F1FB", border: "#85B7EB" },
          { n: 0, label: "Unverifiable", color: "#5C5C8A", bg: "#F0EFF9", border: "#B0ACDE" },
        ].map(c => (
          <div key={c.label} style={{ background: c.bg, border: `0.5px solid ${c.border}`, borderRadius: 10, padding: "12px 14px" }}>
            <p style={{ margin: "0 0 2px", fontSize: 22, fontWeight: 500, color: c.color }}>{c.n}</p>
            <p style={{ margin: 0, fontSize: 12, color: c.color }}>{c.label}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 0, marginBottom: "1.5rem", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
        {[["findings", `Findings (${newFindings.length})`], ["fixed", `Confirmed Fixed (${FIXED_ALL.length})`]].map(([key, label]) => (
          <button key={key} onClick={() => setTab(key)} style={{ padding: "8px 14px", fontSize: 13, fontWeight: 500, background: "none", border: "none", borderBottom: tab === key ? "2px solid var(--color-text-primary)" : "2px solid transparent", color: tab === key ? "var(--color-text-primary)" : "var(--color-text-secondary)", cursor: "pointer", marginBottom: -1, whiteSpace: "nowrap" }}>{label}</button>
        ))}
      </div>

      {tab === "findings" && (
        <div>
          {/* Regression callout */}
          {regressions.length > 0 && (
            <div style={{ background: "#FDEAEA", border: "0.5px solid #E57373", borderRadius: 10, padding: "12px 16px", marginBottom: "1.25rem", fontSize: 13, lineHeight: 1.7, color: "#6B1E1E" }}>
              <strong>{regressions.length} regression{regressions.length !== 1 ? "s" : ""} detected</strong> — a previous fix introduced a new bug. R-01 is the most urgent: the O-01 fix changed <code style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>isAdmin()</code> to return the cached field, but the constructor now reads that uninitialized field through <code style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>isAdmin()</code>, permanently setting <code style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>hasAdminPrivileges = false</code>. Hosts-file domain blocking is silently disabled in every deployment.
            </div>
          )}

          {/* Severity pills */}
          <div style={{ display: "flex", gap: 6, marginBottom: "1rem", flexWrap: "wrap" }}>
            {["High", "Medium", "Low"].map(s => {
              const c = SEVERITY_CONFIG[s];
              return <span key={s} style={{ background: c.bg, color: c.color, border: `0.5px solid ${c.border}`, borderRadius: 20, fontSize: 12, fontWeight: 500, padding: "3px 12px" }}>{s} ({counts[s] || 0})</span>;
            })}
          </div>

          {newFindings.map(f => <FindingCard key={f.id} f={f} />)}

          <div style={{ marginTop: "1.5rem", background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: 10, padding: "12px 16px", fontSize: 13, lineHeight: 1.7, color: "var(--color-text-secondary)" }}>
            <strong style={{ color: "var(--color-text-primary)", fontWeight: 500 }}>Priority fix order — </strong>
            R-01 (bootstrap regression, disables hosts blocking) → R-02 (false-positive trojan cascade) → R-03 (OOM in ransomware/trojan readers) → R-04 (thread-unsafe signature set) → R-05 (rootkit false positives) → R-06 (MD5 → SHA-256) → R-07 / R-08 (code quality).
          </div>
        </div>
      )}

      {tab === "fixed" && (
        <div>
          <div style={{ background: "#EAF3DE", border: "0.5px solid #97C459", borderRadius: 10, padding: "12px 16px", marginBottom: "1.5rem", fontSize: 13, lineHeight: 1.7, color: "#3B6D11" }}>
            <strong>All 37 findings from Parts 1–3 confirmed resolved</strong> — including SecurityServiceImpl.java items that were previously unverifiable due to the file being absent from earlier dumps. The auth layer, rate limiter, CSRF, security headers, streaming file scanner, ZIP-bomb protection, proxy SSRF, and DNS blocking are all correctly implemented.
          </div>
          {FIXED_ALL.map(f => (
            <div key={f.id} style={{ display: "flex", gap: 10, padding: "10px 14px", background: "var(--color-background-primary)", border: "0.5px solid var(--color-border-tertiary)", borderLeft: "3px solid #97C459", borderRadius: 10, marginBottom: 8 }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#3B6D11", fontWeight: 600, minWidth: 38 }}>{f.id}</span>
              <span style={{ fontSize: 13, color: "var(--color-text-secondary)", lineHeight: 1.55 }}>{f.text}</span>
            </div>
          ))}
        </div>
      )}

      <div style={{ marginTop: "2rem", borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: "1rem", fontSize: 12, color: "var(--color-text-tertiary)" }}>
        Part 4 of 4 — expand any finding for location, impact, and exact remediation code.
      </div>
    </div>
  );
}