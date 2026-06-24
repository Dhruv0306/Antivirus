import { useState } from "react";

// ── CONFIRMED FINDINGS FROM PART 4 (all now source-verified) ────────────────

const confirmedFindings = [
  {
    id: "R-01",
    severity: "High",
    badge: "Regression",
    title: "O-01 fix broke hosts-file blocking — isAdmin() bootstrap reads uninitialized false",
    location: "DomainBlockingServiceImpl.java — constructor (~L8310), isAdmin() (~L8390)",
    description: "The constructor calls hasAdminPrivileges = isAdmin() before the field is set. isAdmin() returns hasAdminPrivileges which is still Java's default false. The field is assigned false, so all downstream guards if (hasAdminPrivileges && hostsFileAccessible) are permanently short-circuited. blockDomain(), unblockDomain(), and synchronizeHostsFile() all log 'domain will be blocked in database only' — even when /etc/hosts is fully writable. Verified: hostsFileAccessible IS set correctly by canModifyHostsFile() (called after), but hasAdminPrivileges is always false.",
    impact: "System-wide /etc/hosts domain blocking is permanently disabled for every deployment regardless of actual filesystem permissions. Domains appear blocked in the DB but are never written to the OS-level blocklist.",
    remediation: `// DomainBlockingServiceImpl.java constructor — call canModifyHostsFile()
// directly instead of reading through the not-yet-set isAdmin() method.

public DomainBlockingServiceImpl(
        BlockedDomainRepository blockedDomainRepository,
        @Value("...") String hostsFilePath) {
    this.blockedDomainRepository = blockedDomainRepository;
    this.hostsFilePath = hostsFilePath;
    Path hostsPath = Paths.get(hostsFilePath);

    // ✅ Set the field directly from the filesystem check
    this.hasAdminPrivileges = canModifyHostsFile(hostsPath);
    this.hostsFileAccessible = this.hasAdminPrivileges;

    if (!hostsFileAccessible) {
        logger.warn("Hosts file at {} is not writable...", hostsFilePath);
    }
}
// isAdmin() stays as-is — returning the cached field is correct after construction.`
  },
  {
    id: "R-02",
    severity: "High",
    badge: "New",
    title: "hasSuspiciousNetworkBehavior() flags every config/source/HTML file as a trojan",
    location: "SecurityServiceImpl.java — hasSuspiciousNetworkBehavior() (~L9857), detectTrojan() (~L9795)",
    description: "The method returns true when any 4 lines contain http://, https://, ftp://, an IP-address regex, 'socket', 'connect', or 'download'. A Spring Boot application.properties file alone triggers this: DB URL (http/JDBC) + server.port config + 'connect' in datasource + 'download' in any comment = 4 matches. Any HTML page with two hyperlinks and a download link is flagged. Any README.md with curl examples is a trojan. detectTrojan() calls hasSuspiciousNetworkBehavior() as its final decision, meaning almost every scanned non-binary file is reported as infected.",
    impact: "Near-100% false positive rate on legitimate files. The antivirus scanner would quarantine its own application config. Dashboard flooded with false trojan alerts, rendering all scan output untrustworthy.",
    remediation: `// SecurityServiceImpl.java — remove hasSuspiciousNetworkBehavior() entirely.
// The MALICIOUS_PATTERNS list already covers network threats with precise,
// context-aware regexes. detectTrojan() should delegate to it.

@Override
public boolean detectTrojan(File file) {
    try {
        String fileName = file.getName().toLowerCase();
        for (String sig : TROJAN_NAME_SIGNATURES) {
            if (fileName.contains(sig)) return true;
        }
        // Reuse the bounded streaming pattern scanner (already has 10 MB cap)
        return containsSuspiciousPatterns(file);
    } catch (Exception e) {
        logger.error("Trojan detection failed for file: {}", file.getName(), e);
        return false;
    }
}

// Keep ONLY high-signal name patterns; remove broad terms like "inject"/"payload"
private static final Set<String> TROJAN_NAME_SIGNATURES = Set.of(
    "backdoor", "rootkit", "trojan", "remote_access",
    "stealer", "reverse_shell", "wscript.shell"
);
// DELETE hasSuspiciousNetworkBehavior()`
  },
  {
    id: "R-03",
    severity: "Medium",
    badge: "New",
    title: "detectRansomware() and detectTrojan() use unbounded BufferedReader — M-02 fix bypassed",
    location: "SecurityServiceImpl.java — detectRansomware() (~L9664), detectTrojan() (~L9795), hasSuspiciousNetworkBehavior() (~L9857)",
    description: "containsSuspiciousPatterns() correctly caps reads at MAX_PATTERN_SCAN_BYTES (10 MB) via a char-count guard. detectRansomware() and detectTrojan() each open their own new BufferedReader(new FileReader(file)) with no byte counter. Both read the entire file line-by-line with no limit. A 100 MB file submitted for scanning goes through: containsSuspiciousPatterns() (capped at 10 MB) + detectRansomware() (uncapped, reads all 100 MB) + detectTrojan() (uncapped, reads all 100 MB) = 210 MB read per file. Under concurrent upload load this multiplies.",
    impact: "OOM risk under concurrent scan load. Three concurrent 50 MB uploads consume ~300 MB of heap in BufferedReader alone beyond the 10 MB containsSuspiciousPatterns() limit. Reverts the M-02 fix.",
    remediation: `// SecurityServiceImpl.java — replace the inline BufferedReader loop
// in detectRansomware() with extension check + delegate to bounded scanner.

@Override
public boolean detectRansomware(File file) {
    try {
        if (RANSOMWARE_EXTENSIONS.contains(
                getFileExtension(file).toLowerCase())) return true;
        // containsSuspiciousPatterns() is already bounded to MAX_PATTERN_SCAN_BYTES
        return containsSuspiciousPatterns(file);
    } catch (Exception e) {
        logger.error("Ransomware detection failed: {}", file.getName(), e);
        return false;
    }
}
// Move ransomware keywords into MALICIOUS_PATTERNS:
Pattern.compile("(?i)\\byour files have been encrypted\\b"),
Pattern.compile("(?i)\\bbtc wallet\\b"),
Pattern.compile("(?i)\\.(?:onion|tor)\\b"),
Pattern.compile("(?i)\\bdecrypt.{0,30}ransom|ransom.{0,30}decrypt\\b"),

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
    location: "SecurityServiceImpl.java — KNOWN_MALWARE_SIGNATURES (~L8940), updateVirusDefinitions() (~L9622), calculateFileHash() / scanFile() (~L9263)",
    description: "private static final Set<String> KNOWN_MALWARE_SIGNATURES = new HashSet<>(). updateVirusDefinitions() calls .add() on it without synchronization while concurrent scan threads call .contains() inside calculateFileHash(). HashSet is not thread-safe: concurrent structural modification during a read produces ConcurrentModificationException or silent data corruption (lost/duplicate entries, infinite loops in internal HashMap bucket traversal). On a JVM with N scan threads active, every updateVirusDefinitions() call races with N concurrent .contains() reads.",
    impact: "ConcurrentModificationException or silent signature-set corruption under concurrent scan + update load. Unpredictable detection gaps.",
    remediation: `// SecurityServiceImpl.java — replace with ConcurrentHashMap.newKeySet()
// which provides thread-safe O(1) reads and writes with no synchronization overhead.

private static final Set<String> KNOWN_MALWARE_SIGNATURES =
    ConcurrentHashMap.newKeySet();

static {
    KNOWN_MALWARE_SIGNATURES.addAll(List.of(
        "e4968ef99266df7c9a1f0637d2389dab",
        "a7d6f45f05f9bc45f2b9c6fb93d7d9ab",
        "c8d03b43a0c9b5890b6f6994da2c4639"
    ));
}
// updateVirusDefinitions(): KNOWN_MALWARE_SIGNATURES.add() is now thread-safe.`
  },
  {
    id: "R-05",
    severity: "Medium",
    badge: "New",
    title: "detectRootkit() produces extreme false positives — dotfiles, zero-byte files, /proc/, /sys/",
    location: "SecurityServiceImpl.java — detectRootkit() (~L9946)",
    description: "detectRootkit() returns true for: (1) Any file whose absolute path starts with /proc/ or /sys/ — every Linux process, memory map, and kernel interface is flagged as a rootkit. The system scan would flag the antivirus process itself. (2) Files.isHidden() returning true — on Linux any dotfile (.bashrc, .gitignore, .env, .npmrc, .ssh/authorized_keys, .profile) is 'hidden'. A user's home directory scan would flag virtually everything. (3) attrs.size() == 0 — empty lock files, marker files, and touch-created flags are all flagged. The !file.getName().endsWith('.log') carve-out is far too narrow.",
    impact: "System scan generates hundreds of false rootkit alerts per directory scan. Legitimate files quarantined or deleted. Dashboard completely noise-flooded, masking real threats.",
    remediation: `// SecurityServiceImpl.java — narrow all three conditions to genuine indicators.

@Override
public boolean detectRootkit(File file) {
    try {
        String absPath = file.getAbsolutePath().toLowerCase();

        // 1. Only flag HIGH-signal driver/boot locations — not /proc or /sys
        boolean inRootkitLocation =
            absPath.contains("/lib/modules/") ||
            absPath.contains("/boot/") ||
            absPath.contains("\\\\system32\\\\drivers\\\\") ||
            absPath.contains("\\\\syswow64\\\\drivers\\\\");

        if (inRootkitLocation) {
            // Only report if binary rootkit patterns are found in that location
            byte[] header = readFilePrefix(file, 4096);
            if (detectRootkitBinaryPatterns(header)) {
                logger.warn("Rootkit binary patterns in driver location: {}", file.getName());
                return true;
            }
        }

        // 2. Check kernel manipulation text patterns (already good — keep)
        // 3. Remove Files.isHidden() check — dotfiles are not rootkits
        // 4. Remove zero-byte file check — empty files are entirely normal

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
    title: "MD5 still used for malware signature matching — collision attacks bypass detection",
    location: "SecurityServiceImpl.java — calculateFileHash() (~L9263), KNOWN_MALWARE_SIGNATURES (~L8940)",
    description: "calculateFileHash() uses MessageDigest.getInstance(\"MD5\"). The C-01 mismatch is resolved (both now consistently use MD5) but MD5 is cryptographically broken: collision attacks are achievable in seconds on commodity hardware. An attacker can craft a malware binary whose MD5 matches that of a known-clean file in the signature list, or craft a file that doesn't match any known signature while still executing malicious code. All modern AV signature databases (VirusTotal, MalwareBazaar) use SHA-256 as the minimum.",
    impact: "Signature database bypass via MD5 collision. Crafted malware passes the KNOWN_MALWARE_SIGNATURES check and relies on pattern matching to detect it — but the pattern scanner is separately bypassable by encoding malicious payloads.",
    remediation: `// SecurityServiceImpl.java — switch calculateFileHash() to SHA-256
private String calculateFileHash(File file) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256"); // ← was MD5
    try (InputStream is = Files.newInputStream(file.toPath())) {
        byte[] buffer = new byte[8192];
        int read;
        while ((read = is.read(buffer)) > 0) md.update(buffer, 0, read);
    }
    return bytesToHex(md.digest()); // now returns 64-char hex string
}
// Update KNOWN_MALWARE_SIGNATURES to SHA-256 hashes:
static {
    KNOWN_MALWARE_SIGNATURES.addAll(List.of(
        // Replace with real SHA-256 hashes from a threat intel feed
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ));
}`
  },
  {
    id: "R-07",
    severity: "Low",
    badge: "New",
    title: "@SuppressWarnings(\"null\") on saveScanResult() and loadInfectedScanResult()",
    location: "SecurityServiceImpl.java — saveScanResult() (~L9195), loadInfectedScanResult() (~L9585)",
    description: "Both methods retain @SuppressWarnings(\"null\") despite the explicit null guard (assignOwnerIfMissing + Optional.orElseThrow) making the annotation unnecessary. The O-02 fix removed these from AntivirusController but not from the service impl methods where the actual JPA calls happen.",
    remediation: `// Remove @SuppressWarnings("null") from both methods.
// saveScanResult() — assignOwnerIfMissing() already null-guards result.
// loadInfectedScanResult() — .orElseThrow() guarantees non-null; no suppression needed.`
  },
  {
    id: "R-08",
    severity: "Low",
    badge: "New",
    title: "updateVirusDefinitions() adds a 26-char placeholder that can never match any MD5 hash",
    location: "SecurityServiceImpl.java — updateVirusDefinitions() (~L9622)",
    description: "KNOWN_MALWARE_SIGNATURES.add(\"new_malware_signature_hash\") adds a 26-character string. MD5 hashes are always exactly 32 hex characters. This string can never match any file's computed hash. The endpoint returns HTTP 200 and logs nothing, giving false confidence that signatures were updated.",
    remediation: `@Override
public void updateVirusDefinitions() {
    logger.info("Virus definition update requested — external feed not configured");
    throw new ResponseStatusException(HttpStatus.NOT_IMPLEMENTED,
        "Signature update feed not configured. Integrate VirusTotal or MalwareBazaar.");
}`
  },
];

// ── ADDITIONAL FINDINGS DISCOVERED IN THIS READ PASS ────────────────────────

const additionalFindings = [
  {
    id: "S-01",
    severity: "Medium",
    badge: "New",
    title: "detectRootkit() logs absolute server path via string concatenation — info leak + bad practice",
    location: "SecurityServiceImpl.java — detectRootkit() (~L9963, L9970)",
    description: "Two of the four logger.warn() calls inside detectRootkit() use string concatenation instead of SLF4J parameterized logging:\n  logger.warn(\"...suspicious location: \" + file.getAbsolutePath());\n  logger.warn(\"...kernel manipulation pattern found in \" + file.getName());\nThe first call logs file.getAbsolutePath() — the full server-side absolute path — into the application log. This exposes server directory structure to anyone with log-file access. The second and third use file.getName() (safe). All four bypass SLF4J's lazy string evaluation: the string is always constructed even when the log level would suppress output.",
    impact: "Absolute server paths written to log files visible to any user or process with log access. On multi-tenant or shared hosting environments this discloses the server's directory layout.",
    remediation: `// SecurityServiceImpl.java — convert all four warn() calls to parameterized form.
// The unsafe ones:
logger.warn("Potential rootkit detected: File in suspicious location: {}",
    file.getName()); // ← use getName() not getAbsolutePath()
logger.warn("Potential rootkit detected: Kernel manipulation pattern in: {}",
    file.getName());

// The others (already use getName but still need {} syntax):
logger.warn("Potential rootkit detected: Suspicious binary patterns in: {}",
    file.getName());
logger.warn("Potential rootkit detected: Zero-byte file: {}", file.getName());

// General rule: never log getAbsolutePath() at WARN/INFO level.`
  },
  {
    id: "S-02",
    severity: "Medium",
    badge: "New",
    title: "LogService.readAllLogLines() loads up to 80 MB into heap to return 5 results",
    location: "LogService.java — readAllLogLines() (~L7459), getLastFiveScanResults() (~L7424)",
    description: "readAllLogLines() calls Files.readAllLines(logFile) for every existing log file: the current scan_history.log plus up to 7 backups. With MAX_LOG_FILE_SIZE_BYTES = 10 MB and MAX_LOG_BACKUPS = 7, this allocates up to 80 MB of String lists into the Java heap in a single call. The caller (getLastFiveScanResults()) then sorts all of it just to take 5 records. Every call to GET /api/antivirus/scan-history triggers this allocation. Under concurrent polling from the dashboard's 5-second interval, multiple 80 MB allocations stack up.",
    impact: "Up to 80 MB heap pressure per request on a busy dashboard. Under 5-second polling from 3 concurrent browser sessions, 240 MB+ is allocated per polling cycle — likely causing GC pressure or OOM on deployments with <512 MB heap.",
    remediation: `// LogService.java — read only the MOST RECENT log file (no rotation scan)
// and parse the last 5 lines directly without loading everything.

public List<ScanResult> getLastFiveScanResults() {
    try {
        Path currentLog = Paths.get(LOG_DIRECTORY).resolve(LOG_FILE);
        if (!Files.exists(currentLog)) return List.of();

        // Read only the tail of the current log — not all rotated backups
        List<String> allLines = Files.readAllLines(currentLog);
        int from = Math.max(0, allLines.size() - 100); // last 100 lines max
        return allLines.subList(from, allLines.size()).stream()
            .filter(l -> l != null && !l.isBlank())
            .sorted(Comparator.comparing(
                line -> Long.parseLong(line.split(":")[0]),
                Comparator.reverseOrder()))
            .limit(5)
            .map(this::decodeScanResult)
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
    } catch (IOException e) {
        logger.error("Error reading scan history log: {}", e.getMessage());
        return List.of();
    }
}`
  },
  {
    id: "S-03",
    severity: "Medium",
    badge: "New",
    title: "hasRansomwareBehavior() calls parentDir.listFiles() on every scanned file — O(n²) in large directories",
    location: "SecurityServiceImpl.java — hasRansomwareBehavior() (~L9731), detectRansomware() (~L9657)",
    description: "hasRansomwareBehavior() calls file.getParentFile().listFiles() which loads the ENTIRE directory listing of the parent directory into a File[] array for every file being scanned. For a directory containing 10,000 files, scanning all of them calls listFiles() 10,000 times, each loading a 10,000-element File[] array. This is O(n²) in directory size. On Linux, each listFiles() call is a blocking syscall that reads directory entries from disk. For a /home directory with 50,000 files, this produces 50,000 directory reads of 50,000 entries = 2.5 billion file-object allocations.",
    impact: "System scan of a large user home directory causes GC thrashing and potential OOM. Scan performance degrades quadratically with directory size.",
    remediation: `// Remove hasRansomwareBehavior() entirely (it's also called only from detectRansomware()
// which is being replaced with R-03's fix).
// If the directory-scan heuristic is still desired, cache the listing per directory:

private final Map<String, File[]> directoryListingCache = new ConcurrentHashMap<>();

private boolean hasRansomwareBehavior(File file) {
    File parentDir = file.getParentFile();
    if (parentDir == null) return false;

    // Cache the listing for this directory — one listFiles() per directory, not per file
    File[] files = directoryListingCache.computeIfAbsent(
        parentDir.getAbsolutePath(), k -> parentDir.listFiles());
    if (files == null) return false;

    // ... rest of logic unchanged ...
}
// Clear the cache before each scan invocation and after completion.`
  },
  {
    id: "S-04",
    severity: "Low",
    badge: "New",
    title: "scanDirectory(String, boolean) walks the filesystem tree twice — doubles I/O on large directories",
    location: "SecurityServiceImpl.java — scanDirectory(String, boolean) (~L10122)",
    description: "The method opens two separate Files.walk(dir) streams sequentially: the first pass counts total files to populate totalFiles for progress logging; the second pass actually scans them. Between the two walks, files can be created or deleted, causing totalFiles to be inaccurate. More critically, each Files.walk() on a large filesystem reads every directory's inode — doubling the I/O cost for a purely cosmetic progress percentage.",
    remediation: `// Use a single pass with an AtomicInteger that updates in the forEach lambda.
// Progress can be logged relative to scanned count without needing a total upfront.

AtomicInteger scanned = new AtomicInteger(0);
AtomicInteger infected = new AtomicInteger(0);

try (Stream<Path> paths = recursive ? Files.walk(dir) : Files.list(dir)) {
    paths.filter(Files::isRegularFile)
         .filter(p -> !isFileExcluded(p))
         .forEach(path -> {
             // ... scan logic ...
             int n = scanned.incrementAndGet();
             if (n % 50 == 0) logger.info("Scanned {} files, {} infected", n, infected.get());
         });
}
// No first-pass walk needed.`
  },
  {
    id: "S-05",
    severity: "Low",
    badge: "Config",
    title: "Production CORS default still lists localhost dev origins",
    location: "application-prod.properties (~L10490), application.properties (~L10542)",
    description: "Both application-prod.properties and the base application.properties contain:\n  app.cors.allowed-origins=${CORS_ALLOWED_ORIGINS:http://localhost:5000,http://localhost:3000,http://localhost:5173}\nIf CORS_ALLOWED_ORIGINS is not explicitly set in production, the server accepts cross-origin requests from three localhost dev-server addresses. On a production server this is harmless (localhost requests come from the server itself), but it is configuration bleed that signals the env var was not provided and that the deployment may not be fully configured.",
    remediation: `# application-prod.properties — no localhost fallback in production.
# If CORS_ALLOWED_ORIGINS is unset, refuse to start rather than accepting localhost.
app.cors.allowed-origins=\${CORS_ALLOWED_ORIGINS}  # no fallback — fail fast

# Add a startup validator bean:
@PostConstruct
public void validateCorsOrigins() {
    if (allowedOrigins == null || allowedOrigins.isBlank()) {
        throw new IllegalStateException(
            "CORS_ALLOWED_ORIGINS must be set in production. " +
            "Set it to the actual frontend domain (e.g. https://app.example.com).");
    }
}

# application.properties (base) — safe fallback is empty, not localhost
app.cors.allowed-origins=\${CORS_ALLOWED_ORIGINS:}`
  },
  {
    id: "S-06",
    severity: "Low",
    badge: "Config",
    title: "application-local.properties enables H2 AUTO_SERVER=TRUE — opens a TCP port",
    location: "application-local.properties (~L10437)",
    description: "The local profile sets:\n  spring.datasource.url=jdbc:h2:file:./data/antivirus_local;AUTO_SERVER=TRUE;MODE=PostgreSQL\nAUTO_SERVER=TRUE causes H2 to start an embedded TCP server on a random port, allowing remote connections from any process on the machine. This is useful for opening H2 console in a browser while the Spring app is running, but it also means the database is accessible to any local process without credentials (H2 default SA user has no password in local profile: spring.datasource.password=).",
    remediation: `# application-local.properties — remove AUTO_SERVER=TRUE
# Use the H2 console via Spring Boot's built-in /h2-console endpoint instead.
spring.datasource.url=jdbc:h2:file:./data/antivirus_local;MODE=PostgreSQL
spring.datasource.username=sa
spring.datasource.password=localdevonly  # ← set even for local dev

# H2 console is already enabled for local via spring.h2.console.enabled=true
# Access it at http://localhost:8080/h2-console`
  },
];

const SEVERITY_CONFIG = {
  High:   { color: "#854F0B", bg: "#FAEEDA", border: "#EF9F27" },
  Medium: { color: "#185FA5", bg: "#E6F1FB", border: "#85B7EB" },
  Low:    { color: "#3B6D11", bg: "#EAF3DE", border: "#97C459" },
};

const BADGE_CONFIG = {
  Regression: { color: "#6B1E1E", bg: "#FDEAEA", border: "#E57373" },
  New:        { color: "#5C3D8F", bg: "#F0EBF9", border: "#C4A1E8" },
  Config:     { color: "#1A6040", bg: "#E3F5ED", border: "#7ECBA8" },
};

function SBadge({ severity }) {
  const c = SEVERITY_CONFIG[severity];
  return <span style={{ background: c.bg, color: c.color, border: `0.5px solid ${c.border}`, borderRadius: 6, fontSize: 11, fontWeight: 500, padding: "2px 8px" }}>{severity}</span>;
}

function TBadge({ badge }) {
  const c = BADGE_CONFIG[badge] || BADGE_CONFIG.New;
  return <span style={{ background: c.bg, color: c.color, border: `0.5px solid ${c.border}`, borderRadius: 6, fontSize: 10, fontWeight: 600, padding: "2px 7px", textTransform: "uppercase", letterSpacing: "0.05em" }}>{badge}</span>;
}

function Card({ f }) {
  const [open, setOpen] = useState(false);
  const c = SEVERITY_CONFIG[f.severity];
  return (
    <div style={{ background: "var(--color-background-primary)", border: "0.5px solid var(--color-border-tertiary)", borderLeft: `3px solid ${c.border}`, borderRadius: 10, marginBottom: 8, overflow: "hidden" }}>
      <button onClick={() => setOpen(v => !v)} style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", background: "none", border: "none", padding: "11px 16px", cursor: "pointer", textAlign: "left" }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: c.color, fontWeight: 700, minWidth: 36 }}>{f.id}</span>
        <TBadge badge={f.badge} />
        <SBadge severity={f.severity} />
        <span style={{ flex: 1, fontSize: 13, fontWeight: 500, color: "var(--color-text-primary)", marginLeft: 4, lineHeight: 1.4 }}>{f.title}</span>
        <i className={`ti ${open ? "ti-chevron-up" : "ti-chevron-down"}`} style={{ fontSize: 15, color: "var(--color-text-secondary)", flexShrink: 0 }} />
      </button>
      {open && (
        <div style={{ padding: "0 16px 16px", borderTop: "0.5px solid var(--color-border-tertiary)" }}>
          {[
            ["Location", <code style={{ fontSize: 12, background: "var(--color-background-secondary)", padding: "5px 10px", borderRadius: 6, display: "block", whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--color-text-secondary)" }}>{f.location}</code>],
            ["Description", <p style={{ margin: 0, fontSize: 13, color: "var(--color-text-secondary)", lineHeight: 1.65, whiteSpace: "pre-wrap" }}>{f.description}</p>],
            ...(f.impact ? [["Impact", <p style={{ margin: 0, fontSize: 13, color: c.color, lineHeight: 1.65, fontWeight: 500 }}>{f.impact}</p>]] : []),
            ["Remediation", <pre style={{ margin: 0, fontSize: 12, background: "var(--color-background-secondary)", padding: "11px 14px", borderRadius: 8, overflow: "auto", whiteSpace: "pre", color: "var(--color-text-primary)", lineHeight: 1.6, fontFamily: "var(--font-mono)" }}>{f.remediation}</pre>],
          ].map(([label, child]) => (
            <div key={label} style={{ marginTop: 12 }}>
              <p style={{ margin: "0 0 5px", fontSize: 10, fontWeight: 600, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.07em" }}>{label}</p>
              {child}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function AuditPart4Final() {
  const [tab, setTab] = useState("confirmed");
  const allFindings = [...confirmedFindings, ...additionalFindings];
  const byCounts = allFindings.reduce((a, f) => { a[f.severity] = (a[f.severity]||0)+1; return a; }, {});

  return (
    <div style={{ padding: "1.5rem 0", maxWidth: 720, margin: "0 auto" }}>
      <div style={{ marginBottom: "1.5rem" }}>
        <p style={{ margin: "0 0 4px", fontSize: 11, fontWeight: 600, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.07em" }}>Security audit — part 4 (final)</p>
        <p style={{ margin: "0 0 0.5rem", fontSize: 20, fontWeight: 500, color: "var(--color-text-primary)" }}>SecurityServiceImpl verified + additional findings</p>
        <p style={{ margin: 0, fontSize: 13, color: "var(--color-text-secondary)" }}>
          All 37 prior findings confirmed fixed · 1 regression detected · {allFindings.length} active findings this round
        </p>
      </div>

      {/* Score tiles */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: "1.5rem" }}>
        {[
          { label: "High", ...SEVERITY_CONFIG.High },
          { label: "Medium", ...SEVERITY_CONFIG.Medium },
          { label: "Low", ...SEVERITY_CONFIG.Low },
          { label: "Total", color: "var(--color-text-primary)", bg: "var(--color-background-secondary)", border: "var(--color-border-tertiary)" },
        ].map(t => (
          <div key={t.label} style={{ background: t.bg, border: `0.5px solid ${t.border}`, borderRadius: 10, padding: "12px 14px" }}>
            <p style={{ margin: "0 0 2px", fontSize: 22, fontWeight: 500, color: t.color }}>
              {t.label === "Total" ? allFindings.length : (byCounts[t.label] || 0)}
            </p>
            <p style={{ margin: 0, fontSize: 12, color: t.color }}>{t.label}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", borderBottom: "0.5px solid var(--color-border-tertiary)", marginBottom: "1.5rem" }}>
        {[["confirmed", `Part 4 Findings (${confirmedFindings.length})`], ["additional", `New This Pass (${additionalFindings.length})`]].map(([key, label]) => (
          <button key={key} onClick={() => setTab(key)} style={{
            padding: "8px 14px", fontSize: 13, fontWeight: 500,
            background: "none", border: "none",
            borderBottom: tab === key ? "2px solid var(--color-text-primary)" : "2px solid transparent",
            color: tab === key ? "var(--color-text-primary)" : "var(--color-text-secondary)",
            cursor: "pointer", marginBottom: -1, whiteSpace: "nowrap",
          }}>{label}</button>
        ))}
      </div>

      {tab === "confirmed" && (
        <>
          <div style={{ background: "#FDEAEA", border: "0.5px solid #E57373", borderRadius: 10, padding: "11px 14px", marginBottom: "1.25rem", fontSize: 13, color: "#6B1E1E", lineHeight: 1.7 }}>
            <strong>R-01 is the highest priority</strong> — the O-01 fix created a circular dependency where <code style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>isAdmin()</code> reads its own uninitialized field in the constructor, permanently setting <code style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>hasAdminPrivileges = false</code>. Hosts-file blocking is silently disabled in every deployment. Fix: call <code style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>canModifyHostsFile()</code> directly in the constructor.
          </div>
          {confirmedFindings.map(f => <Card key={f.id} f={f} />)}
        </>
      )}

      {tab === "additional" && (
        <>
          <div style={{ background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: 10, padding: "11px 14px", marginBottom: "1.25rem", fontSize: 13, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
            <strong style={{ color: "var(--color-text-primary)" }}>6 additional issues</strong> found in this deep read — 3 Medium performance/security issues in the LogService, hasRansomwareBehavior() and detectRootkit() logging, and 3 Low configuration issues in properties files.
          </div>
          {additionalFindings.map(f => <Card key={f.id} f={f} />)}
        </>
      )}

      <div style={{ marginTop: "2rem", borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: "1rem", fontSize: 12, color: "var(--color-text-tertiary)" }}>
        Part 4 (final) — expand any card for location, impact, and drop-in remediation code.
      </div>
    </div>
  );
}