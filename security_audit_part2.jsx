import { useState } from "react";

const additionalFindings = [
  {
    id: "H-07",
    severity: "High",
    title: "NetworkSecurity.js bypasses auth interceptor with hardcoded axios calls",
    location: "frontend/src/components/NetworkSecurity.js (~L4171, L4182, L4193, L4204)",
    description: "NetworkSecurity.js imports axios directly and calls hardcoded http://localhost:8080 URLs — completely bypassing the authenticated axios client in api/client.js. The result is that every request it makes carries no Authorization header. In any environment other than local dev the requests fail with HTTP 401 silently. Additionally the hardcoded host makes the component non-deployable.",
    impact: "Silent auth failure in staging/production. Any firewall toggle, domain removal, or status poll is unauthorized and returns 401, leaving the UI in a permanently stale state.",
    remediation: `// NetworkSecurity.js — use the shared authenticated client, not raw axios
import { networkSecurityApi, antivirusApi } from '../api/client';  // ← not axios

// Replace every raw axios call:
// BEFORE
const response = await axios.get('http://localhost:8080/api/antivirus/network/status');
// AFTER
const response = await antivirusApi.get('/network/status');

// BEFORE
await axios.post('http://localhost:8080/api/antivirus/network/firewall', { enabled: !firewallEnabled });
// AFTER
await networkSecurityApi.post('/firewall/toggle', { enabled: !firewallEnabled });

// BEFORE
await axios.delete(\`http://localhost:8080/api/antivirus/network/blocked-domains/\${domain}\`);
// AFTER
await networkSecurityApi.post('/unblock', { domain });`,
  },
  {
    id: "H-08",
    severity: "High",
    title: "Exception messages from IOException leaked into API response bodies",
    location: "src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java (~L8791, L8863), src/main/java/com/antivirus/service/impl/SystemMonitorService.java (~L9496)",
    description: "ScanResult.threatDetails is set directly to exception messages: errorResult.setThreatDetails(\"Error accessing directory: \" + e.getMessage()). Java IOException messages routinely contain: full absolute file paths, OS error codes (e.g. \"Permission denied: /etc/shadow\"), and kernel-level error descriptions. All of these are serialized into the JSON response body returned to the browser.",
    impact: "Filesystem layout, sensitive paths, and OS internals disclosed to every authenticated user. Aids directory traversal and privilege escalation planning.",
    remediation: `// SecurityServiceImpl.java — use a safe, opaque message for user-facing fields
// Log the detailed message internally, expose only a code externally

private static final Map<String, String> SAFE_ERROR_MESSAGES = Map.of(
    "ACCESS_DENIED",  "Access denied to this path",
    "IO_ERROR",       "Could not read file",
    "SCAN_ERROR",     "Scan could not be completed"
);

// Inside scanDirectory catch block:
} catch (AccessDeniedException e) {
    logger.debug("Access denied to path: {}", path); // detail stays in logs only
    ScanResult errorResult = new ScanResult();
    errorResult.setFilePath(path.getFileName().toString()); // filename only, not full path
    errorResult.setInfected(false);
    errorResult.setThreatType("ERROR");
    errorResult.setThreatDetails(SAFE_ERROR_MESSAGES.get("ACCESS_DENIED")); // ← safe message
    results.add(errorResult);
} catch (IOException e) {
    logger.error("IO error at path {}", path, e);
    ScanResult errorResult = new ScanResult();
    errorResult.setFilePath(path.getFileName().toString());
    errorResult.setThreatType("ERROR");
    errorResult.setThreatDetails(SAFE_ERROR_MESSAGES.get("IO_ERROR")); // ← safe message
    results.add(errorResult);
}`,
  },
  {
    id: "H-09",
    severity: "High",
    title: "@Transactional on performSystemScan() holds DB connection for full scan duration",
    location: "src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java — @Transactional on performSystemScan() (~L8743)",
    description: "@Transactional on performSystemScan() opens a database connection at the start of the method and holds it open until the entire recursive filesystem scan completes — potentially hours on large drives. HikariCP's default pool size is 10. Two simultaneous system scans plus normal API traffic will exhaust the pool, blocking all queries across the entire application including login checks.",
    impact: "Full application DoS from connection pool exhaustion. Two concurrent scan requests can deny all other users of database access.",
    remediation: `// SecurityServiceImpl.java — remove @Transactional from performSystemScan()
// and save results in batches instead

@Override
// @Transactional  ← REMOVE THIS
public List<ScanResult> performSystemScan() {
    // ...scan logic stays the same...
}

// Inside the scan loop, flush to DB in bounded batches to avoid OOM:
private static final int FLUSH_BATCH_SIZE = 100;

private void scanDirectory(Path dir, /* ... */, List<ScanResult> results, /* ... */) {
    // ... existing logic ...
    results.add(result);

    // Persist eagerly and release memory
    if (results.size() >= FLUSH_BATCH_SIZE) {
        scanResultRepository.saveAll(results);
        results.clear();
    }
}

// Final flush after loop in performSystemScan():
if (!results.isEmpty()) {
    scanResultRepository.saveAll(results);
    results.clear();
}`,
  },
  {
    id: "M-07",
    severity: "Medium",
    title: "spring.jpa.hibernate.ddl-auto=update in base application.properties",
    location: "src/main/resources/application.properties (~L9728)",
    description: "ddl-auto=update tells Hibernate to automatically modify production database schema on every startup. This is safe in local dev but catastrophic in production: it can drop columns that Hibernate thinks are unused, corrupt indexes, or apply partial schema changes if startup is interrupted. The prod profile (application-prod.properties) does not override this setting.",
    impact: "Irreversible production data loss on schema change. No change-controlled migration path.",
    remediation: `# application.properties (base)
spring.jpa.hibernate.ddl-auto=none   # ← safe default for all profiles

# application-dev.properties — only dev gets update/create-drop
spring.jpa.hibernate.ddl-auto=update

# application-prod.properties — explicit validate (Flyway/Liquibase manages schema)
spring.jpa.hibernate.ddl-auto=validate

# Add Flyway to pom.xml for proper migration control:
# <dependency>
#   <groupId>org.flywaydb</groupId>
#   <artifactId>flyway-core</artifactId>
# </dependency>`,
  },
  {
    id: "M-08",
    severity: "Medium",
    title: "Dashboard polls every 5 seconds without cancelling in-flight requests",
    location: "frontend/src/components/Dashboard.js (~L1834-1852), frontend/src/components/NetworkScan.js (~L3371-3379)",
    description: "setInterval(fetchSystemStatus, 5000) fires every 5 seconds but never cancels the previous in-flight axios request. If the server is slow and a request takes >5 seconds, multiple requests queue up. On component unmount the interval is cleared but any in-flight request still calls setScanHistory() on an unmounted component, causing a React state-update-on-unmounted-component warning and a potential memory leak. Dashboard polls at 5-second intervals and NetworkScan at 30-second intervals — both unconditionally.",
    impact: "Cascading request pile-up under slow server conditions; React memory leaks on navigation; unnecessary server load even when the tab is inactive.",
    remediation: `// Dashboard.js — use AbortController to cancel in-flight requests
useEffect(() => {
    const controller = new AbortController();
    
    const fetchStatus = async () => {
        try {
            const response = await antivirusApi.get('/system/status', {
                signal: controller.signal
            });
            setSystemStatus(response.data);
            setError(null);
        } catch (err) {
            if (err.name !== 'CanceledError') { // ignore abort
                setError('Error fetching status: ' + err.message);
            }
        } finally {
            setLoading(false);
            setRefreshing(false);
        }
    };

    fetchStatus(); // initial fetch
    const interval = setInterval(fetchStatus, 5000);
    
    return () => {
        controller.abort();      // cancel in-flight request
        clearInterval(interval); // stop scheduling new ones
    };
}, []);`,
  },
  {
    id: "M-09",
    severity: "Medium",
    title: "Verbose console.log of full API response bodies in production builds",
    location: "frontend/src/components/NetworkScan.js (~L3399, L3414, L3450, L3454, L3529, L3534), frontend/src/components/FileScan.js (~L2852)",
    description: "Numerous console.log() calls dump full API response bodies to the browser console: console.log('Network status response:', response.data), console.log('Firewall toggle response:', response.data), and console.log('Blocking domain:', newDomain). Vite does not strip console statements in production builds by default. Any user who opens DevTools — including the target of a social-engineering attack — can see network topology, blocked domain lists, and security control states.",
    impact: "Sensitive operational data (firewall state, blocked IPs, domain lists) visible to all users via browser DevTools. Aids targeted attacks.",
    remediation: `// vite.config.js — strip console.log in production builds
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => ({
    plugins: [react()],
    esbuild: {
        drop: mode === 'production' ? ['console', 'debugger'] : [],
    },
    // ...rest of config
}));

// For development, replace console.log with a toggled logger utility:
// src/utils/logger.js
const isDev = import.meta.env.DEV;
export const log = isDev ? console.log.bind(console) : () => {};
export const logError = isDev ? console.error.bind(console) : () => {};

// Components use: import { log, logError } from '../utils/logger';
// instead of bare console.log / console.error`,
  },
  {
    id: "M-10",
    severity: "Medium",
    title: "Dashboard renders raw server error strings directly in JSX",
    location: "frontend/src/components/Dashboard.js (~L1885), frontend/src/components/NetworkScan.js (~L3430), frontend/src/components/SystemScan.js (~L4876)",
    description: "Error messages from API responses are passed directly into state and then rendered as {error} inside MUI <Alert> components. React does escape string children, so stored XSS via a reflected error message is not directly exploitable here. However, the pattern becomes dangerous if any component ever switches to dangerouslySetInnerHTML, and it also means that raw internal error strings (including the exception message leakage found in H-08) are displayed verbatim to users.",
    impact: "Exposes internal error detail to users; sets a pattern that leads to XSS if any future component uses dangerouslySetInnerHTML.",
    remediation: `// Create a centralized error normalizer that maps server errors to safe UX messages
// src/utils/errors.js
const USER_MESSAGES = {
    401: 'Authentication required. Please log in again.',
    403: 'You do not have permission to perform this action.',
    409: 'A scan is already in progress.',
    413: 'Too many files. Please reduce the selection.',
    500: 'A server error occurred. Please try again.',
    default: 'An unexpected error occurred.',
};

export function toUserMessage(error) {
    if (!error?.response) {
        return error?.code === 'ERR_NETWORK'
            ? 'Cannot reach the server. Check your connection.'
            : USER_MESSAGES.default;
    }
    return USER_MESSAGES[error.response.status] ?? USER_MESSAGES.default;
}

// Component usage:
} catch (err) {
    setError(toUserMessage(err)); // never exposes raw server strings
}`,
  },
  {
    id: "L-05",
    severity: "Low",
    title: "isAdmin() calls canModifyHostsFile() on every invocation — non-idempotent privilege check",
    location: "src/main/java/com/antivirus/service/impl/DomainBlockingServiceImpl.java — isAdmin() (~L7868)",
    description: "isAdmin() is defined as return canModifyHostsFile(Paths.get(hostsFilePath)), which performs a live filesystem check on every call. The constructor also calls isAdmin() and stores the result in hasAdminPrivileges, but the public isAdmin() bypasses the stored field. This means callers get a live re-check rather than the cached startup result, and the two values can diverge if file permissions change at runtime.",
    impact: "Logic inconsistency if the hosts file permissions change mid-run; unnecessary filesystem I/O on every status endpoint call.",
    remediation: `// DomainBlockingServiceImpl.java — return the cached field
@Override
public boolean isAdmin() {
    return hasAdminPrivileges;  // use the field set at construction time
}

// If you need a live re-check at runtime (e.g. after privilege escalation),
// add an explicit method like refreshPrivilegeCheck() that updates the field:
public void refreshPrivilegeCheck() {
    this.hasAdminPrivileges = canModifyHostsFile(Paths.get(hostsFilePath));
    this.hostsFileAccessible = hasAdminPrivileges;
}`,
  },
  {
    id: "L-06",
    severity: "Low",
    title: "H2 database path exposed in public README and default DB URL",
    location: "README.md (~L179), src/main/resources/application.properties (DB_URL default ~L9720)",
    description: "The README advertises http://localhost:8080/h2-console as a public URL, and the default spring.datasource.url uses a relative file path (./data/antivirus_v3). H2 console is correctly disabled in application.properties (spring.h2.console.enabled=false), but the dev profile re-enables it unconditionally. Because the dev profile is the default, any deployment that does not explicitly set SPRING_PROFILES_ACTIVE=prod will have H2 console exposed. The relative file path also leaks the process working directory.",
    impact: "H2 console gives unauthenticated (or authenticated) users a full SQL interface to the production database in any deployment running the default dev profile.",
    remediation: `# application-dev.properties — restrict H2 console to localhost only
spring.h2.console.enabled=true
spring.h2.console.settings.web-allow-others=false  # already default but be explicit

# SecurityConfig.java — if dev profile is active, require auth for H2 console
@Bean
@Profile("dev")
public SecurityFilterChain h2ConsoleChain(HttpSecurity http) throws Exception {
    http
        .securityMatcher("/h2-console/**")
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/h2-console/**").hasRole("ADMIN"))
        .httpBasic(Customizer.withDefaults())
        .headers(h -> h.frameOptions(f -> f.sameOrigin()))
        .csrf(csrf -> csrf.disable());
    return http.build();
}`,
  },
];

const SEVERITY_CONFIG = {
  Critical: { color: "#A32D2D", bg: "#FCEBEB", border: "#F09595" },
  High: { color: "#854F0B", bg: "#FAEEDA", border: "#EF9F27" },
  Medium: { color: "#185FA5", bg: "#E6F1FB", border: "#85B7EB" },
  Low: { color: "#3B6D11", bg: "#EAF3DE", border: "#97C459" },
};

const roadmap = [
  {
    phase: "Phase 1",
    label: "Before any deployment",
    duration: "1–2 days",
    color: "#A32D2D",
    bg: "#FCEBEB",
    border: "#F09595",
    items: [
      { id: "C-01", text: "Fix hash algorithm mismatch (MD5 → SHA-256 signatures)" },
      { id: "C-02", text: "Remove all hardcoded credential defaults; add startup validator" },
      { id: "C-03", text: "Replace Base64 sessionStorage with HttpOnly session cookie" },
      { id: "C-04", text: "Re-enable CSRF with CookieCsrfTokenRepository" },
      { id: "C-05", text: "Purge VITE_API_PASSWORD from all env files and bundle" },
      { id: "M-07", text: "Switch ddl-auto from update to validate + add Flyway" },
    ],
  },
  {
    phase: "Phase 2",
    label: "Within first sprint",
    duration: "3–5 days",
    color: "#854F0B",
    bg: "#FAEEDA",
    border: "#EF9F27",
    items: [
      { id: "H-01", text: "Add @JsonIgnore to filePath; expose only getDisplayName()" },
      { id: "H-02", text: "Add Bucket4j rate limiter filter on /api/**" },
      { id: "H-03", text: "Make system scan async with job ID + status polling endpoint" },
      { id: "H-04", text: "Parallel port scan with bounded ExecutorService" },
      { id: "H-05", text: "Remove user filename from temp file suffix; add content-type allowlist" },
      { id: "H-06", text: "Add full security header suite via Spring Security" },
      { id: "H-07", text: "Replace raw axios in NetworkSecurity.js with authenticated client" },
      { id: "H-08", text: "Replace exception messages in threatDetails with opaque error codes" },
      { id: "H-09", text: "Remove @Transactional from performSystemScan(); batch-save" },
    ],
  },
  {
    phase: "Phase 3",
    label: "Within second sprint",
    duration: "3–5 days",
    color: "#185FA5",
    bg: "#E6F1FB",
    border: "#85B7EB",
    items: [
      { id: "M-01", text: "Switch .matches() → .find(); tighten malware regex patterns" },
      { id: "M-02", text: "Stream file content instead of readAllBytes; cap at 10 MB" },
      { id: "M-03", text: "Add ZIP-bomb entry count and uncompressed-size limit" },
      { id: "M-04", text: "Add audit logging on quarantine/delete with actor identity" },
      { id: "M-05", text: "Replace LogService manual file writes with SLF4J rolling appender" },
      { id: "M-06", text: "Move background monitor to @Scheduled; remove raw Thread()" },
      { id: "M-08", text: "Add AbortController to all polling useEffect hooks" },
      { id: "M-09", text: "Configure Vite to strip console statements in production" },
      { id: "M-10", text: "Centralize error normalization to prevent raw server strings in UI" },
    ],
  },
  {
    phase: "Phase 4",
    label: "Housekeeping",
    duration: "1 day",
    color: "#3B6D11",
    bg: "#EAF3DE",
    border: "#97C459",
    items: [
      { id: "L-01", text: "Implement or remove stub authenticateUser/authorizeUser" },
      { id: "L-02", text: "Fix manifest.json template strings" },
      { id: "L-03", text: "Remove @SuppressWarnings(\"null\") from upload handlers" },
      { id: "L-04", text: "Add Disallow: / to robots.txt" },
      { id: "L-05", text: "Fix isAdmin() to return cached hasAdminPrivileges field" },
      { id: "L-06", text: "Restrict H2 console with auth and localhost-only access" },
    ],
  },
];

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
      borderRadius: 10,
      marginBottom: 8,
      overflow: "hidden",
    }}>
      <button onClick={() => setOpen(v => !v)} style={{
        display: "flex", alignItems: "center", gap: 10,
        width: "100%", background: "none", border: "none",
        padding: "12px 16px", cursor: "pointer", textAlign: "left",
      }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: cfg.color, fontWeight: 500, minWidth: 38 }}>{f.id}</span>
        <Badge severity={f.severity} />
        <span style={{ flex: 1, fontSize: 14, fontWeight: 500, color: "var(--color-text-primary)", marginLeft: 4 }}>{f.title}</span>
        <i className={`ti ${open ? "ti-chevron-up" : "ti-chevron-down"}`} style={{ fontSize: 16, color: "var(--color-text-secondary)" }} aria-hidden="true" />
      </button>
      {open && (
        <div style={{ padding: "0 16px 16px", borderTop: "0.5px solid var(--color-border-tertiary)" }}>
          <SectionBlock label="Location">
            <code style={{ fontSize: 12, background: "var(--color-background-secondary)", padding: "6px 10px", borderRadius: 6, display: "block", whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--color-text-secondary)" }}>{f.location}</code>
          </SectionBlock>
          <SectionBlock label="Description">
            <p style={{ margin: 0, fontSize: 14, color: "var(--color-text-secondary)", lineHeight: 1.65 }}>{f.description}</p>
          </SectionBlock>
          <SectionBlock label="Impact">
            <p style={{ margin: 0, fontSize: 14, color: cfg.color, lineHeight: 1.65, fontWeight: 500 }}>{f.impact}</p>
          </SectionBlock>
          <SectionBlock label="Remediation">
            <pre style={{ margin: 0, fontSize: 12, background: "var(--color-background-secondary)", padding: "12px 14px", borderRadius: 8, overflow: "auto", whiteSpace: "pre", color: "var(--color-text-primary)", lineHeight: 1.6, fontFamily: "var(--font-mono)" }}>{f.remediation}</pre>
          </SectionBlock>
        </div>
      )}
    </div>
  );
}

function SectionBlock({ label, children }) {
  return (
    <div style={{ marginTop: 12 }}>
      <p style={{ margin: "0 0 6px", fontSize: 11, fontWeight: 500, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</p>
      {children}
    </div>
  );
}

export default function AuditPart2() {
  const [tab, setTab] = useState("findings");
  const [filter, setFilter] = useState("All");
  const categories = ["All", "High", "Medium", "Low"];
  const counts = additionalFindings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {});
  const visible = filter === "All" ? additionalFindings : additionalFindings.filter(f => f.severity === filter);

  return (
    <div style={{ padding: "1.5rem 0", maxWidth: 720, margin: "0 auto" }}>
      <h2 className="sr-only" style={{ position: "absolute", width: 1, height: 1, overflow: "hidden" }}>
        Security audit continuation — 9 additional findings and remediation roadmap
      </h2>

      <div style={{ marginBottom: "1.5rem" }}>
        <p style={{ margin: "0 0 4px", fontSize: 11, fontWeight: 500, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Security audit — part 2</p>
        <p style={{ margin: "0 0 1rem", fontSize: 20, fontWeight: 500, color: "var(--color-text-primary)" }}>Additional findings & remediation roadmap</p>
        <p style={{ margin: 0, fontSize: 13, color: "var(--color-text-secondary)" }}>
          9 additional findings from deeper frontend/backend analysis &nbsp;·&nbsp; 31 total across both parts
        </p>
      </div>

      <div style={{ display: "flex", gap: 0, marginBottom: "1.5rem", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
        {[["findings", "Additional Findings (9)"], ["roadmap", "Remediation Roadmap"]].map(([key, label]) => (
          <button key={key} onClick={() => setTab(key)} style={{
            padding: "8px 16px",
            fontSize: 13,
            fontWeight: 500,
            background: "none",
            border: "none",
            borderBottom: tab === key ? "2px solid var(--color-text-primary)" : "2px solid transparent",
            color: tab === key ? "var(--color-text-primary)" : "var(--color-text-secondary)",
            cursor: "pointer",
            marginBottom: -1,
          }}>{label}</button>
        ))}
      </div>

      {tab === "findings" && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: "1.5rem" }}>
            {["High", "Medium", "Low"].map(s => {
              const cfg = SEVERITY_CONFIG[s];
              return (
                <div key={s} style={{ background: cfg.bg, border: `0.5px solid ${cfg.border}`, borderRadius: 10, padding: "12px 14px" }}>
                  <p style={{ margin: "0 0 2px", fontSize: 22, fontWeight: 500, color: cfg.color }}>{counts[s] || 0}</p>
                  <p style={{ margin: 0, fontSize: 12, color: cfg.color }}>{s}</p>
                </div>
              );
            })}
          </div>
          <div style={{ display: "flex", gap: 6, marginBottom: "1rem", flexWrap: "wrap" }}>
            {categories.map(c => {
              const active = filter === c;
              const cfg = c !== "All" ? SEVERITY_CONFIG[c] : null;
              return (
                <button key={c} onClick={() => setFilter(c)} style={{
                  padding: "4px 12px", fontSize: 12, fontWeight: 500, borderRadius: 20,
                  border: active ? `1.5px solid ${cfg ? cfg.border : "var(--color-border-primary)"}` : "0.5px solid var(--color-border-tertiary)",
                  background: active && cfg ? cfg.bg : "var(--color-background-primary)",
                  color: active && cfg ? cfg.color : "var(--color-text-secondary)",
                  cursor: "pointer",
                }}>{c}{c !== "All" ? ` (${counts[c] || 0})` : ` (${additionalFindings.length})`}</button>
              );
            })}
          </div>
          {visible.map(f => <FindingCard key={f.id} f={f} />)}
        </>
      )}

      {tab === "roadmap" && (
        <div>
          <div style={{ background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: 10, padding: "12px 16px", marginBottom: "1.5rem", fontSize: 13, lineHeight: 1.7, color: "var(--color-text-secondary)" }}>
            <strong style={{ color: "var(--color-text-primary)", fontWeight: 500 }}>How to use this roadmap — </strong>
            Each phase is a gate: don't ship Phase 1 items into production carrying Phase 1 issues. The effort estimates assume one mid-level engineer who knows the codebase. Phase 2 and 3 can run in parallel across two engineers. Each fix is linked to its finding ID from Parts 1 and 2.
          </div>
          {roadmap.map(phase => (
            <div key={phase.phase} style={{
              marginBottom: "1.25rem",
              border: `0.5px solid ${phase.border}`,
              borderLeft: `3px solid ${phase.border}`,
              borderRadius: 10,
              overflow: "hidden",
            }}>
              <div style={{ background: phase.bg, padding: "10px 16px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{ fontSize: 13, fontWeight: 500, color: phase.color }}>{phase.phase}</span>
                  <span style={{ fontSize: 13, color: phase.color }}>{phase.label}</span>
                </div>
                <span style={{ fontSize: 11, color: phase.color, fontFamily: "var(--font-mono)", background: "rgba(255,255,255,0.5)", padding: "2px 8px", borderRadius: 12 }}>{phase.duration}</span>
              </div>
              <div style={{ background: "var(--color-background-primary)", padding: "8px 0" }}>
                {phase.items.map((item, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 10, padding: "7px 16px", borderBottom: i < phase.items.length - 1 ? "0.5px solid var(--color-border-tertiary)" : "none" }}>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: phase.color, fontWeight: 500, minWidth: 38, paddingTop: 2 }}>{item.id}</span>
                    <span style={{ fontSize: 13, color: "var(--color-text-secondary)", lineHeight: 1.55 }}>{item.text}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}

          <div style={{ background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: 10, padding: "14px 16px", marginTop: "1.5rem" }}>
            <p style={{ margin: "0 0 8px", fontSize: 13, fontWeight: 500, color: "var(--color-text-primary)" }}>Architectural recommendations beyond individual fixes</p>
            {[
              ["Replace HTTP Basic auth entirely", "Move to a proper session or JWT flow with HttpOnly cookies. HTTP Basic sends credentials on every request; one captured request compromises the credential permanently."],
              ["Consider a proper AV SDK", "The regex-based malware scanner cannot realistically detect novel threats. For production, integrate ClamAV (via REST wrapper or JNA) or a cloud AV API (VirusTotal, Windows Defender ATP) to provide real signature databases with daily updates."],
              ["Add structured security event logging", "Create a dedicated audit log for all security events (login, logout, scan start/stop, quarantine, domain block) with a consistent schema. Store separately from application logs and archive with tamper-evident checksums."],
              ["Multi-user RBAC before sharing", "The current InMemoryUserDetailsManager supports a single admin account. If the app will serve multiple users, a JPA-backed UserDetailsService with distinct READ/WRITE/ADMIN roles must be added before Phase 2 IDOR fixes become meaningful."],
              ["Add a dependency vulnerability scan to CI", "Run mvn dependency-check:check and npm audit in your pipeline. The most recent Spring Boot parent (3.4.5) is current, but the H2 database version used at runtime warrants periodic checks."],
            ].map(([title, body], i) => (
              <div key={i} style={{ display: "flex", gap: 10, marginBottom: i < 4 ? 10 : 0 }}>
                <i className="ti ti-arrow-right" style={{ fontSize: 14, color: "var(--color-text-tertiary)", flexShrink: 0, marginTop: 3 }} aria-hidden="true" />
                <div>
                  <span style={{ fontSize: 13, fontWeight: 500, color: "var(--color-text-primary)" }}>{title} — </span>
                  <span style={{ fontSize: 13, color: "var(--color-text-secondary)" }}>{body}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div style={{ marginTop: "2rem", borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: "1rem", fontSize: 12, color: "var(--color-text-tertiary)" }}>
        Part 2 of 2 — click findings to expand or switch to the Remediation Roadmap tab for the prioritized fix plan.
      </div>
    </div>
  );
}