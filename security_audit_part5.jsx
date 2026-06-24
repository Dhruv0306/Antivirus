import { useState } from "react";

const part4Summary = [
  { id: "R-01", severity: "High",   title: "DomainBlockingServiceImpl bootstrap bug: isAdmin() reads uninitialized field — hosts blocking always disabled" },
  { id: "R-02", severity: "High",   title: "hasSuspiciousNetworkBehavior() causes ~100% false-positive rate on any config/source/HTML file" },
  { id: "R-03", severity: "Medium", title: "detectRansomware() + detectTrojan() use unbounded BufferedReader — M-02 fix bypassed" },
  { id: "R-04", severity: "Medium", title: "KNOWN_MALWARE_SIGNATURES is a non-thread-safe HashSet mutated concurrently by updateVirusDefinitions()" },
  { id: "R-05", severity: "Medium", title: "detectRootkit() false-positives every dotfile, zero-byte file, /proc/ and /sys/ entry" },
  { id: "R-06", severity: "Medium", title: "MD5 still used for signature matching — collision-prone, bypassable" },
  { id: "S-01", severity: "Medium", title: "detectRootkit() logs file.getAbsolutePath() via string concatenation — path disclosure in logs" },
  { id: "S-02", severity: "Medium", title: "LogService.readAllLogLines() loads all 8 rotating log files (up to 80 MB) per request" },
  { id: "S-03", severity: "Medium", title: "hasRansomwareBehavior() calls parentDir.listFiles() per scanned file — O(n²) in large directories" },
  { id: "R-07", severity: "Low",    title: "@SuppressWarnings(null) on saveScanResult() and loadInfectedScanResult() in SecurityServiceImpl" },
  { id: "R-08", severity: "Low",    title: "updateVirusDefinitions() adds 26-char placeholder — never matches any MD5 hash; endpoint is a no-op" },
  { id: "S-04", severity: "Low",    title: "scanDirectory(String, boolean) walks the tree twice (count pass + scan pass) — doubles I/O" },
  { id: "S-05", severity: "Low",    title: "Production CORS default still lists localhost:3000/5000/5173 origins" },
  { id: "S-06", severity: "Low",    title: "application-local.properties enables H2 AUTO_SERVER=TRUE — opens unauthenticated TCP port" },
];

const newFindings = [
  {
    id: "F-01",
    severity: "Medium",
    badge: "Regression",
    title: "DirectoryScan.js catch block exposes raw error strings — partial M-10 regression",
    location: "frontend/src/components/DirectoryScan.js — handleScan() catch block (~L2510)",
    description: "DirectoryScan.js correctly imports toUserMessage from errors.js, but the catch block never calls it:\n\n  const errorMessage = err.response?.data?.error || err.message || 'Unknown error';\n  setError('Error scanning directory: ' + errorMessage);\n\nThis exposes two unsafe sources: (1) err.response?.data?.error — a raw server-side error string that may contain file paths or internal details; (2) err.message — an Axios error string like 'Request failed with status code 413' or 'Network Error: connect ECONNREFUSED 127.0.0.1:8080'. Both reach the user's screen. FileScan.js and NetworkScan.js correctly use toUserMessage(); DirectoryScan.js is the sole regression.",
    impact: "Internal server errors, file-path information from the backend, and raw Axios error messages are displayed in the UI, aiding reconnaissance of the server stack.",
    remediation: `// DirectoryScan.js — replace the manual error extraction with toUserMessage()
} catch (err) {
    logError('Scan error:', err);
    // BEFORE (exposes raw strings):
    // const errorMessage = err.response?.data?.error || err.message || 'Unknown error';
    // setError('Error scanning directory: ' + errorMessage);

    // AFTER (safe, normalised):
    setError(toUserMessage(err));  // already imported at the top of the file
} finally {
    setScanning(false);
}`
  },
  {
    id: "F-02",
    severity: "Medium",
    badge: "New",
    title: "No OWASP Dependency-Check plugin in pom.xml — CVE scanning absent from build pipeline",
    location: "pom.xml — <build><plugins> section (~L361)",
    description: "pom.xml has no OWASP Dependency-Check Maven plugin, no Snyk integration, and no automated CVE scanning. The build will succeed even if a transitive dependency with a known critical CVE is introduced. H2's runtime scope means it ships with the application JAR; H2 had CVE-2022-45868 (unauthenticated RCE via the web console URL trick) — the console is now correctly disabled, but future H2 CVEs would go undetected. Spring Boot 3.4.5 is current, but its transitive tree includes ~80 JARs none of which are currently checked.",
    impact: "Vulnerable transitive dependencies can be silently introduced with each mvn update or dependency version bump, with no automated detection.",
    remediation: `<!-- pom.xml — add dependency check to the build lifecycle -->
<build>
  <plugins>
    <!-- OWASP Dependency Check — fails build on CVSS >= 7 -->
    <plugin>
      <groupId>org.owasp</groupId>
      <artifactId>dependency-check-maven</artifactId>
      <version>10.0.3</version>
      <configuration>
        <failBuildOnCVSS>7</failBuildOnCVSS>
        <suppressionFile>owasp-suppressions.xml</suppressionFile>
        <formats>
          <format>HTML</format>
          <format>JSON</format>
        </formats>
      </configuration>
      <executions>
        <execution>
          <goals><goal>check</goal></goals>
        </execution>
      </executions>
    </plugin>
  </plugins>
</build>

<!-- Also add to package.json scripts for frontend: -->
<!-- "audit": "npm audit --audit-level=high" -->
<!-- Run in CI: npm audit && mvn dependency-check:check -->`
  },
  {
    id: "F-03",
    severity: "Medium",
    badge: "New",
    title: "No Flyway dependency despite ddl-auto=validate in production — schema changes silently break prod startup",
    location: "pom.xml (~L361), application-prod.properties (~L10452)",
    description: "application-prod.properties sets spring.jpa.hibernate.ddl-auto=validate, which tells Hibernate to validate that the DB schema matches the JPA entities at startup. If any entity field is added, renamed, or typed differently, Spring Boot fails to start with a SchemaManagementException. There is no Flyway or Liquibase dependency in pom.xml to manage schema migrations. The only schema management path is: modify entity → change dev profile runs update → dump schema → manually apply to prod. This is entirely manual and undocumented, making any entity change a potential outage.",
    impact: "Any entity-level code change (e.g. adding a new column to ScanResult) immediately breaks the production deployment with no automated migration path. Rollback requires a manual DB schema patch.",
    remediation: `<!-- pom.xml — add Flyway for automated schema migrations -->
<dependency>
    <groupId>org.flywaydb</groupId>
    <artifactId>flyway-core</artifactId>
    <!-- version managed by Spring Boot parent -->
</dependency>

<!-- Create migration files in src/main/resources/db/migration/ -->
<!-- V1__initial_schema.sql — dump the current schema from dev H2 -->
<!-- V2__add_owner_to_scan_result.sql — each future change gets a numbered migration -->

<!-- application-prod.properties -->
spring.flyway.enabled=true
spring.flyway.locations=classpath:db/migration
spring.flyway.validate-on-migrate=true
spring.jpa.hibernate.ddl-auto=none  <!-- Flyway owns the schema, not Hibernate -->

<!-- application-dev.properties -->
spring.flyway.enabled=false   <!-- Dev still uses ddl-auto=update for speed -->
spring.jpa.hibernate.ddl-auto=update`
  },
  {
    id: "F-04",
    severity: "Low",
    badge: "New",
    title: "Dashboard.js scan history never auto-loads — empty table on every page load",
    location: "frontend/src/components/Dashboard.js — useEffect (~L1875), fetchScanHistory() (~L1904)",
    description: "The component's useEffect calls only fetchStatus() (system status) and sets up a 5-second interval for it. fetchScanHistory() is defined separately but is only called from handleRefresh() (the manual refresh button). Consequences: (1) the scan history table is permanently empty on page load; (2) the useEffect depends on [historyPage, historyRowsPerPage] but neither variable is used inside the effect — pagination controls silently do nothing. Users must manually click Refresh to see any scan history, defeating the purpose of pagination.",
    impact: "Broken UX: scan history appears unavailable until the user discovers the Refresh button. Pagination is non-functional.",
    remediation: `// Dashboard.js — call fetchScanHistory() inside the useEffect,
// and keep separate effects for status polling and history pagination.

// Effect 1: poll system status every 5 seconds
useEffect(() => {
    const controller = new AbortController();
    const fetchStatus = async () => {
        try {
            const res = await antivirusApi.get('/system/status', { signal: controller.signal });
            setSystemStatus(res.data);
            setError(null);
        } catch (err) {
            if (err.name !== 'CanceledError' && err.code !== 'ERR_CANCELED')
                setError(toUserMessage(err));
        } finally { setLoading(false); setRefreshing(false); }
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => { controller.abort(); clearInterval(interval); };
}, []); // ← no pagination deps here

// Effect 2: reload scan history when page or page size changes
useEffect(() => {
    fetchScanHistory();
}, [historyPage, historyRowsPerPage]); // ← pagination deps belong here`
  },
  {
    id: "F-05",
    severity: "Low",
    badge: "New",
    title: "Dashboard.js handleRefresh() calls fetchSystemStatus() without AbortController",
    location: "frontend/src/components/Dashboard.js — fetchSystemStatus() (~L1893), handleRefresh() (~L1916)",
    description: "The component defines two functions that both fetch /system/status: fetchStatus() inside the useEffect (correctly uses AbortController) and fetchSystemStatus() outside it (no AbortController). handleRefresh() calls fetchSystemStatus(), which will attempt to call setSystemStatus(), setLoading(), and setRefreshing() even if the component has been unmounted between when the user clicked Refresh and when the response arrives. This triggers the React 'state update on unmounted component' pattern — a memory leak in React 17 and a silent no-op in React 18, but still dead code that should be removed.",
    impact: "Minor memory leak in React 17 environments. In React 18 it's a silent no-op. Either way, the duplicate function creates maintenance confusion.",
    remediation: `// Dashboard.js — remove fetchSystemStatus() entirely.
// Expose a ref-based trigger pattern so handleRefresh() can trigger the effect's logic.

const triggerRefreshRef = useRef(null);

// Inside useEffect, expose the fetchStatus function via ref:
triggerRefreshRef.current = fetchStatus;

// handleRefresh uses the ref — no duplicate function needed:
const handleRefresh = () => {
    setRefreshing(true);
    triggerRefreshRef.current?.();
    fetchScanHistory();
};`
  },
  {
    id: "F-06",
    severity: "Low",
    badge: "Config",
    title: "vite.config.js uses process.env.NODE_ENV instead of the defineConfig({ mode }) callback",
    location: "frontend/vite.config.js — esbuild.drop config (~L482)",
    description: "The esbuild.drop config reads process.env.NODE_ENV at the time vite.config.js is evaluated. This works with vite build (which sets NODE_ENV=production before evaluating the config) but is fragile: if a CI/CD pipeline or deploy script sets NODE_ENV externally before launching vite build — for example, to NODE_ENV=test for a preview build — the drop condition evaluates incorrectly and console statements may be retained or incorrectly dropped in non-production builds. The Vite documentation recommends the defineConfig(({ mode }) => ...) callback form which is evaluated after Vite resolves the mode from CLI flags.",
    impact: "In certain CI/CD configurations, console.log statements may not be stripped in production builds, leaking debug information. Or they may be incorrectly stripped in preview/test builds, silencing diagnostics.",
    remediation: `// vite.config.js — use the callback form so mode is resolved by Vite
import { defineConfig, transformWithEsbuild } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => ({   // ← callback form
  plugins: [
    {
      name: 'treat-js-files-as-jsx',
      async transform(code, id) {
        if (!id.match(/src\\/.*\\.js$/)) return null;
        return transformWithEsbuild(code, id, {
          loader: 'jsx',
          jsx: 'automatic',
        });
      },
    },
    react(),
  ],
  esbuild: {
    // mode is 'production' only when --mode production is used (vite build default)
    drop: mode === 'production' ? ['console', 'debugger'] : [],
  },
  server: { port: 5000, strictPort: true },
  preview: { port: 5000 },
  optimizeDeps: {
    esbuildOptions: { loader: { '.js': 'jsx' } },
  },
}));`
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
  Config:     { color: "#1A5F3F", bg: "#E3F5ED", border: "#7ECBA8" },
};

function SBadge({ severity }) {
  const c = SEVERITY_CONFIG[severity];
  return (
    <span style={{ background: c.bg, color: c.color, border: `0.5px solid ${c.border}`, borderRadius: 6, fontSize: 11, fontWeight: 500, padding: "2px 8px" }}>
      {severity}
    </span>
  );
}

function TBadge({ badge }) {
  const c = BADGE_CONFIG[badge] || BADGE_CONFIG.New;
  return (
    <span style={{ background: c.bg, color: c.color, border: `0.5px solid ${c.border}`, borderRadius: 6, fontSize: 10, fontWeight: 700, padding: "2px 7px", textTransform: "uppercase", letterSpacing: "0.05em" }}>
      {badge}
    </span>
  );
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(false);
  const c = SEVERITY_CONFIG[f.severity];
  return (
    <div style={{ background: "var(--color-background-primary)", border: "0.5px solid var(--color-border-tertiary)", borderLeft: `3px solid ${c.border}`, borderRadius: 10, marginBottom: 8, overflow: "hidden" }}>
      <button onClick={() => setOpen(v => !v)} style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", background: "none", border: "none", padding: "11px 16px", cursor: "pointer", textAlign: "left" }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: c.color, fontWeight: 700, minWidth: 38 }}>{f.id}</span>
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
              <p style={{ margin: "0 0 5px", fontSize: 10, fontWeight: 700, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.07em" }}>{label}</p>
              {child}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const priorityGroups = [
  {
    label: "Ship-blocker (fix before any deployment)",
    color: "#854F0B", bg: "#FAEEDA", border: "#EF9F27",
    items: ["R-01 — hosts-file blocking silently disabled", "R-02 — trojan detector flags every config/source file", "R-04 — HashSet race condition on signature set", "F-01 — DirectoryScan exposes raw server errors"],
  },
  {
    label: "First sprint (within 3–5 days)",
    color: "#185FA5", bg: "#E6F1FB", border: "#85B7EB",
    items: ["R-03 — detectRansomware/Trojan unbounded reads (OOM)", "R-05 — detectRootkit floods dashboard with dotfile alerts", "R-06 — MD5 → SHA-256 for signature matching", "S-01 — absolute path logged via string concat in detectRootkit()", "S-02 — LogService loads 80 MB to return 5 rows", "S-03 — hasRansomwareBehavior() O(n²) directory listing", "F-02 — OWASP dependency-check plugin missing from pom.xml", "F-03 — Flyway missing; prod schema changes break startup"],
  },
  {
    label: "Second sprint (code quality & config hygiene)",
    color: "#3B6D11", bg: "#EAF3DE", border: "#97C459",
    items: ["R-07 — remove @SuppressWarnings(null) from SecurityServiceImpl", "R-08 — return 501 from updateVirusDefinitions() instead of no-op", "S-04 — single-pass directory walk (remove count pass)", "S-05 — remove localhost CORS fallback from prod properties", "S-06 — remove AUTO_SERVER=TRUE from local H2 URL", "F-04 — Dashboard scan history never auto-loads; fix useEffect deps", "F-05 — Dashboard duplicate fetchSystemStatus without AbortController", "F-06 — vite.config.js: use defineConfig({mode}) callback"],
  },
];

export default function AuditPart5() {
  const [tab, setTab] = useState("new");
  const byCounts = newFindings.reduce((a, f) => { a[f.severity] = (a[f.severity]||0)+1; return a; }, {});

  return (
    <div style={{ padding: "1.5rem 0", maxWidth: 720, margin: "0 auto" }}>
      <div style={{ marginBottom: "1.5rem" }}>
        <p style={{ margin: "0 0 4px", fontSize: 11, fontWeight: 700, color: "var(--color-text-tertiary)", textTransform: "uppercase", letterSpacing: "0.07em" }}>Security audit — part 5</p>
        <p style={{ margin: "0 0 0.5rem", fontSize: 20, fontWeight: 500, color: "var(--color-text-primary)" }}>Frontend deep-read + build pipeline findings</p>
        <p style={{ margin: 0, fontSize: 13, color: "var(--color-text-secondary)" }}>
          Complete read of all {"{"}56{"}"} source files · {newFindings.length} new findings · master fix priority list
        </p>
      </div>

      {/* Scoreboard */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: "1.5rem" }}>
        {["Medium","Low"].concat(["Total"]).map((label) => {
          const c = SEVERITY_CONFIG[label] || { color: "var(--color-text-primary)", bg: "var(--color-background-secondary)", border: "var(--color-border-tertiary)" };
          const n = label === "Total" ? newFindings.length : (byCounts[label] || 0);
          return (
            <div key={label} style={{ background: c.bg, border: `0.5px solid ${c.border}`, borderRadius: 10, padding: "12px 14px" }}>
              <p style={{ margin: "0 0 2px", fontSize: 22, fontWeight: 500, color: c.color }}>{n}</p>
              <p style={{ margin: 0, fontSize: 12, color: c.color }}>{label === "Total" ? "New this pass" : label}</p>
            </div>
          );
        })}
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", borderBottom: "0.5px solid var(--color-border-tertiary)", marginBottom: "1.5rem" }}>
        {[["new", `New Findings (${newFindings.length})`], ["p4ref", `Part 4 Reference (${part4Summary.length})`], ["priority", "Master Fix Priority"]].map(([key, label]) => (
          <button key={key} onClick={() => setTab(key)} style={{ padding: "8px 13px", fontSize: 12, fontWeight: 500, background: "none", border: "none", borderBottom: tab === key ? "2px solid var(--color-text-primary)" : "2px solid transparent", color: tab === key ? "var(--color-text-primary)" : "var(--color-text-secondary)", cursor: "pointer", marginBottom: -1, whiteSpace: "nowrap" }}>
            {label}
          </button>
        ))}
      </div>

      {tab === "new" && (
        <div>
          <div style={{ background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: 10, padding: "11px 14px", marginBottom: "1.25rem", fontSize: 13, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
            <strong style={{ color: "var(--color-text-primary)" }}>Six new findings</strong> from a line-by-line read of all 56 files. The highest priority is <strong>F-01</strong>: DirectoryScan.js imports <code style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>toUserMessage</code> but the catch block never calls it — raw server error strings reach the UI. Also notable: <strong>F-02</strong> (no CVE scanning in the build) and <strong>F-03</strong> (no schema migration tool despite validate mode in prod).
          </div>
          {newFindings.map(f => <FindingCard key={f.id} f={f} />)}
        </div>
      )}

      {tab === "p4ref" && (
        <div>
          <div style={{ background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: 10, padding: "11px 14px", marginBottom: "1.25rem", fontSize: 13, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
            <strong style={{ color: "var(--color-text-primary)" }}>Part 4 findings (R-01–R-08, S-01–S-06)</strong> — all source-confirmed in this pass. Expand the Parts 4 artifacts for full descriptions and remediation code.
          </div>
          {part4Summary.map(f => (
            <div key={f.id} style={{ display: "flex", gap: 10, padding: "9px 14px", background: "var(--color-background-primary)", border: "0.5px solid var(--color-border-tertiary)", borderLeft: `3px solid ${SEVERITY_CONFIG[f.severity].border}`, borderRadius: 10, marginBottom: 6 }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: SEVERITY_CONFIG[f.severity].color, fontWeight: 700, minWidth: 38 }}>{f.id}</span>
              <SBadge severity={f.severity} />
              <span style={{ fontSize: 13, color: "var(--color-text-secondary)", lineHeight: 1.5, marginLeft: 4 }}>{f.title}</span>
            </div>
          ))}
        </div>
      )}

      {tab === "priority" && (
        <div>
          <div style={{ background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: 10, padding: "11px 14px", marginBottom: "1.25rem", fontSize: 13, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
            <strong style={{ color: "var(--color-text-primary)" }}>Complete priority-ordered fix list</strong> across all audit rounds — 22 active findings across three phases. Each group is a gate: don't ship until the previous group is closed.
          </div>
          {priorityGroups.map((group, gi) => (
            <div key={gi} style={{ border: `0.5px solid ${group.border}`, borderLeft: `3px solid ${group.border}`, borderRadius: 10, marginBottom: "1rem", overflow: "hidden" }}>
              <div style={{ background: group.bg, padding: "9px 14px" }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: group.color }}>{`Phase ${gi + 1} — `}</span>
                <span style={{ fontSize: 13, color: group.color }}>{group.label}</span>
              </div>
              <div style={{ background: "var(--color-background-primary)" }}>
                {group.items.map((item, ii) => (
                  <div key={ii} style={{ display: "flex", alignItems: "flex-start", gap: 8, padding: "7px 14px", borderBottom: ii < group.items.length - 1 ? "0.5px solid var(--color-border-tertiary)" : "none" }}>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: group.color, fontWeight: 700, minWidth: 38, paddingTop: 1 }}>{item.split(" — ")[0]}</span>
                    <span style={{ fontSize: 13, color: "var(--color-text-secondary)", lineHeight: 1.5 }}>{item.split(" — ")[1]}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      <div style={{ marginTop: "2rem", borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: "1rem", fontSize: 12, color: "var(--color-text-tertiary)" }}>
        Part 5 — complete audit across all 56 files. Use the Master Fix Priority tab for the consolidated remediation plan.
      </div>
    </div>
  );
}