package com.antivirus.service.impl;

import com.antivirus.dto.PagedResponse;
import com.antivirus.model.ScanResult;
import com.antivirus.service.SecurityService;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import com.antivirus.service.SystemMonitorService;
import com.antivirus.repository.ScanResultRepository;
import com.antivirus.service.LogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.stream.Stream;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryStream;

@Service
public class SecurityServiceImpl implements SecurityService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityServiceImpl.class);

    @Autowired
    private ScanResultRepository scanResultRepository;

    @Autowired
    private SystemMonitorService systemMonitorService;

    @SuppressWarnings("unused")
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private LogService logService;

    private final AtomicBoolean systemScanRunning = new AtomicBoolean(false);
    private final AtomicBoolean stopSystemScan = new AtomicBoolean(false);

    @SuppressWarnings("unused")
    private boolean isElevated = false;

    // Safe opaque error messages to prevent leaking sensitive info in API responses
    private static final Map<String, String> SAFE_ERROR_MESSAGES = Map.of(
            "ACCESS_DENIED", "Access denied to this path",
            "IO_ERROR", "Could not read file",
            "SCAN_ERROR", "Scan could not be completed");

    // ── R-06: Signatures updated to SHA-256 (64 hex chars) ──
    // MD5 is cryptographically broken; SHA-256 is the minimum standard
    // used by all modern threat-intel feeds (VirusTotal, MalwareBazaar).
    //
    // Known-hash lookups (EICAR plus a live threat-intel feed) are now
    // owned by ThreatIntelSignatureService, a proper Spring bean with
    // @PostConstruct + a background-thread refresh, instead of the static
    // block that used to live here. That static block ran the moment this
    // class was loaded by the JVM, which fired a real HTTP call on every
    // plain unit test run (SecurityServiceImplTest instantiates this class
    // directly, no Spring context needed to trigger a static initializer),
    // and could add several seconds to every application/test startup.
    // See ThreatIntelSignatureService for the loading/refresh logic.
    @Autowired
    private ThreatIntelSignatureService threatIntelSignatureService;

    // Suspicious file extensions
    private static final Set<String> SUSPICIOUS_EXTENSIONS = new HashSet<>(Arrays.asList(
            ".exe", ".dll", ".bat", ".cmd", ".scr", ".js", ".vbs", ".hta",
            ".sys", ".bin", ".com", ".msi", ".pif", ".gadget", ".msp",
            ".cpl", ".hta", ".msc", ".jar", ".ps1", ".psm1", ".vbe",
            ".ws", ".wsf", ".wsh", ".scr", ".sct", ".shb", ".tmp"));

    // High-signal trojan name indicators — broad terms like
    // "inject"/"payload"/"downloader" removed
    private static final Set<String> TROJAN_NAME_SIGNATURES = Set.of(
            "backdoor", "rootkit", "trojan", "remote_access",
            "stealer", "reverse_shell", "wscript.shell");

    // ── Ransomware-specific constants ──────────────────────────────────
    private static final Set<String> RANSOMWARE_EXTENSIONS = Set.of(
            ".encrypted", ".crypto", ".locked", ".crypted", ".crypt",
            ".vault", ".petya", ".wannacry", ".wcry", ".wncry",
            ".locky", ".zepto", ".thor", ".aesir", ".zzzzz");

    private static final List<Pattern> RANSOMWARE_PATTERNS = List.of(
            Pattern.compile("(?i)\\byour files have been encrypted\\b"),
            Pattern.compile("(?i)\\byour important files\\b"),
            Pattern.compile("(?i)\\bbtc wallet\\b"),
            Pattern.compile("(?i)\\.(?:onion|tor)\\b"),
            Pattern.compile("(?i)\\bdecrypt.{0,30}ransom|ransom.{0,30}decrypt\\b"),
            Pattern.compile("(?i)\\bbitcoin\\b.{0,80}(?:wallet|payment|transfer)"),
            Pattern.compile("(?i)\\bransom\\b.{0,80}(?:payment|demand|note)"));

    private final ThreadLocal<Map<String, File[]>> dirListingCache = ThreadLocal.withInitial(HashMap::new);

    private static final int MAX_SYSTEM_SCAN_RESULTS = 2_000;
    private static final long MAX_SYSTEM_SCAN_DURATION_MS = 5 * 60 * 1000L;
    private static final long MAX_PATTERN_SCAN_BYTES = 10L * 1024 * 1024L;
    private static final int MAX_PATTERN_WINDOW_CHARS = 16 * 1024;
    private static final int MAX_ZIP_ENTRIES = 1_000;
    private static final long MAX_ZIP_UNCOMPRESSED_BYTES = 500L * 1024 * 1024L;

    // ── Scoring engine ──────────────────────────────────────────────────
    // Every detector below contributes points instead of an instant true/false
    // verdict. A single weak signal (one JS pattern, one weird extension) can
    // no longer condemn a file on its own; only corroborating signals push a
    // file across the SUSPICIOUS or MALICIOUS threshold. This is what actually
    // fixes the false-positive rate, the old model treated any single regex
    // hit as proof of infection.
    private static final int SCORE_KNOWN_HASH = 100;
    private static final int SCORE_EXTENSION_MASQUERADE = 70;
    private static final int SCORE_RANSOMWARE_EXTENSION = 60;
    private static final int SCORE_RANSOMWARE_TEXT_PATTERN = 45;
    private static final int SCORE_RANSOMWARE_DIR_BEHAVIOR = 55;
    private static final int SCORE_ROOTKIT_BINARY = 65;
    private static final int SCORE_ROOTKIT_TEXT = 20;
    private static final int SCORE_TROJAN_NAME = 35;
    private static final int SCORE_STRONG_PATTERN = 30;
    private static final int SCORE_WEAK_PATTERN = 8;
    private static final int MAX_WEAK_PATTERN_SCORE = 32;
    private static final int SCORE_ZIP_SUSPICIOUS_ENTRY = 15;

    private static final int THRESHOLD_MALICIOUS = 60;
    private static final int THRESHOLD_SUSPICIOUS = 25;

    // Strong patterns require a specific, hard-to-hit combination of tokens
    // (e.g. PowerShell + a real encoding/bypass flag together, not either
    // alone). These carry real weight because legitimate code rarely matches
    // them by accident.
    private static final List<Pattern> STRONG_PATTERNS = List.of(
            Pattern.compile("(?i)\\bpowershell\\b.{0,120}(?:-enc\\b|-encodedcommand|-w\\s+hidden)"),
            Pattern.compile("(?i)\\bpowershell\\b.{0,120}downloadstring"),
            Pattern.compile("(?i)\\bpowershell\\b.{0,120}\\bbypass\\b"),
            Pattern.compile("(?i)\\bicacls\\b.{0,80}\\bgrant\\b.{0,80}\\beveryone\\b"),
            Pattern.compile("(?i)\\bconnect\\s*\\(.*\\d{1,3}(?:\\.\\d{1,3}){3}"),
            Pattern.compile("(?i)\\bpost\\b.{0,80}\\bpassword\\b.{0,80}(?:https?://|socket|connect)"),
            Pattern.compile("(?i)\\bkeylog(?:ger)?\\b.{0,80}(?:getasynckeystate|setwindowshookex|keyboard_event)"));

    // Weak patterns show up constantly in ordinary code (JS libraries, web
    // pages, admin scripts). Each one alone is near-meaningless, so they are
    // capped in total contribution rather than being individually decisive.
    private static final List<Pattern> WEAK_PATTERNS = List.of(
            Pattern.compile("(?i)\\beval\\s*\\("),
            Pattern.compile("(?i)\\bdocument\\.write\\s*\\("),
            Pattern.compile("(?i)<script\\b"),
            Pattern.compile("(?i)\\bbase64_decode\\b"),
            Pattern.compile("(?i)\\bshell_exec\\s*\\("),
            Pattern.compile("(?i)\\bruntime\\.exec\\s*\\("),
            Pattern.compile("(?i)\\bsystem\\s*\\("),
            Pattern.compile("(?i)\\bpassthru\\s*\\("),
            Pattern.compile("(?i)\\bprocess\\.spawn\\b"),
            Pattern.compile("(?i)\\bcreateprocess\\w*\\b"),
            Pattern.compile("(?i)\\bnew\\s+socket\\s*\\("),
            Pattern.compile("(?i)\\bwget\\s+https?://"),
            Pattern.compile("(?i)\\bcurl\\b.{0,80}\\s-O\\b"),
            Pattern.compile("(?i)\\breg\\b.{0,80}\\badd\\b"),
            Pattern.compile("(?i)\\bregistry\\.setvalue\\b"),
            Pattern.compile("(?i)\\.encrypt\\s*\\("),
            Pattern.compile("(?i)\\bchmod\\b.{0,40}\\b777\\b"),
            Pattern.compile("(?i)\\.upload\\s*\\("),
            Pattern.compile("(?i)\\\\startup\\\\"),
            Pattern.compile("(?i)\\\\system32\\\\drivers\\\\"),
            Pattern.compile("(?i)\\\\tasks\\\\"),
            Pattern.compile("(?i)\\bunescape\\b"),
            Pattern.compile("(?i)\\bdecode(?:uri)?\\b"),
            Pattern.compile("(?i)\\bfromcharcode\\b"));

    // Narrower kernel-manipulation phrases. Dropped the old bare "driver load"
    // pattern, since it matched routine system/driver documentation and logs.
    private static final Pattern[] KERNEL_PATTERNS = {
            Pattern.compile("(?i)kernel.{0,20}hook"),
            Pattern.compile("(?i)syscall.{0,20}table"),
            Pattern.compile("(?i)interrupt.{0,20}descriptor.{0,20}table"),
            Pattern.compile("(?i)idt.{0,20}hook"),
            Pattern.compile("(?i)process.{0,20}hiding")
    };

    // Extensions a scan directory is expected to contain in normal use.
    // Used to spot ransomware's mass-rename behavior without blocklisting
    // every non-media, non-office extension the way the old code did.
    private static final Set<String> COMMON_EXTENSIONS = Set.of(
            ".txt", ".md", ".json", ".yaml", ".yml", ".xml", ".java", ".js", ".ts", ".jsx", ".tsx",
            ".py", ".c", ".cpp", ".h", ".css", ".html", ".htm", ".jpg", ".jpeg", ".png", ".gif",
            ".bmp", ".svg", ".ico", ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".pdf", ".doc",
            ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".zip", ".rar", ".7z", ".tar", ".gz",
            ".properties", ".gitignore", ".env", ".log", ".sql", ".sh", ".bat", ".ini", ".conf",
            ".lock", ".toml", ".class", ".jar", ".exe", ".dll");

    // Lightweight result of any scoring sub-check: points contributed plus the
    // human-readable signal names that produced them (stored on ScanResult
    // for later review/audit instead of a single opaque boolean).
    private record ScoreResult(int total, List<String> signals) {
        @SuppressWarnings("unused")
        static final ScoreResult NONE = new ScoreResult(0, List.of());
    }

    // ── Generic bounded pattern scanner ───────────────────────────────
    private boolean scanWithPatterns(File file, List<Pattern> patterns) {
        try (Reader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream(file), StandardCharsets.UTF_8))) {
            char[] buffer = new char[8192];
            StringBuilder window = new StringBuilder(MAX_PATTERN_WINDOW_CHARS);
            long charsRead = 0L;
            int read;

            while ((read = reader.read(buffer)) != -1 && charsRead < MAX_PATTERN_SCAN_BYTES) {
                charsRead += read;
                window.append(buffer, 0, read);

                for (Pattern pattern : patterns) {
                    if (pattern.matcher(window).find()) {
                        logger.debug("Pattern matched: {}", pattern.pattern());
                        return true;
                    }
                }

                if (window.length() > MAX_PATTERN_WINDOW_CHARS) {
                    window.delete(0, window.length() - MAX_PATTERN_WINDOW_CHARS);
                }
            }
            return false;
        } catch (IOException e) {
            logger.error("Error scanning {} with patterns: {}",
                    file.getAbsolutePath(), e.getMessage(), e);
            return false;
        }
    }

    @Override
    public ScanResult scanFile(File file) {
        ScanResult result = new ScanResult();
        result.setFilePath(file.getAbsolutePath());
        result.setOwnerUsername(resolveCurrentUsername());
        result.setInfected(false);
        result.setVerdict("CLEAN");
        result.setRiskScore(0);
        result.setScanType("FILE");
        result.setActionTaken("NONE");

        try {
            if (!file.exists()) {
                result.setThreatType("ERROR");
                result.setThreatDetails("File does not exist");
                saveScanResult(result);
                return result;
            }

            if (!file.canRead()) {
                result.setThreatType("ERROR");
                result.setThreatDetails("Cannot read file");
                saveScanResult(result);
                return result;
            }

            // Check file size
            if (file.length() > 100 * 1024 * 1024) { // 100MB limit
                result.setThreatType("WARNING");
                result.setThreatDetails("File too large to scan");
                saveScanResult(result);
                return result;
            }

            // Calculate file hash (SHA-256 — R-06)
            String fileHash = calculateFileHash(file);

            // Check against known malware signatures (thread-safe — R-04).
            // This is the only check allowed to short-circuit straight to
            // MALICIOUS on its own: an exact hash match against a curated
            // threat-intel feed is a confirmed identification, not a heuristic.
            if (threatIntelSignatureService.isKnownMalicious(fileHash)) {
                applyVerdict(result, "MALICIOUS", "VIRUS", "Known malware signature detected",
                        SCORE_KNOWN_HASH, List.of("KNOWN_HASH_MATCH"));
                saveScanResult(result);
                logService.logScanResult(result);
                return result;
            }

            // Zip-bomb / archive-abuse protection is a resource-safety check,
            // not a content-based threat verdict, so it is reported as
            // SUSPICIOUS (not scored against the malware engine) rather than
            // folded into the malware score.
            if (isZipFile(file)) {
                ZipEvaluation zipEval = evaluateZipArchive(file);
                if (zipEval.bomb()) {
                    applyVerdict(result, "SUSPICIOUS", "WARNING",
                            "Archive exceeds safe processing limits (possible zip bomb)",
                            THRESHOLD_SUSPICIOUS, List.of("ZIP_BOMB_LIMIT_EXCEEDED"));
                    saveScanResult(result);
                    logService.logScanResult(result);
                    return result;
                }
            }

            int score = 0;
            List<String> signals = new ArrayList<>();

            byte[] header = readFilePrefix(file, 8);

            int masqueradeScore = checkExtensionMasquerade(file, header);
            if (masqueradeScore > 0) {
                score += masqueradeScore;
                signals.add("EXTENSION_MASQUERADE");
            }

            String extension = getFileExtension(file).toLowerCase();
            if (RANSOMWARE_EXTENSIONS.contains(extension)) {
                score += SCORE_RANSOMWARE_EXTENSION;
                signals.add("RANSOMWARE_EXTENSION");
            }
            if (containsRansomwarePatterns(file)) {
                score += SCORE_RANSOMWARE_TEXT_PATTERN;
                signals.add("RANSOMWARE_NOTE_TEXT");
            }
            int dirBehaviorScore = scoreRansomwareDirectoryBehavior(file);
            if (dirBehaviorScore > 0) {
                score += dirBehaviorScore;
                signals.add("RANSOMWARE_DIRECTORY_BEHAVIOR");
            }

            String fileName = file.getName().toLowerCase();
            for (String sig : TROJAN_NAME_SIGNATURES) {
                if (fileName.contains(sig)) {
                    score += SCORE_TROJAN_NAME;
                    signals.add("TROJAN_NAME_SIGNATURE");
                    break;
                }
            }

            ScoreResult patternScore = scorePatterns(file);
            score += patternScore.total();
            signals.addAll(patternScore.signals());

            ScoreResult rootkitScore = scoreRootkit(file, header);
            score += rootkitScore.total();
            signals.addAll(rootkitScore.signals());

            if (isZipFile(file)) {
                ZipEvaluation zipEval = evaluateZipArchive(file);
                if (zipEval.suspiciousEntries() > 0) {
                    score += SCORE_ZIP_SUSPICIOUS_ENTRY;
                    signals.add("ZIP_CONTAINS_EXECUTABLE_ENTRY");
                }
            }

            score = Math.min(score, 100);
            String verdict = score >= THRESHOLD_MALICIOUS ? "MALICIOUS"
                    : score >= THRESHOLD_SUSPICIOUS ? "SUSPICIOUS" : "CLEAN";

            applyVerdictFromScore(result, verdict, score, signals);

        } catch (Exception e) {
            logger.error("Error scanning file: {}", e.getMessage());
            result.setThreatType("ERROR");
            result.setThreatDetails("Error scanning file");
            result.setActionTaken("NONE");
        }

        saveScanResult(result);
        logService.logScanResult(result);
        return result;
    }

    // Sets a confirmed, single-signal verdict (currently only used for the
    // exact-hash match, which needs no scoring since it is not a heuristic).
    private void applyVerdict(ScanResult result, String verdict, String threatType, String details,
            int score, List<String> signals) {
        result.setVerdict(verdict);
        result.setRiskScore(Math.min(score, 100));
        result.setDetectionSignals(String.join(",", signals));
        result.setInfected("MALICIOUS".equals(verdict));
        result.setThreatType(threatType);
        result.setThreatDetails(details);
        result.setActionTaken("MALICIOUS".equals(verdict) ? "REPORTED" : "NONE");
    }

    // Sets the verdict derived from the aggregate heuristic score.
    private void applyVerdictFromScore(ScanResult result, String verdict, int score, List<String> signals) {
        result.setVerdict(verdict);
        result.setRiskScore(score);
        result.setDetectionSignals(signals.isEmpty() ? null : String.join(",", signals));

        switch (verdict) {
            case "MALICIOUS" -> {
                result.setInfected(true);
                result.setThreatType(inferThreatType(signals));
                result.setThreatDetails("Multiple corroborating threat signals detected (score " + score + "/100)");
                result.setActionTaken("REPORTED");
            }
            case "SUSPICIOUS" -> {
                result.setInfected(false);
                result.setThreatType("SUSPICIOUS");
                result.setThreatDetails(
                        "Some suspicious indicators found (score " + score + "/100); manual review recommended");
                result.setActionTaken("NONE");
            }
            default -> {
                result.setInfected(false);
                result.setThreatType("CLEAN");
                result.setThreatDetails("No threats detected");
                result.setActionTaken("NONE");
            }
        }
    }

    private String inferThreatType(List<String> signals) {
        for (String s : signals) {
            if (s.startsWith("RANSOMWARE")) {
                return "RANSOMWARE";
            }
            if (s.startsWith("ROOTKIT")) {
                return "ROOTKIT";
            }
            if (s.startsWith("TROJAN")) {
                return "TROJAN";
            }
        }
        return "MALWARE";
    }

    private String resolveCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return "system";
        }

        String username = authentication.getName();
        if (username == null || username.isBlank() || "anonymousUser".equalsIgnoreCase(username)) {
            return "system";
        }

        return username.trim().toLowerCase(Locale.ROOT);
    }

    private void assignOwnerIfMissing(ScanResult result) {
        if (result == null) {
            return;
        }

        String owner = result.getOwnerUsername();
        if (owner == null || owner.isBlank()) {
            result.setOwnerUsername(resolveCurrentUsername());
        }
    }

    // ── R-07: Removed @SuppressWarnings("null") — assignOwnerIfMissing()
    // already null-guards result before the save call. ──
    private ScanResult saveScanResult(ScanResult result) {
        assignOwnerIfMissing(result);
        return scanResultRepository.save(result);
    }

    // ── R-06: Switched from MD5 to SHA-256 ────────────────────────────
    // MD5 is cryptographically broken; collision attacks can bypass
    // signature matching. SHA-256 is the minimum standard used by all
    // modern threat-intel feeds (VirusTotal, MalwareBazaar).
    private String calculateFileHash(File file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream is = Files.newInputStream(file.toPath())) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) > 0) {
                md.update(buffer, 0, read);
            }
        }
        return bytesToHex(md.digest()); // now returns 64-char hex string
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    private String getFileExtension(File file) {
        String name = file.getName();
        int lastIndexOf = name.lastIndexOf(".");
        if (lastIndexOf == -1) {
            return "";
        }
        return name.substring(lastIndexOf);
    }

    // NOTE: the old scanFileContent()/containsMaliciousZipContent() pair was
    // never actually called from scanFile() (both were dead code left over
    // from an earlier version), which meant zip-bomb protection existed on
    // paper but never ran. evaluateZipArchive() below is now wired directly
    // into scanFile().

    private boolean isZipFile(File file) {
        return file.getName().toLowerCase().endsWith(".zip") ||
                file.getName().toLowerCase().endsWith(".jar") ||
                file.getName().toLowerCase().endsWith(".war");
    }

    // Resource-safety result (entry count / decompression bomb) kept separate
    // from a content-based suspicious-entry count, since the former is a
    // hard block and the latter is only a minor scoring signal.
    private record ZipEvaluation(boolean bomb, int suspiciousEntries) {
    }

    private ZipEvaluation evaluateZipArchive(File file) {
        int entryCount = 0;
        int suspiciousEntries = 0;
        long totalUncompressed = 0L;
        byte[] buffer = new byte[8192];

        try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(new FileInputStream(file)))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                entryCount++;
                if (entryCount > MAX_ZIP_ENTRIES) {
                    logger.warn("ZIP bomb suspected: entry count exceeds {}", MAX_ZIP_ENTRIES);
                    return new ZipEvaluation(true, suspiciousEntries);
                }

                // ZipEntry#getSize() is frequently -1 for entries written with
                // a data descriptor (size unknown until the entry is fully
                // read), which let oversized entries slip past a getSize()-only
                // check. Read the actual decompressed bytes instead, and bail
                // out mid-entry the moment the running total crosses the limit
                // rather than waiting for the whole entry to finish.
                int read;
                while ((read = zis.read(buffer)) != -1) {
                    totalUncompressed += read;
                    if (totalUncompressed > MAX_ZIP_UNCOMPRESSED_BYTES) {
                        logger.warn("ZIP bomb suspected: uncompressed size exceeds {} bytes",
                                MAX_ZIP_UNCOMPRESSED_BYTES);
                        return new ZipEvaluation(true, suspiciousEntries);
                    }
                }

                if (SUSPICIOUS_EXTENSIONS.contains(getFileExtension(new File(entry.getName())))) {
                    suspiciousEntries++;
                }

                zis.closeEntry();
            }
        } catch (IOException e) {
            logger.error("Error scanning ZIP file {}: {}", file.getAbsolutePath(), e.getMessage(), e);
            return new ZipEvaluation(false, 0);
        }
        return new ZipEvaluation(false, suspiciousEntries);
    }

    // Executable magic-byte check (MZ for PE, 0x7F 'ELF' for ELF binaries).
    // This is deliberately NOT used to flag files with executable extensions,
    // since every real .exe/.dll on the system would trip it. It is only
    // meaningful when the extension claims the file is something else, see
    // checkExtensionMasquerade() below.
    private boolean containsSuspiciousBytes(byte[] content) {
        try {
            if (content.length >= 4) {
                if (content[0] == 0x4D && content[1] == 0x5A) {
                    return true;
                }
                if (content[0] == 0x7F && content[1] == 0x45 &&
                        content[2] == 0x4C && content[3] == 0x46) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            logger.error("Error checking for suspicious bytes: {}", e.getMessage());
            return false;
        }
    }

    // Flags a file only when it is disguised: an executable header hiding
    // behind a non-executable extension (e.g. "invoice.pdf" that is really a
    // PE binary). A .exe or .dll legitimately having an MZ header is expected
    // and not scored at all.
    private int checkExtensionMasquerade(File file, byte[] header) {
        String ext = getFileExtension(file).toLowerCase();
        if (ext.isEmpty() || SUSPICIOUS_EXTENSIONS.contains(ext)) {
            return 0;
        }
        return containsSuspiciousBytes(header) ? SCORE_EXTENSION_MASQUERADE : 0;
    }

    // Aggregates strong- and weak-pattern hits into a single bounded score in
    // one pass over the file, instead of returning true on the first match.
    private ScoreResult scorePatterns(File file) {
        Set<String> matchedStrong = new LinkedHashSet<>();
        Set<String> matchedWeak = new LinkedHashSet<>();

        try (Reader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream(file), StandardCharsets.UTF_8))) {
            char[] buffer = new char[8192];
            StringBuilder window = new StringBuilder(MAX_PATTERN_WINDOW_CHARS);
            long charsRead = 0L;
            int read;

            while ((read = reader.read(buffer)) != -1 && charsRead < MAX_PATTERN_SCAN_BYTES) {
                charsRead += read;
                window.append(buffer, 0, read);

                for (Pattern pattern : STRONG_PATTERNS) {
                    if (pattern.matcher(window).find()) {
                        matchedStrong.add(pattern.pattern());
                    }
                }
                for (Pattern pattern : WEAK_PATTERNS) {
                    if (pattern.matcher(window).find()) {
                        matchedWeak.add(pattern.pattern());
                    }
                }

                if (window.length() > MAX_PATTERN_WINDOW_CHARS) {
                    window.delete(0, window.length() - MAX_PATTERN_WINDOW_CHARS);
                }

                // Stop early once strong matches alone already cross the
                // MALICIOUS threshold; no need to keep reading the file.
                if (matchedStrong.size() * SCORE_STRONG_PATTERN >= THRESHOLD_MALICIOUS) {
                    break;
                }
            }
        } catch (IOException e) {
            logger.error("Error scanning {} with patterns: {}",
                    file.getAbsolutePath(), e.getMessage(), e);
        }

        int strongScore = matchedStrong.size() * SCORE_STRONG_PATTERN;
        int weakScore = Math.min(matchedWeak.size() * SCORE_WEAK_PATTERN, MAX_WEAK_PATTERN_SCORE);

        List<String> signals = new ArrayList<>();
        if (strongScore > 0) {
            signals.add("STRONG_CODE_PATTERN(x" + matchedStrong.size() + ")");
        }
        if (weakScore > 0) {
            signals.add("WEAK_CODE_PATTERN(x" + matchedWeak.size() + ")");
        }
        return new ScoreResult(strongScore + weakScore, signals);
    }

    private boolean containsRansomwarePatterns(File file) {
        return scanWithPatterns(file, RANSOMWARE_PATTERNS);
    }

    private byte[] readFilePrefix(File file, int maxBytes) throws IOException {
        try (InputStream is = new BufferedInputStream(Files.newInputStream(file.toPath()));
                ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(maxBytes, 8 * 1024))) {
            byte[] buffer = new byte[8192];
            int remaining = maxBytes;
            int read;
            while (remaining > 0 && (read = is.read(buffer, 0, Math.min(buffer.length, remaining))) != -1) {
                out.write(buffer, 0, read);
                remaining -= read;
            }
            return out.toByteArray();
        }
    }

    @SuppressWarnings("unused")
    private boolean checkElevatedPrivileges() {
        try {
            String osName = System.getProperty("os.name").toLowerCase();
            if (osName.contains("windows")) {
                String programFiles = System.getenv("ProgramFiles");
                File testFile = new File(programFiles);
                return testFile.canWrite();
            } else {
                return System.getProperty("user.name").equals("root");
            }
        } catch (SecurityException e) {
            logger.warn("Unable to determine privilege level: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public List<ScanResult> performSystemScan() {
        if (!systemScanRunning.compareAndSet(false, true)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "System scan is already in progress");
        }
        stopSystemScan.set(false);
        List<ScanResult> results = new ArrayList<>(Math.min(MAX_SYSTEM_SCAN_RESULTS, 256));
        AtomicInteger scannedFiles = new AtomicInteger(0);
        AtomicInteger skippedFiles = new AtomicInteger(0);
        long scanDeadline = System.currentTimeMillis() + MAX_SYSTEM_SCAN_DURATION_MS;

        try {
            logger.info("Starting system scan...");
            File[] roots = File.listRoots();
            if (roots == null || roots.length == 0) {
                throw new RuntimeException("No root directories found");
            }

            logger.info("Found {} root directories to scan", roots.length);

            Set<String> skipDirectories = new HashSet<>(Arrays.asList(
                    "$Recycle.Bin",
                    "System Volume Information",
                    "Windows",
                    "Program Files",
                    "Program Files (x86)",
                    "ProgramData",
                    "Recovery",
                    "Config.Msi",
                    "Documents and Settings"));

            for (File root : roots) {
                if (stopSystemScan.get()) {
                    logger.info("System scan stopped by user");
                    break;
                }

                logger.info("Scanning root directory: {}", root.getAbsolutePath());

                try {
                    scanDirectory(root.toPath(), skipDirectories, results, scannedFiles, skippedFiles, scanDeadline);
                } catch (AccessDeniedException e) {
                    logger.debug("Access denied to root directory: {}", root, e);
                    ScanResult errorResult = new ScanResult();
                    errorResult.setFilePath(root.getPath());
                    errorResult.setInfected(false);
                    errorResult.setThreatType("ERROR");
                    errorResult.setThreatDetails(SAFE_ERROR_MESSAGES.get("ACCESS_DENIED"));
                    errorResult.setScanType("SYSTEM");
                    errorResult.setActionTaken("NONE");
                    saveScanResult(errorResult);
                    if (results.size() < MAX_SYSTEM_SCAN_RESULTS) {
                        results.add(errorResult);
                    }
                } catch (IOException e) {
                    logger.error("IO error scanning root directory: {}", root, e);
                    ScanResult errorResult = new ScanResult();
                    errorResult.setFilePath(root.getPath());
                    errorResult.setInfected(false);
                    errorResult.setThreatType("ERROR");
                    errorResult.setThreatDetails(SAFE_ERROR_MESSAGES.get("IO_ERROR"));
                    errorResult.setScanType("SYSTEM");
                    errorResult.setActionTaken("NONE");
                    saveScanResult(errorResult);
                    if (results.size() < MAX_SYSTEM_SCAN_RESULTS) {
                        results.add(errorResult);
                    }
                } catch (Exception e) {
                    logger.error("Unexpected error scanning root directory: {}", root, e);
                    ScanResult errorResult = new ScanResult();
                    errorResult.setFilePath(root.getPath());
                    errorResult.setInfected(false);
                    errorResult.setThreatType("ERROR");
                    errorResult.setThreatDetails(SAFE_ERROR_MESSAGES.get("SCAN_ERROR"));
                    errorResult.setScanType("SYSTEM");
                    errorResult.setActionTaken("NONE");
                    saveScanResult(errorResult);
                    if (results.size() < MAX_SYSTEM_SCAN_RESULTS) {
                        results.add(errorResult);
                    }
                }
            }

            logger.info("System scan completed. Scanned: {}, Skipped: {}, Total Results: {}",
                    scannedFiles.get(), skippedFiles.get(), results.size());
            return results;
        } catch (Exception e) {
            logger.error("Critical error during system scan: {}", e.getMessage(), e);
            throw new RuntimeException("System scan failed: " + e.getMessage(), e);
        } finally {
            systemScanRunning.set(false);
            stopSystemScan.set(false);
        }
    }

    private void scanDirectory(Path directory, Set<String> skipDirectories,
            List<ScanResult> results,
            AtomicInteger scannedFiles,
            AtomicInteger skippedFiles,
            long scanDeadline) throws IOException {
        try {
            if (stopSystemScan.get() || System.currentTimeMillis() >= scanDeadline
                    || results.size() >= MAX_SYSTEM_SCAN_RESULTS) {
                if (results.size() >= MAX_SYSTEM_SCAN_RESULTS) {
                    logger.warn("System scan capped at {} results to avoid resource exhaustion",
                            MAX_SYSTEM_SCAN_RESULTS);
                }
                if (System.currentTimeMillis() >= scanDeadline) {
                    logger.warn("System scan stopped after exceeding {} ms", MAX_SYSTEM_SCAN_DURATION_MS);
                }
                stopSystemScan.set(true);
                return;
            }

            if (skipDirectories.stream()
                    .anyMatch(dir -> directory.toString().toLowerCase().contains(dir.toLowerCase()))) {
                logger.debug("Skipping restricted directory: {}", directory);
                skippedFiles.incrementAndGet();
                return;
            }

            DirectoryStream<Path> stream = Files.newDirectoryStream(directory);
            try (stream) {
                for (Path path : stream) {
                    if (stopSystemScan.get()) {
                        return;
                    }

                    try {
                        boolean isDirectory = Files.isDirectory(path);
                        boolean isReadable = Files.isReadable(path);
                        boolean isRegularFile = Files.isRegularFile(path);

                        if (isDirectory) {
                            scanDirectory(path, skipDirectories, results, scannedFiles, skippedFiles, scanDeadline);
                        } else if (isRegularFile && isReadable) {
                            logger.debug("Scanning file: {}", path);
                            ScanResult result = scanFile(path.toFile());
                            if (results.size() < MAX_SYSTEM_SCAN_RESULTS) {
                                results.add(result);
                            } else {
                                stopSystemScan.set(true);
                                return;
                            }
                            scannedFiles.incrementAndGet();

                            if (result.isInfected()) {
                                logger.warn("Infected file found: {} (Type: {})",
                                        path, result.getThreatType());
                            }

                            if (System.currentTimeMillis() >= scanDeadline
                                    || results.size() >= MAX_SYSTEM_SCAN_RESULTS) {
                                stopSystemScan.set(true);
                                return;
                            }
                        }
                    } catch (AccessDeniedException e) {
                        logger.debug("Access denied to path: {}", path);
                        skippedFiles.incrementAndGet();
                    } catch (IOException e) {
                        logger.error("IO error processing path: {}", path, e);
                        ScanResult errorResult = new ScanResult();
                        errorResult.setFilePath(path.getFileName().toString());
                        errorResult.setInfected(false);
                        errorResult.setThreatType("ERROR");
                        errorResult.setThreatDetails(SAFE_ERROR_MESSAGES.get("IO_ERROR"));
                        errorResult.setScanType("SYSTEM");
                        errorResult.setActionTaken("NONE");
                        saveScanResult(errorResult);
                        if (results.size() < MAX_SYSTEM_SCAN_RESULTS) {
                            results.add(errorResult);
                        }
                    } catch (Exception e) {
                        logger.error("Unexpected error processing path: {}", path, e);
                        ScanResult errorResult = new ScanResult();
                        errorResult.setFilePath(path.getFileName().toString());
                        errorResult.setInfected(false);
                        errorResult.setThreatType("ERROR");
                        errorResult.setThreatDetails(SAFE_ERROR_MESSAGES.get("SCAN_ERROR"));
                        errorResult.setScanType("SYSTEM");
                        errorResult.setActionTaken("NONE");
                        saveScanResult(errorResult);
                        if (results.size() < MAX_SYSTEM_SCAN_RESULTS) {
                            results.add(errorResult);
                        }
                    }
                }
            } catch (AccessDeniedException e) {
                logger.debug("Access denied to directory: {}", directory);
                skippedFiles.incrementAndGet();
            }
        } catch (Exception e) {
            logger.error("Error scanning directory {}: {}", directory, e.getMessage());
        }
    }

    @Override
    public void stopSystemScan() {
        if (systemScanRunning.get()) {
            logger.info("Stopping system scan...");
            stopSystemScan.set(true);
        }
    }

    @Override
    public boolean isSystemScanRunning() {
        return systemScanRunning.get();
    }

    @Override
    public boolean checkNetworkSafety() {
        return systemMonitorService.isRealtimeProtectionEnabled() &&
                !systemMonitorService.getSystemStatus().containsValue(false);
    }

    @Override
    public boolean isSecureBrowsingEnabled() {
        return systemMonitorService.isRealtimeProtectionEnabled();
    }

    @Override
    public void enableSecureBrowsing() {
        systemMonitorService.enableRealtimeProtection();
    }

    @Override
    public void disableSecureBrowsing() {
        systemMonitorService.disableRealtimeProtection();
    }

    private static final int MAX_PAGE_SIZE = 100;

    @Override
    public PagedResponse<ScanResult> getScanHistory(int page, int size) {
        Pageable pageable = PageRequest.of(page, normalizePageSize(size),
                Sort.by(Sort.Direction.DESC, "scanDateTime"));
        return PagedResponse.from(scanResultRepository.findAllByOrderByScanDateTimeDesc(pageable));
    }

    @Override
    public PagedResponse<ScanResult> getInfectedFiles(int page, int size) {
        Pageable pageable = PageRequest.of(page, normalizePageSize(size),
                Sort.by(Sort.Direction.DESC, "scanDateTime"));
        return PagedResponse.from(scanResultRepository.findByInfectedTrue(pageable));
    }

    private int normalizePageSize(int size) {
        if (size < 1) {
            return 10;
        }
        return Math.min(size, MAX_PAGE_SIZE);
    }

    @Override
    public void updateVirusDefinitions() {
        logger.info("Virus definition update requested; refreshing threat-intel feed in the background");
        threatIntelSignatureService.refreshAsync();
    }

    @Override
    public void quarantineFile(File file) {
        try {
            File quarantineDir = new File("quarantine");
            if (!quarantineDir.exists() && !quarantineDir.mkdir()) {
                throw new IOException("Failed to create quarantine directory");
            }

            String safeName = UUID.randomUUID() + "_" + file.getName() + ".quarantine";
            File quarantinedFile = new File(quarantineDir, safeName);
            Files.move(file.toPath(), quarantinedFile.toPath());
        } catch (IOException e) {
            logger.error("Failed to quarantine file: {}", file.getAbsolutePath(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to quarantine file");
        }
    }

    @Override
    public void quarantineScanResult(Long scanResultId) {
        ScanResult result = loadInfectedScanResult(scanResultId);
        File file = new File(result.getFilePath());
        if (!file.exists()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "File no longer exists on disk");
        }
        quarantineFile(file);
        result.setActionTaken("QUARANTINED");
        saveScanResult(result);
    }

    @Override
    public void deleteScanResult(Long scanResultId) {
        ScanResult result = loadInfectedScanResult(scanResultId);
        File file = new File(result.getFilePath());
        deleteInfectedFile(file);
        result.setActionTaken("DELETED");
        saveScanResult(result);
    }

    // ── R-07: Removed @SuppressWarnings("null") — .orElseThrow()
    // guarantees non-null return; no suppression needed. ──
    private ScanResult loadInfectedScanResult(Long scanResultId) {
        ScanResult result = scanResultRepository.findById(scanResultId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan result not found"));
        if (!result.isInfected()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Only infected scan results can be modified");
        }
        String requestingUser = resolveCurrentUsername();
        String owner = result.getOwnerUsername();
        if (owner == null || owner.isBlank()) {
            result.setOwnerUsername(requestingUser);
            scanResultRepository.save(result);
            return result;
        }
        if (!owner.equalsIgnoreCase(requestingUser)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You are not allowed to modify this scan result");
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    @Override
    public boolean detectKeylogger() {
        List<String> suspiciousProcesses = systemMonitorService.getSystemStatus()
                .get("suspiciousProcesses") instanceof List<?>
                        ? (List<String>) systemMonitorService.getSystemStatus().get("suspiciousProcesses")
                        : new ArrayList<>();

        for (String process : suspiciousProcesses) {
            if (process.toLowerCase().contains("keylog") ||
                    process.toLowerCase().contains("hook") ||
                    process.toLowerCase().contains("keyboard")) {
                return true;
            }
        }

        return false;
    }

    // Individual detect*() methods below are kept for API/controller
    // compatibility, but now mirror the scoring model: each runs its own
    // slice of the scoring logic and only returns true once the aggregate
    // score for that category crosses THRESHOLD_MALICIOUS. This intentionally
    // makes them stricter than before, since a single weak signal (e.g. one
    // suspicious filename fragment) was previously enough to report a
    // confirmed trojan on its own.

    @Override
    public boolean detectRansomware(File file) {
        try {
            int score = 0;
            String extension = getFileExtension(file).toLowerCase();
            if (RANSOMWARE_EXTENSIONS.contains(extension)) {
                score += SCORE_RANSOMWARE_EXTENSION;
            }
            if (containsRansomwarePatterns(file)) {
                score += SCORE_RANSOMWARE_TEXT_PATTERN;
            }
            score += scoreRansomwareDirectoryBehavior(file);
            return score >= THRESHOLD_MALICIOUS;
        } catch (Exception e) {
            logger.error("Ransomware detection failed for file: {}", file.getName(), e);
            return false;
        }
    }

    // Classic ransomware behavior: many sibling files renamed to the SAME
    // unrecognized extension, alongside a ransom-note-style filename. This
    // replaces the old "extension longer than 4 chars" check, which matched
    // ordinary extensions like .json, .yaml, and .properties and flagged
    // almost any project directory containing a readme.txt.
    @SuppressWarnings("null")
    private int scoreRansomwareDirectoryBehavior(File file) {
        File parentDir = file.getParentFile();
        if (parentDir == null || !parentDir.exists()) {
            return 0;
        }

        // Use cached listing — ONE listFiles() call per directory, not per file.
        File[] files = dirListingCache.get()
                .computeIfAbsent(parentDir.getAbsolutePath(), k -> parentDir.listFiles());
        if (files == null) {
            return 0;
        }

        boolean hasRansomNote = false;
        Map<String, Integer> unknownExtCounts = new HashMap<>();
        for (File f : files) {
            String name = f.getName().toLowerCase();
            if ((name.contains("readme") && name.contains("txt")) ||
                    name.contains("how_to_decrypt") ||
                    name.contains("recovery") ||
                    name.contains("help_decrypt") ||
                    name.contains("decrypt_instructions")) {
                hasRansomNote = true;
            }
            String ext = getFileExtension(f).toLowerCase();
            if (!ext.isEmpty() && !COMMON_EXTENSIONS.contains(ext) && !RANSOMWARE_EXTENSIONS.contains(ext)) {
                unknownExtCounts.merge(ext, 1, Integer::sum);
            }
        }

        if (!hasRansomNote) {
            return 0;
        }

        int maxSameUnknownExt = unknownExtCounts.values().stream().mapToInt(Integer::intValue).max().orElse(0);
        return maxSameUnknownExt >= 5 ? SCORE_RANSOMWARE_DIR_BEHAVIOR : 0;
    }

    @Override
    public boolean detectTrojan(File file) {
        try {
            int score = 0;
            String fileName = file.getName().toLowerCase();
            for (String sig : TROJAN_NAME_SIGNATURES) {
                if (fileName.contains(sig)) {
                    score += SCORE_TROJAN_NAME;
                    break;
                }
            }
            score += scorePatterns(file).total();
            return score >= THRESHOLD_MALICIOUS;
        } catch (Exception e) {
            logger.error("Trojan detection failed for file: {}", file.getName(), e);
            return false;
        }
    }

    @Override
    public void deleteInfectedFile(File file) {
        try {
            if (!Files.deleteIfExists(file.toPath())) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "File not found");
            }
        } catch (IOException e) {
            logger.error("Failed to delete file: {}", file.getAbsolutePath(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to delete file");
        }
    }

    @Override
    public boolean detectMalware(File file) {
        try {
            String fileHash = calculateFileHash(file);
            if (threatIntelSignatureService.isKnownMalicious(fileHash)) {
                return true;
            }

            int score = 0;
            byte[] header = readFilePrefix(file, 8);
            score += checkExtensionMasquerade(file, header);
            score += scorePatterns(file).total();
            score += scoreRootkit(file, header).total();

            String extension = getFileExtension(file).toLowerCase();
            if (RANSOMWARE_EXTENSIONS.contains(extension)) {
                score += SCORE_RANSOMWARE_EXTENSION;
            }
            if (containsRansomwarePatterns(file)) {
                score += SCORE_RANSOMWARE_TEXT_PATTERN;
            }
            score += scoreRansomwareDirectoryBehavior(file);

            String fileName = file.getName().toLowerCase();
            for (String sig : TROJAN_NAME_SIGNATURES) {
                if (fileName.contains(sig)) {
                    score += SCORE_TROJAN_NAME;
                    break;
                }
            }

            return score >= THRESHOLD_MALICIOUS;
        } catch (Exception e) {
            logger.error("Error during malware detection for file: {}", file.getName(), e);
            return false;
        }
    }

    // ── R-05 (carried forward): only flags HIGH-signal driver/boot locations,
    // not /proc, /sys, dotfiles, or empty files, AND requires corroborating
    // binary patterns in those locations before the binary signal fires. The
    // weak text-pattern signal below is capped low enough that it alone can
    // never reach MALICIOUS; it only nudges a file toward SUSPICIOUS or adds
    // to a genuinely corroborated score.
    @Override
    public boolean detectRootkit(File file) {
        try {
            byte[] header = readFilePrefix(file, 8);
            return scoreRootkit(file, header).total() >= THRESHOLD_MALICIOUS;
        } catch (IOException e) {
            logger.error("Error during rootkit detection for file: {}", file.getName(), e);
            return false;
        }
    }

    private ScoreResult scoreRootkit(File file, byte[] header8) {
        int score = 0;
        List<String> signals = new ArrayList<>();
        try {
            String absPath = file.getAbsolutePath().toLowerCase();

            boolean inRootkitLocation = absPath.contains("/lib/modules/") ||
                    absPath.contains("/boot/") ||
                    absPath.contains("\\system32\\drivers\\") ||
                    absPath.contains("\\syswow64\\drivers\\");

            if (inRootkitLocation) {
                byte[] header = readFilePrefix(file, 4096);
                if (detectRootkitBinaryPatterns(header)) {
                    logger.warn("Rootkit binary patterns in driver location: {}", file.getName());
                    score += SCORE_ROOTKIT_BINARY;
                    signals.add("ROOTKIT_BINARY_IN_DRIVER_LOCATION");
                }
            }

            int sampleSize = (int) Math.min(file.length(), MAX_PATTERN_SCAN_BYTES);
            byte[] content = readFilePrefix(file, sampleSize);
            String contentStr = new String(content, StandardCharsets.UTF_8);

            for (Pattern pattern : KERNEL_PATTERNS) {
                if (pattern.matcher(contentStr).find()) {
                    score += SCORE_ROOTKIT_TEXT;
                    signals.add("ROOTKIT_TEXT_PATTERN");
                    break;
                }
            }
        } catch (IOException e) {
            logger.error("Error during rootkit scoring for file: {}", file.getName(), e);
        }
        return new ScoreResult(score, signals);
    }

    private boolean detectRootkitBinaryPatterns(byte[] content) {
        byte[][] signatures = {
                new byte[] { 0x68, 0x69, 0x64, 0x65, 0x70, 0x72, 0x6F, 0x63 },
                new byte[] { 0x73, 0x79, 0x73, 0x63, 0x61, 0x6C, 0x6C },
                new byte[] { 0x6B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x33, 0x32 }
        };

        for (byte[] signature : signatures) {
            if (containsSequence(content, signature)) {
                return true;
            }
        }

        return false;
    }

    private boolean containsSequence(byte[] content, byte[] sequence) {
        if (content.length < sequence.length) {
            return false;
        }

        for (int i = 0; i <= content.length - sequence.length; i++) {
            boolean found = true;
            for (int j = 0; j < sequence.length; j++) {
                if (content[i + j] != sequence[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return true;
            }
        }
        return false;
    }

    @Override
    public List<ScanResult> scanDirectory(String directoryPath, boolean recursive) {
        List<ScanResult> results = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger totalFiles = new AtomicInteger(0);
        AtomicInteger processedFiles = new AtomicInteger(0);
        AtomicInteger infectedFiles = new AtomicInteger(0);
        String absolutePath;
        dirListingCache.get().clear();

        try {
            if (directoryPath.startsWith("/") || directoryPath.matches("^[A-Za-z]:\\\\.*")) {
                absolutePath = directoryPath;
            } else {
                String userDir = System.getProperty("user.dir");
                absolutePath = Paths.get(userDir, directoryPath).toString();
            }

            Path dir = Paths.get(absolutePath);

            if (!Files.exists(dir)) {
                throw new IllegalArgumentException("Directory does not exist: " + absolutePath);
            }
            if (!Files.isDirectory(dir)) {
                throw new IllegalArgumentException("Path is not a directory: " + absolutePath);
            }
            if (!Files.isReadable(dir)) {
                throw new IllegalArgumentException("Directory is not readable: " + absolutePath);
            }

            logger.info("Starting directory scan: {}", absolutePath);
            logger.info("Recursive mode: {}", recursive);

            logger.info("Found {} files to scan", totalFiles.get());

            try (Stream<Path> paths = recursive ? Files.walk(dir) : Files.list(dir)) {
                paths.filter(Files::isRegularFile)
                        .filter(p -> !isFileExcluded(p))
                        .forEach(path -> {
                            try {
                                if (isFileExcluded(path)) {
                                    logSkippedFile(path, results, "File excluded by filter");
                                    return;
                                }

                                if (Files.size(path) > 100 * 1024 * 1024) {
                                    logSkippedFile(path, results, "File too large (>100MB)");
                                    return;
                                }

                                ScanResult result = scanFile(path.toFile());
                                result.setScanType("DIRECTORY");
                                results.add(result);

                                if (result.isInfected()) {
                                    infectedFiles.incrementAndGet();
                                }

                                int processed = processedFiles.incrementAndGet();
                                if (processed % 50 == 0 || processed == totalFiles.get()) {
                                    logger.info("Scanned {} files, {} infected so far", processed, infectedFiles.get());
                                }

                            } catch (AccessDeniedException e) {
                                logger.debug("Access denied to file: {}", path);
                                logErrorFile(path, results, SAFE_ERROR_MESSAGES.get("ACCESS_DENIED"));
                            } catch (IOException e) {
                                logger.error("IO error scanning file: {}", path, e);
                                logErrorFile(path, results, SAFE_ERROR_MESSAGES.get("IO_ERROR"));
                            } catch (Exception e) {
                                logger.error("Unexpected error scanning file: {}", path, e);
                                logErrorFile(path, results, SAFE_ERROR_MESSAGES.get("SCAN_ERROR"));
                            }
                        });
            }

            logScanSummary(absolutePath, totalFiles.get(), infectedFiles.get(), results.size());
            saveResultsInBatches(results);
            return results;

        } catch (AccessDeniedException e) {
            logger.debug("Access denied to directory: {}", directoryPath, e);
            ScanResult errorResult = createErrorResult(directoryPath, SAFE_ERROR_MESSAGES.get("ACCESS_DENIED"));
            results.add(errorResult);
            saveScanResult(errorResult);
            return results;
        } catch (IOException e) {
            logger.error("IO error scanning directory: {}", directoryPath, e);
            ScanResult errorResult = createErrorResult(directoryPath, SAFE_ERROR_MESSAGES.get("IO_ERROR"));
            results.add(errorResult);
            saveScanResult(errorResult);
            return results;
        } catch (Exception e) {
            logger.error("Unexpected error scanning directory: {}", directoryPath, e);
            ScanResult errorResult = createErrorResult(directoryPath, SAFE_ERROR_MESSAGES.get("SCAN_ERROR"));
            results.add(errorResult);
            saveScanResult(errorResult);
            return results;
        } finally {
            dirListingCache.remove();
        }
    }

    private boolean isFileExcluded(Path path) {
        try {
            String fileName = path.getFileName().toString().toLowerCase();

            if (Files.isHidden(path) || fileName.startsWith(".")) {
                return true;
            }

            if (fileName.equals("thumbs.db") ||
                    fileName.equals("desktop.ini") ||
                    fileName.equals(".ds_store")) {
                return true;
            }

            String pathStr = path.toString().toLowerCase();
            return pathStr.contains("\\windows\\") ||
                    pathStr.contains("\\program files\\") ||
                    pathStr.contains("\\program files (x86)\\") ||
                    pathStr.contains("/proc/") ||
                    pathStr.contains("/sys/");

        } catch (IOException e) {
            logger.error("Error checking if file is excluded: {}", path, e);
            return false;
        }
    }

    private void logSkippedFile(Path path, List<ScanResult> results, String reason) {
        logger.debug("Skipping file: {} - {}", path, reason);
        ScanResult skipResult = new ScanResult();
        skipResult.setFilePath(path.toString());
        skipResult.setInfected(false);
        skipResult.setThreatType("SKIPPED");
        skipResult.setThreatDetails(reason);
        skipResult.setScanType("DIRECTORY");
        skipResult.setActionTaken("NONE");
        results.add(skipResult);
    }

    private void logErrorFile(Path path, List<ScanResult> results, String safeMessage) {
        logger.error("Error scanning file: {}", path);
        ScanResult errorResult = new ScanResult();
        errorResult.setFilePath(path.getFileName().toString());
        errorResult.setInfected(false);
        errorResult.setThreatType("ERROR");
        errorResult.setThreatDetails(safeMessage);
        errorResult.setScanType("DIRECTORY");
        errorResult.setActionTaken("NONE");
        results.add(errorResult);
    }

    private void logScanSummary(String directory, int totalFiles, int infectedFiles, int resultsSize) {
        logger.info("Directory scan completed: {}", directory);
        logger.info("Total files scanned: {}", totalFiles);
        logger.info("Infected files found: {}", infectedFiles);
        logger.info("Total results (including skipped/errors): {}", resultsSize);
    }

    private ScanResult createErrorResult(String path, String safeMessage) {
        ScanResult result = new ScanResult();
        result.setFilePath(path);
        result.setInfected(false);
        result.setThreatType("ERROR");
        result.setThreatDetails(safeMessage);
        result.setScanType("DIRECTORY");
        result.setActionTaken("NONE");
        return result;
    }

    private void saveResultsInBatches(List<ScanResult> results) {
        final int BATCH_SIZE = 100;
        for (int i = 0; i < results.size(); i += BATCH_SIZE) {
            int end = Math.min(i + BATCH_SIZE, results.size());
            List<ScanResult> batch = results.subList(i, end);
            batch.forEach(this::assignOwnerIfMissing);
            scanResultRepository.saveAll(batch);
            logger.debug("Saved batch of {} results to database", batch.size());
        }
    }
}
