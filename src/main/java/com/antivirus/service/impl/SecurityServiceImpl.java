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
import java.util.concurrent.ConcurrentHashMap;
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

    // ── R-04: Thread-safe signature set using ConcurrentHashMap.newKeySet() ──
    // Allows concurrent .contains() reads from scan threads and .add() writes
    // from updateVirusDefinitions() without ConcurrentModificationException.
    private static final Set<String> KNOWN_MALWARE_SIGNATURES = ConcurrentHashMap.newKeySet();

    // ── R-06: Signatures updated to SHA-256 (64 hex chars) ──
    // MD5 is cryptographically broken; SHA-256 is the minimum standard
    // used by all modern threat-intel feeds (VirusTotal, MalwareBazaar).
    static {
        KNOWN_MALWARE_SIGNATURES.addAll(List.of(
                // Replace with real SHA-256 hashes from a threat intel feed
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "5d41402abc4b2a76b9719d911017c592a3d494c4b7a2c8e1f0b3d5a7c9e1f3d5",
                "7d793037a0760186574b0282f2f435e7c3d6d8a0b2c4e6f8d0a2b4c6e8f0a2b4"));
    }

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

    private static final int MAX_SYSTEM_SCAN_RESULTS = 2_000;
    private static final long MAX_SYSTEM_SCAN_DURATION_MS = 5 * 60 * 1000L;
    private static final long MAX_PATTERN_SCAN_BYTES = 10L * 1024 * 1024L;
    private static final int MAX_PATTERN_WINDOW_CHARS = 16 * 1024;
    private static final int MAX_ZIP_ENTRIES = 1_000;
    private static final long MAX_ZIP_UNCOMPRESSED_BYTES = 500L * 1024 * 1024L;

    // Malicious code patterns (includes high-signal ransomware patterns for
    // defense-in-depth)
    private static final List<Pattern> MALICIOUS_PATTERNS = Arrays.asList(
            // JavaScript threats
            Pattern.compile("(?i)\\beval\\s*\\("),
            Pattern.compile("(?i)\\bdocument\\.write\\s*\\("),
            Pattern.compile("(?i)<script\\b"),
            Pattern.compile("(?i)\\bbase64_decode\\b"),

            // Shell execution
            Pattern.compile("(?i)\\bshell_exec\\s*\\("),
            Pattern.compile("(?i)\\bruntime\\.exec\\s*\\("),
            Pattern.compile("(?i)\\bsystem\\s*\\("),
            Pattern.compile("(?i)\\bpassthru\\s*\\("),

            // Process manipulation
            Pattern.compile("(?i)\\bprocess\\.spawn\\b"),
            Pattern.compile("(?i)\\bcreateprocess\\w*\\b"),

            // PowerShell threats
            Pattern.compile("(?i)\\bpowershell\\b.{0,120}(?:-enc|-encodedcommand|-w\\s+hidden)"),
            Pattern.compile("(?i)\\bpowershell\\b.{0,120}downloadstring"),
            Pattern.compile("(?i)\\bpowershell\\b.{0,120}\\bbypass\\b"),
            Pattern.compile("(?i)\\bpowershell\\b.{0,120}\\bhidden\\b"),

            // Network threats
            Pattern.compile("(?i)\\bnew\\s+socket\\s*\\("),
            Pattern.compile("(?i)\\bconnect\\s*\\(.*\\d{1,3}(?:\\.\\d{1,3}){3}"),
            Pattern.compile("(?i)\\bwget\\s+https?://"),
            Pattern.compile("(?i)\\bcurl\\b.{0,80}\\s-O\\b"),

            // Registry manipulation
            Pattern.compile("(?i)\\breg\\b.{0,80}\\badd\\b"),
            Pattern.compile("(?i)\\bregistry\\.setvalue\\b"),

            // File system threats
            Pattern.compile("(?i)\\.encrypt\\s*\\("),
            Pattern.compile("(?i)\\bchmod\\b.{0,40}\\b777\\b"),
            Pattern.compile("(?i)\\bicacls\\b.{0,80}\\bgrant\\b.{0,80}\\beveryone\\b"),

            // Data exfiltration
            Pattern.compile("(?i)\\.upload\\s*\\("),
            Pattern.compile("(?i)\\bpost\\b.{0,80}\\bpassword\\b"),
            Pattern.compile("(?i)\\bkeylog(?:ger)?\\b"),

            // Persistence mechanisms
            Pattern.compile("(?i)\\\\startup\\\\"),
            Pattern.compile("(?i)\\\\system32\\\\drivers\\\\"),
            Pattern.compile("(?i)\\\\tasks\\\\"),

            // Obfuscation
            Pattern.compile("(?i)\\bunescape\\b"),
            Pattern.compile("(?i)\\bdecode(?:uri)?\\b"),
            Pattern.compile("(?i)\\bfromcharcode\\b"),

            // ── Ransomware patterns (defense-in-depth) ──
            Pattern.compile("(?i)\\byour files have been encrypted\\b"),
            Pattern.compile("(?i)\\bbtc wallet\\b"),
            Pattern.compile("(?i)\\.(?:onion|tor)\\b"),
            Pattern.compile("(?i)\\bdecrypt.{0,30}ransom|ransom.{0,30}decrypt\\b"));

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

            // Check against known malware signatures (thread-safe — R-04)
            if (KNOWN_MALWARE_SIGNATURES.contains(fileHash)) {
                result.setInfected(true);
                result.setThreatType("VIRUS");
                result.setThreatDetails("Known malware signature detected");
                result.setActionTaken("REPORTED");
                saveScanResult(result);
                logService.logScanResult(result);
                return result;
            }

            // Check for ransomware FIRST (bounded scan + extension/behavioral checks)
            if (detectRansomware(file)) {
                result.setInfected(true);
                result.setThreatType("RANSOMWARE");
                result.setThreatDetails("Potential ransomware detected");
                result.setActionTaken("REPORTED");
                saveScanResult(result);
                logService.logScanResult(result);
                return result;
            }

            // General malicious-pattern scan (bounded to MAX_PATTERN_SCAN_BYTES)
            if (containsSuspiciousPatterns(file)) {
                result.setInfected(true);
                result.setThreatType("MALWARE");
                result.setThreatDetails("Suspicious code patterns detected");
                result.setActionTaken("REPORTED");
                saveScanResult(result);
                logService.logScanResult(result);
                return result;
            }

            // If no threats found
            result.setThreatType("CLEAN");
            result.setThreatDetails("No threats detected");
            result.setActionTaken("NONE");

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

    @SuppressWarnings("unused")
    private List<String> scanFileContent(File file) throws IOException {
        List<String> threats = new ArrayList<>();

        if (isZipFile(file)) {
            if (containsMaliciousZipContent(file)) {
                threats.add("MALICIOUS_ARCHIVE");
            }
            return threats;
        }

        try {
            byte[] content = readFilePrefix(file, (int) Math.min(file.length(), MAX_PATTERN_SCAN_BYTES));

            if (containsSuspiciousPatterns(file)) {
                threats.add("MALICIOUS_CODE");
                return threats;
            }

            String contentStr = new String(content, StandardCharsets.UTF_8);
            String[] lines = contentStr.split("\n");

            for (String line : lines) {
                if (line.contains("Your files have been encrypted") ||
                        line.contains("bitcoin") ||
                        line.contains("ransom")) {
                    threats.add("RANSOMWARE");
                    return threats;
                }

                if (line.contains("keylog") ||
                        line.contains("GetAsyncKeyState") ||
                        line.contains("keyboard_event")) {
                    threats.add("KEYLOGGER");
                    return threats;
                }
            }
        } catch (Exception e) {
            logger.error("Error scanning file content: {}", e.getMessage());
        }

        return threats;
    }

    private boolean isZipFile(File file) {
        return file.getName().toLowerCase().endsWith(".zip") ||
                file.getName().toLowerCase().endsWith(".jar") ||
                file.getName().toLowerCase().endsWith(".war");
    }

    private boolean containsMaliciousZipContent(File file) {
        int entryCount = 0;
        long totalUncompressed = 0L;

        try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(new FileInputStream(file)))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                entryCount++;
                if (entryCount > MAX_ZIP_ENTRIES) {
                    logger.warn("ZIP bomb suspected: entry count exceeds {}", MAX_ZIP_ENTRIES);
                    return true;
                }

                long entrySize = entry.getSize();
                if (entrySize > 0) {
                    totalUncompressed += entrySize;
                    if (totalUncompressed > MAX_ZIP_UNCOMPRESSED_BYTES) {
                        logger.warn("ZIP bomb suspected: uncompressed size exceeds {} bytes",
                                MAX_ZIP_UNCOMPRESSED_BYTES);
                        return true;
                    }
                }

                if (SUSPICIOUS_EXTENSIONS.contains(getFileExtension(new File(entry.getName())))) {
                    return true;
                }

                zis.closeEntry();
            }
        } catch (IOException e) {
            logger.error("Error scanning ZIP file {}: {}", file.getAbsolutePath(), e.getMessage(), e);
            return false;
        }
        return false;
    }

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

    private boolean containsSuspiciousPatterns(File file) {
        boolean textMatch = scanWithPatterns(file, MALICIOUS_PATTERNS);
        if (textMatch) {
            return true;
        }
        try {
            return containsSuspiciousBytes(readFilePrefix(file, 8));
        } catch (IOException e) {
            logger.error("Error reading file header for binary check: {}", e.getMessage(), e);
            return false;
        }
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

    // ── R-08: Removed placeholder hash that could never match any real
    // SHA-256 digest. Replaced with NOT_IMPLEMENTED response directing
    // operators to integrate a real threat-intel feed. ──
    @Override
    public void updateVirusDefinitions() {
        logger.info("Virus definition update requested — external feed not configured");
        throw new ResponseStatusException(HttpStatus.NOT_IMPLEMENTED,
                "Signature update feed not configured. Integrate VirusTotal or MalwareBazaar.");
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

    @Override
    public boolean detectRansomware(File file) {
        try {
            String extension = getFileExtension(file).toLowerCase();
            if (RANSOMWARE_EXTENSIONS.contains(extension)) {
                return true;
            }

            if (containsRansomwarePatterns(file)) {
                return true;
            }

            if (containsEncryptedContent(file)) {
                return true;
            }

            return hasRansomwareBehavior(file);

        } catch (Exception e) {
            logger.error("Ransomware detection failed for file: {}", file.getName(), e);
            return false;
        }
    }

    private boolean containsEncryptedContent(File file) {
        try {
            byte[] header = new byte[8];
            try (FileInputStream fis = new FileInputStream(file)) {
                if (fis.read(header) != 8) {
                    return false;
                }
            }

            return (header[0] == 0x00 && header[1] == 0x00 && header[2] == 0x00) ||
                    (header[0] == (byte) 0x89 && header[1] == 0x50) ||
                    (new String(header).startsWith("Salted__"));
        } catch (Exception e) {
            return false;
        }
    }

    private boolean hasRansomwareBehavior(File file) {
        File parentDir = file.getParentFile();
        if (parentDir == null || !parentDir.exists()) {
            return false;
        }

        File[] files = parentDir.listFiles();
        if (files == null) {
            return false;
        }

        int encryptedCount = 0;
        boolean hasRansomNote = false;

        for (File f : files) {
            String name = f.getName().toLowerCase();
            if (name.contains("readme") && name.contains("txt") ||
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

    @Override
    public boolean detectTrojan(File file) {
        try {
            String fileName = file.getName().toLowerCase();
            for (String sig : TROJAN_NAME_SIGNATURES) {
                if (fileName.contains(sig))
                    return true;
            }
            return containsSuspiciousPatterns(file);
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
            if (KNOWN_MALWARE_SIGNATURES.contains(fileHash)) {
                return true;
            }

            String extension = getFileExtension(file).toLowerCase();
            if (SUSPICIOUS_EXTENSIONS.contains(extension)) {
                return containsSuspiciousPatterns(file);
            }

            if (detectTrojan(file)) {
                return true;
            }

            if (detectRansomware(file)) {
                return true;
            }

            if (detectRootkit(file)) {
                return true;
            }

            return false;
        } catch (Exception e) {
            logger.error("Error during malware detection for file: " + file.getName(), e);
            return false;
        }
    }

    // ── R-05: Narrowed rootkit detection to eliminate false positives ──
    // Previous version flagged /proc, /sys (every Linux process), dotfiles
    // (.bashrc, .gitignore, .ssh/), and zero-byte files as rootkits.
    // Now only flags HIGH-signal driver/boot locations AND requires
    // corroborating binary patterns in those locations.
    @Override
    public boolean detectRootkit(File file) {
        try {
            String absPath = file.getAbsolutePath().toLowerCase();

            // 1. Only flag HIGH-signal driver/boot locations — not /proc or /sys
            boolean inRootkitLocation = absPath.contains("/lib/modules/") ||
                    absPath.contains("/boot/") ||
                    absPath.contains("\\system32\\drivers\\") ||
                    absPath.contains("\\syswow64\\drivers\\");

            if (inRootkitLocation) {
                // Only report if binary rootkit patterns are found in that location
                byte[] header = readFilePrefix(file, 4096);
                if (detectRootkitBinaryPatterns(header)) {
                    logger.warn("Rootkit binary patterns in driver location: {}", file.getName());
                    return true;
                }
            }

            // 2. Check kernel manipulation text patterns (bounded read)
            int sampleSize = (int) Math.min(file.length(), MAX_PATTERN_SCAN_BYTES);
            byte[] content = readFilePrefix(file, sampleSize);
            String contentStr = new String(content, StandardCharsets.UTF_8);

            Pattern[] kernelPatterns = {
                    Pattern.compile("(?i).*kernel.*hook.*"),
                    Pattern.compile("(?i).*syscall.*table.*"),
                    Pattern.compile("(?i).*interrupt.*descriptor.*table.*"),
                    Pattern.compile("(?i).*idt.*hook.*"),
                    Pattern.compile("(?i).*process.*hiding.*"),
                    Pattern.compile("(?i).*driver.*load.*")
            };

            for (Pattern pattern : kernelPatterns) {
                if (pattern.matcher(contentStr).find()) {
                    logger.warn("Potential rootkit detected: Kernel manipulation pattern found in " + file.getName());
                    return true;
                }
            }

            // 3. REMOVED: Files.isHidden() check — dotfiles are not rootkits
            // 4. REMOVED: zero-byte file check — empty files are entirely normal

            return false;

        } catch (IOException e) {
            logger.error("Error during rootkit detection for file: " + file.getName(), e);
            return false;
        }
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

            try (Stream<Path> paths = recursive ? Files.walk(dir) : Files.list(dir)) {
                totalFiles.set((int) paths
                        .filter(Files::isRegularFile)
                        .filter(p -> !isFileExcluded(p))
                        .count());
            }

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
                                if (processed % 10 == 0 || processed == totalFiles.get()) {
                                    logProgress(processed, totalFiles.get(), infectedFiles.get());
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
                    pathStr.contains("\\appdata\\") ||
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

    private void logProgress(int processed, int total, int infected) {
        double percentage = (processed * 100.0) / total;
        logger.info("Progress: {}% ({}/{} files scanned, {} infected)",
                String.format("%.2f", percentage), processed, total, infected);
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
