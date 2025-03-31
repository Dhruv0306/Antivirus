package com.antivirus.service.impl;

import com.antivirus.model.ScanResult;
import com.antivirus.service.SecurityService;
import com.antivirus.service.SystemMonitorService;
import com.antivirus.repository.ScanResultRepository;
import com.antivirus.service.LogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.nio.file.attribute.BasicFileAttributes;
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

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private LogService logService;

    private final AtomicBoolean systemScanRunning = new AtomicBoolean(false);
    private final AtomicBoolean stopSystemScan = new AtomicBoolean(false);

    private boolean isElevated = false;

    // Known malicious file signatures (MD5 hashes)
    private static final Set<String> KNOWN_MALWARE_SIGNATURES = new HashSet<>(Arrays.asList(
        "e4968ef99266df7c9a1f0637d2389dab", // Example malware signature
        "a7d6f45f05f9bc45f2b9c6fb93d7d9ab",
        "c8d03b43a0c9b5890b6f6994da2c4639"
    ));

    // Suspicious file extensions
    private static final Set<String> SUSPICIOUS_EXTENSIONS = new HashSet<>(Arrays.asList(
        ".exe", ".dll", ".bat", ".cmd", ".scr", ".js", ".vbs", ".hta",
        ".sys", ".bin", ".com", ".msi", ".pif", ".gadget", ".msp",
        ".cpl", ".hta", ".msc", ".jar", ".ps1", ".psm1", ".vbe",
        ".ws", ".wsf", ".wsh", ".scr", ".sct", ".shb", ".tmp"
    ));

    // Malicious code patterns
    private static final List<Pattern> MALICIOUS_PATTERNS = Arrays.asList(
        // JavaScript threats
        Pattern.compile("(?i).*eval\\(.*\\).*"), // JavaScript eval
        Pattern.compile("(?i).*document\\.write\\(.*\\).*"), // Dynamic content injection
        Pattern.compile("(?i).*\\<script.*\\>.*"), // Potential XSS
        Pattern.compile("(?i).*\\bbase64_decode\\b.*"), // Base64 encoded content
        
        // Shell execution
        Pattern.compile("(?i).*shell_exec\\(.*\\).*"), // PHP shell execution
        Pattern.compile("(?i).*exec\\(.*\\).*"), // Generic execution
        Pattern.compile("(?i).*system\\(.*\\).*"), // System command execution
        Pattern.compile("(?i).*passthru\\(.*\\).*"), // Command passthrough
        
        // Process manipulation
        Pattern.compile("(?i).*process\\.spawn.*"), // Node.js process spawning
        Pattern.compile("(?i).*runtime\\.exec.*"), // Java Runtime execution
        Pattern.compile("(?i).*createprocess.*"), // Windows process creation
        
        // PowerShell threats
        Pattern.compile("(?i).*powershell.*-enc.*"), // Encoded PowerShell
        Pattern.compile("(?i).*powershell.*downloadstring.*"), // Remote script download
        Pattern.compile("(?i).*powershell.*bypass.*"), // Security bypass
        Pattern.compile("(?i).*powershell.*hidden.*"), // Hidden window
        
        // Network threats
        Pattern.compile("(?i).*new\\s+socket\\s*\\(.*"), // Socket creation
        Pattern.compile("(?i).*connect\\s*\\(.*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*\\).*"), // IP connection
        Pattern.compile("(?i).*wget\\s+http.*"), // File download
        Pattern.compile("(?i).*curl\\s+.*-O.*"), // File download
        
        // Registry manipulation
        Pattern.compile("(?i).*reg.*add.*"), // Registry modification
        Pattern.compile("(?i).*registry\\.setvalue.*"), // Registry API
        
        // File system threats
        Pattern.compile("(?i).*\\.encrypt\\(.*"), // File encryption
        Pattern.compile("(?i).*chmod.*777.*"), // Suspicious permissions
        Pattern.compile("(?i).*icacls.*grant.*everyone.*"), // Windows permissions
        
        // Data exfiltration
        Pattern.compile("(?i).*\\.upload\\(.*"), // File upload
        Pattern.compile("(?i).*post.*password.*"), // Password theft
        Pattern.compile("(?i).*keylog.*"), // Keylogging
        
        // Persistence mechanisms
        Pattern.compile("(?i).*\\\\startup\\\\.*"), // Startup folder
        Pattern.compile("(?i).*\\\\system32\\\\drivers\\\\.*"), // Driver installation
        Pattern.compile("(?i).*\\\\tasks\\\\.*"), // Scheduled tasks
        
        // Obfuscation
        Pattern.compile("(?i).*\\bunescape\\b.*"), // String obfuscation
        Pattern.compile("(?i).*\\bdecode\\b.*"), // Encoding
        Pattern.compile("(?i).*\\bfromcharcode\\b.*") // Character code obfuscation
    );

    @Override
    public boolean authenticateUser(String username, String password) {
        // For demo purposes, we'll use a simple authentication
        // In production, this should check against a user database
        return "admin".equals(username) && 
               passwordEncoder.matches(password, passwordEncoder.encode("admin123"));
    }

    @Override
    public boolean authorizeUser(String username, String operation) {
        // Implementation would check user permissions
        return true; // Simplified for demo
    }

    @Override
    public ScanResult scanFile(File file) {
        ScanResult result = new ScanResult();
        result.setFilePath(file.getAbsolutePath());
        result.setInfected(false);
        result.setScanType("FILE");
        result.setActionTaken("NONE");
        
        try {
            if (!file.exists()) {
                result.setThreatType("ERROR");
                result.setThreatDetails("File does not exist");
                scanResultRepository.save(result);
                return result;
            }

            if (!file.canRead()) {
                result.setThreatType("ERROR");
                result.setThreatDetails("Cannot read file");
                scanResultRepository.save(result);
                return result;
            }

            // Check file size
            if (file.length() > 100 * 1024 * 1024) { // 100MB limit
                result.setThreatType("WARNING");
                result.setThreatDetails("File too large to scan");
                scanResultRepository.save(result);
                return result;
            }

            // Calculate file hash
            String fileHash = calculateFileHash(file);
            
            // Check against known malware signatures
            if (KNOWN_MALWARE_SIGNATURES.contains(fileHash)) {
                result.setInfected(true);
                result.setThreatType("VIRUS");
                result.setThreatDetails("Known malware signature detected");
                result.setActionTaken("QUARANTINED");
                quarantineFile(file);
                scanResultRepository.save(result);
                logService.logScanResult(result);
                return result;
            }

            // Scan file content
            byte[] content = Files.readAllBytes(file.toPath());
            
            // Check for suspicious patterns
            if (containsSuspiciousPatterns(content)) {
                result.setInfected(true);
                result.setThreatType("MALWARE");
                result.setThreatDetails("Suspicious code patterns detected");
                result.setActionTaken("QUARANTINED");
                quarantineFile(file);
                scanResultRepository.save(result);
                logService.logScanResult(result);
                return result;
            }

            // Check for ransomware patterns
            if (detectRansomware(file)) {
                result.setInfected(true);
                result.setThreatType("RANSOMWARE");
                result.setThreatDetails("Potential ransomware detected");
                result.setActionTaken("QUARANTINED");
                quarantineFile(file);
                scanResultRepository.save(result);
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
            result.setThreatDetails("Error scanning file: " + e.getMessage());
            result.setActionTaken("NONE");
        }

        // Save the final result
        scanResultRepository.save(result);
        
        // Log the scan result
        logService.logScanResult(result);

        return result;
    }

    private String calculateFileHash(File file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        try (InputStream is = Files.newInputStream(file.toPath())) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) > 0) {
                md.update(buffer, 0, read);
            }
        }
        byte[] md5sum = md.digest();
        return bytesToHex(md5sum);
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

    private List<String> scanFileContent(File file) throws IOException {
        List<String> threats = new ArrayList<>();
        
        // Check if it's a ZIP file
        if (isZipFile(file)) {
            if (containsMaliciousZipContent(file)) {
                threats.add("MALICIOUS_ARCHIVE");
            }
            return threats;
        }

        try {
            byte[] content = Files.readAllBytes(file.toPath());
            
            // Check for malicious patterns
            if (containsSuspiciousPatterns(content)) {
                threats.add("MALICIOUS_CODE");
                return threats;
            }
            
            // Convert to string for text-based checks
            String contentStr = new String(content);
            String[] lines = contentStr.split("\n");
            
            for (String line : lines) {
                // Check for potential ransomware markers
                if (line.contains("Your files have been encrypted") ||
                    line.contains("bitcoin") ||
                    line.contains("ransom")) {
                    threats.add("RANSOMWARE");
                    return threats;
                }
                
                // Check for keylogger indicators
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
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(file))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // Check for suspicious files in archive
                if (SUSPICIOUS_EXTENSIONS.contains(getFileExtension(new File(entry.getName())))) {
                    return true;
                }
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    private boolean containsSuspiciousBytes(byte[] content) {
        try {
            // Check for executable headers
            if (content.length >= 4) {
                // Check for MZ header (DOS/PE)
                if (content[0] == 0x4D && content[1] == 0x5A) {
                    return true;
                }
                // Check for ELF header
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

    private boolean containsSuspiciousPatterns(byte[] content) {
        try {
            // Convert bytes to string for pattern matching
            String contentStr = new String(content);
            String[] lines = contentStr.split("\n");
            
            for (String line : lines) {
                for (Pattern pattern : MALICIOUS_PATTERNS) {
                    if (pattern.matcher(line).matches()) {
                        return true;
                    }
                }
            }
            
            // If text scanning didn't find anything, check for binary patterns
            return containsSuspiciousBytes(content);
        } catch (Exception e) {
            logger.error("Error checking for suspicious patterns: {}", e.getMessage());
            return false;
        }
    }

    private boolean checkElevatedPrivileges() {
        try {
            String osName = System.getProperty("os.name").toLowerCase();
            if (osName.contains("windows")) {
                // Check if running with admin privileges on Windows
                String programFiles = System.getenv("ProgramFiles");
                File testFile = new File(programFiles);
                return testFile.canWrite();
            } else {
                // For Unix-like systems, check if running as root
                return System.getProperty("user.name").equals("root");
            }
        } catch (SecurityException e) {
            logger.warn("Unable to determine privilege level: {}", e.getMessage());
            return false;
        }
    }

    @Override
    @Transactional
    public List<ScanResult> performSystemScan() {
        if (systemScanRunning.get()) {
            logger.warn("System scan is already running");
            return new ArrayList<>();
        }

        systemScanRunning.set(true);
        stopSystemScan.set(false);
        List<ScanResult> results = new ArrayList<>();
        AtomicInteger scannedFiles = new AtomicInteger(0);
        AtomicInteger skippedFiles = new AtomicInteger(0);
        
        try {
            logger.info("Starting system scan...");
            File[] roots = File.listRoots();
            if (roots == null || roots.length == 0) {
                throw new RuntimeException("No root directories found");
            }
            
            logger.info("Found {} root directories to scan", roots.length);
            
            // List of directories to skip
            Set<String> skipDirectories = new HashSet<>(Arrays.asList(
                "$Recycle.Bin",
                "System Volume Information",
                "Windows",
                "Program Files",
                "Program Files (x86)",
                "ProgramData",
                "Recovery",
                "Config.Msi",
                "Documents and Settings"
            ));
            
            for (File root : roots) {
                if (stopSystemScan.get()) {
                    logger.info("System scan stopped by user");
                    break;
                }
                
                logger.info("Scanning root directory: {}", root.getAbsolutePath());
                
                try {
                    scanDirectory(root.toPath(), skipDirectories, results, scannedFiles, skippedFiles);
                } catch (Exception e) {
                    logger.error("Error scanning root directory {}: {}", root, e.getMessage());
                    ScanResult errorResult = new ScanResult();
                    errorResult.setFilePath(root.getAbsolutePath());
                    errorResult.setInfected(false);
                    errorResult.setThreatType("ERROR");
                    errorResult.setThreatDetails("Error accessing directory: " + e.getMessage());
                    errorResult.setScanType("SYSTEM");
                    errorResult.setActionTaken("NONE");
                    results.add(errorResult);
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
                             AtomicInteger skippedFiles) throws IOException {
        try {
            if (stopSystemScan.get()) {
                return;
            }

            // Skip if directory should be excluded
            if (skipDirectories.stream().anyMatch(dir -> 
                directory.toString().toLowerCase().contains(dir.toLowerCase()))) {
                logger.debug("Skipping restricted directory: {}", directory);
                skippedFiles.incrementAndGet();
                return;
            }

            // This operation can throw AccessDeniedException
            DirectoryStream<Path> stream = Files.newDirectoryStream(directory);
            try (stream) {
                for (Path path : stream) {
                    if (stopSystemScan.get()) {
                        return;
                    }

                    try {
                        // These operations can throw AccessDeniedException
                        boolean isDirectory = Files.isDirectory(path);
                        boolean isReadable = Files.isReadable(path);
                        boolean isRegularFile = Files.isRegularFile(path);

                        if (isDirectory) {
                            scanDirectory(path, skipDirectories, results, scannedFiles, skippedFiles);
                        } else if (isRegularFile && isReadable) {
                            logger.debug("Scanning file: {}", path);
                            ScanResult result = scanFile(path.toFile());
                            results.add(result);
                            scannedFiles.incrementAndGet();
                            
                            if (result.isInfected()) {
                                logger.warn("Infected file found: {} (Type: {})", 
                                    path, result.getThreatType());
                            }
                        }
                    } catch (AccessDeniedException e) {
                        logger.debug("Access denied to path: {}", path);
                        skippedFiles.incrementAndGet();
                    } catch (Exception e) {
                        logger.error("Error processing path {}: {}", path, e.getMessage());
                        ScanResult errorResult = new ScanResult();
                        errorResult.setFilePath(path.toString());
                        errorResult.setInfected(false);
                        errorResult.setThreatType("ERROR");
                        errorResult.setThreatDetails("Error scanning file: " + e.getMessage());
                        errorResult.setScanType("SYSTEM");
                        errorResult.setActionTaken("NONE");
                        results.add(errorResult);
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

    @Override
    public List<ScanResult> getScanHistory() {
        return logService.getLastFiveScanResults();
    }

    @Override
    public List<ScanResult> getInfectedFiles() {
        return scanResultRepository.findByInfectedTrue();
    }

    @Override
    public void updateVirusDefinitions() {
        // In a real implementation, this would download and update virus signatures
        // For demo purposes, we'll just add some new signatures
        KNOWN_MALWARE_SIGNATURES.add("new_malware_signature_hash");
    }

    @Override
    public void quarantineFile(File file) {
        try {
            // Create quarantine directory if it doesn't exist
            File quarantineDir = new File("quarantine");
            if (!quarantineDir.exists()) {
                quarantineDir.mkdir();
            }
            
            // Move file to quarantine
            File quarantinedFile = new File(quarantineDir, file.getName() + ".quarantine");
            Files.move(file.toPath(), quarantinedFile.toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean detectKeylogger() {
        // Check for known keylogger processes and patterns
        List<String> suspiciousProcesses = systemMonitorService.getSystemStatus()
            .get("suspiciousProcesses") instanceof List<?> ?
            (List<String>) systemMonitorService.getSystemStatus().get("suspiciousProcesses") :
            new ArrayList<>();

        // Check if any suspicious process contains keylogger-related names
        for (String process : suspiciousProcesses) {
            if (process.toLowerCase().contains("keylog") ||
                process.toLowerCase().contains("hook") ||
                process.toLowerCase().contains("keyboard")) {
                return true;
            }
        }

        // Additional checks could include:
        // 1. Checking for keyboard hook APIs being used
        // 2. Monitoring for suspicious keyboard event listeners
        // 3. Checking for known keylogger file signatures
        return false;
    }

    @Override
    public boolean detectRansomware(File file) {
        try {
            // Check file extension for common ransomware extensions
            String extension = getFileExtension(file).toLowerCase();
            Set<String> ransomwareExtensions = new HashSet<>(Arrays.asList(
                ".encrypted", ".crypto", ".locked", ".crypted", ".crypt",
                ".vault", ".petya", ".wannacry", ".wcry", ".wncry",
                ".locky", ".zepto", ".thor", ".aesir", ".zzzzz"
            ));

            if (ransomwareExtensions.contains(extension)) {
                return true;
            }

            // Check file content for ransomware patterns
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    // Check for common ransomware message patterns
                    if (line.toLowerCase().contains("your files have been encrypted") ||
                        line.toLowerCase().contains("bitcoin") ||
                        line.toLowerCase().contains("ransom") ||
                        line.toLowerCase().contains("decrypt") ||
                        line.toLowerCase().contains("payment") ||
                        line.toLowerCase().contains("btc wallet") ||
                        line.toLowerCase().contains("your important files") ||
                        line.toLowerCase().matches(".*\\.(onion|tor).*")) {
                        return true;
                    }
                }
            } catch (IOException e) {
                // If we can't read the file as text, check for encrypted content markers
                return containsEncryptedContent(file);
            }

            // Check for file system behavior indicative of ransomware
            return hasRansomwareBehavior(file);

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private boolean containsEncryptedContent(File file) {
        try {
            // Read first few bytes to check for encryption markers
            byte[] header = new byte[8];
            try (FileInputStream fis = new FileInputStream(file)) {
                if (fis.read(header) != 8) {
                    return false;
                }
            }

            // Check for common encryption headers
            return (header[0] == 0x00 && header[1] == 0x00 && header[2] == 0x00) || // Possible AES
                   (header[0] == (byte)0x89 && header[1] == 0x50) || // Possible encrypted PNG
                   (new String(header).startsWith("Salted__")); // OpenSSL encryption
        } catch (Exception e) {
            return false;
        }
    }

    private boolean hasRansomwareBehavior(File file) {
        File parentDir = file.getParentFile();
        if (parentDir == null || !parentDir.exists()) {
            return false;
        }

        // Check for ransomware indicators in the directory
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

        // If we find a ransom note and multiple files with suspicious extensions
        return hasRansomNote && encryptedCount > 5;
    }

    @Override
    public boolean detectTrojan(File file) {
        try {
            // Known trojan file signatures
            Set<String> trojanSignatures = new HashSet<>(Arrays.asList(
                "backdoor", "rootkit", "trojan", "RAT",
                "remote_access", "stealer", "inject",
                "payload", "downloader"
            ));

            // Check file name for suspicious patterns
            String fileName = file.getName().toLowerCase();
            for (String signature : trojanSignatures) {
                if (fileName.contains(signature)) {
                    return true;
                }
            }

            // Check file content for trojan patterns
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    // Check for common trojan code patterns
                    if (line.toLowerCase().contains("socket.connect") ||
                        line.toLowerCase().contains("reverse_tcp") ||
                        line.toLowerCase().contains("remote_shell") ||
                        line.toLowerCase().contains("process.create") ||
                        line.toLowerCase().contains("registry.write") ||
                        line.toLowerCase().contains("wscript.shell") ||
                        line.matches("(?i).*\\b(bind|reverse)\\s*shell\\b.*")) {
                        return true;
                    }
                }
            } catch (IOException e) {
                // If we can't read as text, check binary patterns
                return containsTrojanBinaryPatterns(file);
            }

            // Check for suspicious network behavior
            return hasSuspiciousNetworkBehavior(file);

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private boolean containsTrojanBinaryPatterns(File file) {
        try (InputStream is = new FileInputStream(file)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            
            // Common binary patterns found in trojans
            byte[][] patterns = {
                // Common shellcode patterns
                {(byte)0xFC, (byte)0xE8, (byte)0x82, (byte)0x00},
                // Common reverse shell patterns
                {(byte)0x68, (byte)0x7F, (byte)0x00, (byte)0x00, (byte)0x01},
                // Common payload patterns
                {(byte)0x4D, (byte)0x5A, (byte)0x90, (byte)0x00}
            };

            while ((bytesRead = is.read(buffer)) != -1) {
                for (byte[] pattern : patterns) {
                    if (containsPattern(buffer, bytesRead, pattern)) {
                        return true;
                    }
                }
            }
        } catch (IOException e) {
            return false;
        }
        return false;
    }

    private boolean containsPattern(byte[] buffer, int bufferLength, byte[] pattern) {
        for (int i = 0; i <= bufferLength - pattern.length; i++) {
            boolean found = true;
            for (int j = 0; j < pattern.length; j++) {
                if (buffer[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return true;
        }
        return false;
    }

    private boolean hasSuspiciousNetworkBehavior(File file) {
        // Check if the file has network-related strings
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            int networkPatternCount = 0;
            
            while ((line = reader.readLine()) != null) {
                if (line.toLowerCase().contains("http://") ||
                    line.toLowerCase().contains("https://") ||
                    line.toLowerCase().contains("ftp://") ||
                    line.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*") || // IP addresses
                    line.contains("socket") ||
                    line.contains("connect") ||
                    line.contains("download")) {
                    networkPatternCount++;
                }
                
                // If we find multiple network-related patterns, consider it suspicious
                if (networkPatternCount > 3) {
                    return true;
                }
            }
        } catch (IOException e) {
            return false;
        }
        return false;
    }

    @Override
    public void deleteInfectedFile(File file) {
        try {
            Files.deleteIfExists(file.toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean detectMalware(File file) {
        try {
            // Check for known malware signatures
            String fileHash = calculateFileHash(file);
            if (KNOWN_MALWARE_SIGNATURES.contains(fileHash)) {
                return true;
            }

            // Check file extension
            String extension = getFileExtension(file).toLowerCase();
            if (SUSPICIOUS_EXTENSIONS.contains(extension)) {
                // Check for malicious patterns in suspicious files
                byte[] content = Files.readAllBytes(file.toPath());
                return containsSuspiciousPatterns(content);
            }

            // Check for trojan behavior
            if (detectTrojan(file)) {
                return true;
            }

            // Check for ransomware behavior
            if (detectRansomware(file)) {
                return true;
            }

            // Check for rootkit behavior
            if (detectRootkit(file)) {
                return true;
            }

            return false;
        } catch (Exception e) {
            logger.error("Error during malware detection for file: " + file.getName(), e);
            return false;
        }
    }

    @Override
    public boolean detectRootkit(File file) {
        try {
            // Check for common rootkit file locations
            String[] suspiciousLocations = {
                "/proc/",
                "/sys/",
                "/boot/",
                "C:\\Windows\\System32\\Drivers\\",
                "C:\\Windows\\SysWOW64\\Drivers\\"
            };

            // Check if file is in a suspicious location
            for (String location : suspiciousLocations) {
                if (file.getAbsolutePath().toLowerCase().startsWith(location.toLowerCase())) {
                    logger.warn("Potential rootkit detected: File in suspicious location: " + file.getAbsolutePath());
                    return true;
                }
            }

            // Read file content for analysis
            byte[] content = Files.readAllBytes(file.toPath());
            String contentStr = new String(content);

            // Check for rootkit indicators in binary content
            if (detectRootkitBinaryPatterns(content)) {
                logger.warn("Potential rootkit detected: Suspicious binary patterns in " + file.getName());
                return true;
            }

            // Check for kernel manipulation patterns
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

            // Check file attributes for hidden properties
            BasicFileAttributes attrs = Files.readAttributes(file.toPath(), BasicFileAttributes.class);
            if (Files.isHidden(file.toPath())) {
                logger.warn("Potential rootkit detected: Hidden file attributes in " + file.getName());
                return true;
            }

            // Check file size anomalies
            if (attrs.size() == 0 && !file.getName().endsWith(".log")) {
                logger.warn("Potential rootkit detected: Zero-byte file in system location: " + file.getName());
                return true;
            }

            return false;

        } catch (IOException e) {
            logger.error("Error during rootkit detection for file: " + file.getName(), e);
            return false;
        }
    }

    /**
     * Analyzes binary content for common rootkit patterns
     * @param content The binary content to analyze
     * @return true if suspicious patterns are found
     */
    private boolean detectRootkitBinaryPatterns(byte[] content) {
        // Common rootkit binary signatures
        byte[][] signatures = {
            // Example: Hidden process manipulation
            new byte[] { 0x68, 0x69, 0x64, 0x65, 0x70, 0x72, 0x6F, 0x63 },
            // Example: System call table modification
            new byte[] { 0x73, 0x79, 0x73, 0x63, 0x61, 0x6C, 0x6C },
            // Example: Kernel manipulation
            new byte[] { 0x6B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x33, 0x32 }
        };

        // Check for each signature
        for (byte[] signature : signatures) {
            if (containsSequence(content, signature)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Helper method to check if a byte array contains a specific sequence
     */
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
    @Transactional
    public List<ScanResult> scanDirectory(String directoryPath, boolean recursive) {
        List<ScanResult> results = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger totalFiles = new AtomicInteger(0);
        AtomicInteger processedFiles = new AtomicInteger(0);
        AtomicInteger infectedFiles = new AtomicInteger(0);
        String absolutePath;

        try {
            // Convert relative path to absolute path
            if (directoryPath.startsWith("/") || directoryPath.matches("^[A-Za-z]:\\\\.*")) {
                // Path is already absolute
                absolutePath = directoryPath;
            } else {
                // Get the user's working directory
                String userDir = System.getProperty("user.dir");
                absolutePath = Paths.get(userDir, directoryPath).toString();
            }

            Path dir = Paths.get(absolutePath);
            
            // Validate directory
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

            // First pass - count total files
            try (Stream<Path> paths = recursive ? Files.walk(dir) : Files.list(dir)) {
                totalFiles.set((int) paths
                    .filter(Files::isRegularFile)
                    .filter(p -> !isFileExcluded(p))
                    .count());
            }

            logger.info("Found {} files to scan", totalFiles.get());

            // Second pass - scan files
            try (Stream<Path> paths = recursive ? Files.walk(dir) : Files.list(dir)) {
                paths.filter(Files::isRegularFile)
                    .filter(p -> !isFileExcluded(p))
                    .forEach(path -> {
                        try {
                            // Skip excluded files
                            if (isFileExcluded(path)) {
                                logSkippedFile(path, results, "File excluded by filter");
                                return;
                            }

                            // Check file size
                            if (Files.size(path) > 100 * 1024 * 1024) { // 100MB limit
                                logSkippedFile(path, results, "File too large (>100MB)");
                                return;
                            }

                            // Scan the file
                            ScanResult result = scanFile(path.toFile());
                            result.setScanType("DIRECTORY");
                            results.add(result);

                            // Update counters
                            if (result.isInfected()) {
                                infectedFiles.incrementAndGet();
                            }

                            // Log progress
                            int processed = processedFiles.incrementAndGet();
                            if (processed % 10 == 0 || processed == totalFiles.get()) {
                                logProgress(processed, totalFiles.get(), infectedFiles.get());
                            }

                        } catch (Exception e) {
                            logger.error("Error scanning file: {}", path, e);
                            logErrorFile(path, results, e.getMessage());
                        }
                    });
            }

            // Log final summary
            logScanSummary(absolutePath, totalFiles.get(), infectedFiles.get(), results.size());

            // Save results in batches
            saveResultsInBatches(results);

            return results;

        } catch (Exception e) {
            logger.error("Error scanning directory: {}", directoryPath, e);
            ScanResult errorResult = createErrorResult(directoryPath, e.getMessage());
            results.add(errorResult);
            scanResultRepository.save(errorResult);
            return results;
        }
    }

    private boolean isFileExcluded(Path path) {
        try {
            String fileName = path.getFileName().toString().toLowerCase();
            
            // Skip hidden files
            if (Files.isHidden(path) || fileName.startsWith(".")) {
                return true;
            }

            // Skip system files
            if (fileName.equals("thumbs.db") || 
                fileName.equals("desktop.ini") ||
                fileName.equals(".ds_store")) {
                return true;
            }

            // Skip certain directories
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

    private void logErrorFile(Path path, List<ScanResult> results, String error) {
        logger.error("Error scanning file: {} - {}", path, error);
        ScanResult errorResult = new ScanResult();
        errorResult.setFilePath(path.toString());
        errorResult.setInfected(false);
        errorResult.setThreatType("ERROR");
        errorResult.setThreatDetails(error);
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

    private ScanResult createErrorResult(String path, String message) {
        ScanResult result = new ScanResult();
        result.setFilePath(path);
        result.setInfected(false);
        result.setThreatType("ERROR");
        result.setThreatDetails(message);
        result.setScanType("DIRECTORY");
        result.setActionTaken("NONE");
        return result;
    }

    private void saveResultsInBatches(List<ScanResult> results) {
        final int BATCH_SIZE = 100;
        for (int i = 0; i < results.size(); i += BATCH_SIZE) {
            int end = Math.min(i + BATCH_SIZE, results.size());
            List<ScanResult> batch = results.subList(i, end);
            scanResultRepository.saveAll(batch);
            logger.debug("Saved batch of {} results to database", batch.size());
        }
    }
} 