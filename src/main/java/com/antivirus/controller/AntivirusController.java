package com.antivirus.controller;

import com.antivirus.dto.PagedResponse;
import com.antivirus.model.ScanResult;
import com.antivirus.service.SecurityService;
import com.antivirus.service.SystemMonitorService;
import com.antivirus.service.LogService;
import com.antivirus.util.PathSecurityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@RestController
@RequestMapping("/api/antivirus")
public class AntivirusController {
    private static final Logger logger = LoggerFactory.getLogger(AntivirusController.class);
    private static final Set<String> ALLOWED_CONTENT_TYPES = Set.of(
        "application/octet-stream",
        "application/java-archive",
        "application/pdf",
        "application/zip",
        "application/x-zip-compressed",
        "application/x-msdownload",
        "application/x-msdos-program",
        "application/x-dosexec",
        "application/x-executable",
        "application/vnd.microsoft.portable-executable",
        "image/jpeg",
        "image/png",
        "text/plain"
    );

    @Value("${app.scan.max-files-per-directory-upload:500}")
    private int maxFilesPerDirectoryUpload;

    @Autowired
    private SecurityService securityService;

    @Autowired
    private SystemMonitorService systemMonitorService;

    @SuppressWarnings("unused")
    @Autowired
    private LogService logService;

    @SuppressWarnings("null")
    @PostMapping("/scan/file")
    public ResponseEntity<?> scanFile(@RequestParam("file") MultipartFile file) {
        // Validate that filename exists before processing (L-03 fix: handle null/blank filenames explicitly)
        String originalFilename = sanitizeDisplayName(file.getOriginalFilename());
        if (originalFilename == null || originalFilename.isBlank()) {
            logger.error("No valid filename for uploaded file");
            ScanResult errorResult = new ScanResult();
            errorResult.setFilePath("unknown-file");
            errorResult.setFileName("unknown-file");
            errorResult.setInfected(false);
            errorResult.setThreatType("ERROR");
            errorResult.setThreatDetails("No filename for uploaded file (null or blank)");
            return ResponseEntity.badRequest().body(errorResult);
        }

        String contentType = file.getContentType();
        if (contentType == null || !ALLOWED_CONTENT_TYPES.contains(contentType.toLowerCase(Locale.ROOT))) {
            logger.warn("Rejected upload with unsupported content type: {}", contentType);
            ScanResult errorResult = new ScanResult();
            errorResult.setFilePath(originalFilename);
            errorResult.setFileName(originalFilename);
            errorResult.setInfected(false);
            errorResult.setThreatType("ERROR");
            errorResult.setThreatDetails("Unsupported file type");
            return ResponseEntity.badRequest().body(errorResult);
        }

        File tempFile = null;
        try {
            // Create temporary file
            tempFile = File.createTempFile("scan_", "_" + UUID.randomUUID());
            file.transferTo(tempFile);
            logger.info("File uploaded successfully: {}", tempFile.getAbsolutePath());

            // Perform scan
            ScanResult result = securityService.scanFile(tempFile);
            result.setFileName(originalFilename);
            logger.info("File scan completed: {}", result);
            return ResponseEntity.ok(result);

        } catch (IOException e) {
            logger.error("Error processing file upload: {}", e.getMessage());
            ScanResult errorResult = new ScanResult();
            errorResult.setFilePath(originalFilename);
            errorResult.setFileName(originalFilename);
            errorResult.setInfected(false);
            errorResult.setThreatType("ERROR");
            errorResult.setThreatDetails("Error processing file upload");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResult);
        } finally {
            // Clean up the temporary file
            if (tempFile != null && tempFile.exists()) {
                try {
                    if (!tempFile.delete()) {
                        logger.warn("Could not delete temporary file: {}", tempFile.getAbsolutePath());
                    } else {
                        logger.info("Temporary file deleted: {}", tempFile.getAbsolutePath());
                    }
                } catch (Exception e) {
                    logger.warn("Error deleting temporary file: {}", tempFile.getAbsolutePath(), e);
                }
            }
        }
    }

    @PostMapping("/scan/system")
    public ResponseEntity<List<ScanResult>> performSystemScan() {
        return ResponseEntity.ok(securityService.performSystemScan());
    }

    @PostMapping("/scan/system/stop")
    public ResponseEntity<Void> stopSystemScan() {
        securityService.stopSystemScan();
        return ResponseEntity.ok().build();
    }

    @GetMapping("/scan/system/status")
    public ResponseEntity<Map<String, Object>> getSystemScanStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("isRunning", securityService.isSystemScanRunning());
        return ResponseEntity.ok(status);
    }

    @GetMapping("/network/check")
    public ResponseEntity<Boolean> checkNetworkSafety() {
        return ResponseEntity.ok(securityService.checkNetworkSafety());
    }

    @GetMapping("/browsing/status")
    public ResponseEntity<Boolean> getSecureBrowsingStatus() {
        return ResponseEntity.ok(securityService.isSecureBrowsingEnabled());
    }

    @PostMapping("/browsing/enable")
    public ResponseEntity<Void> enableSecureBrowsing() {
        securityService.enableSecureBrowsing();
        return ResponseEntity.ok().build();
    }

    @PostMapping("/browsing/disable")
    public ResponseEntity<Void> disableSecureBrowsing() {
        securityService.disableSecureBrowsing();
        return ResponseEntity.ok().build();
    }

    @GetMapping("/history")
    public ResponseEntity<PagedResponse<ScanResult>> getScanHistory(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return ResponseEntity.ok(securityService.getScanHistory(page, size));
    }

    @GetMapping("/infected")
    public ResponseEntity<PagedResponse<ScanResult>> getInfectedFiles(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return ResponseEntity.ok(securityService.getInfectedFiles(page, size));
    }

    @PostMapping("/update")
    public ResponseEntity<Void> updateVirusDefinitions() {
        securityService.updateVirusDefinitions();
        return ResponseEntity.ok().build();
    }

    @PostMapping("/quarantine")
    public ResponseEntity<Void> quarantineFile(@RequestParam("scanResultId") Long scanResultId) {
        securityService.quarantineScanResult(scanResultId);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Void> deleteInfectedFile(@RequestParam("scanResultId") Long scanResultId) {
        securityService.deleteScanResult(scanResultId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/system/start-monitoring")
    public ResponseEntity<Map<String, Object>> startSystemMonitoring() {
        systemMonitorService.startMonitoring();
        return ResponseEntity.ok(systemMonitorService.getSystemStatus());
    }

    @PostMapping("/system/stop-monitoring")
    public ResponseEntity<Map<String, Object>> stopSystemMonitoring() {
        systemMonitorService.stopMonitoring();
        return ResponseEntity.ok(systemMonitorService.getSystemStatus());
    }

    @GetMapping("/system/status")
    public ResponseEntity<Map<String, Object>> getSystemStatus() {
        return ResponseEntity.ok(systemMonitorService.getSystemStatus());
    }

    /**
     * Endpoint for scanning a directory
     * @param directoryName Name of the directory being scanned
     * @param recursive Whether to scan subdirectories
     * @param files List of files to scan from the directory
     * @return Scan results for all files
     */
    @SuppressWarnings("null")
    @PostMapping("/scan/directory")
    public ResponseEntity<?> scanDirectory(
            @RequestParam("directoryName") String directoryName,
            @RequestParam(value = "recursive", defaultValue = "true") boolean recursive,
            @RequestParam("files") List<MultipartFile> files) {

        if (files == null || files.isEmpty()) {
            logger.error("No files provided for scanning");
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "No files provided for scanning");
            return ResponseEntity.badRequest().body(errorResponse);
        }

        if (files.size() > maxFilesPerDirectoryUpload) {
            logger.warn("Directory upload rejected: {} files exceeds limit of {}", files.size(), maxFilesPerDirectoryUpload);
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Too many files. Maximum allowed: " + maxFilesPerDirectoryUpload);
            return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE).body(errorResponse);
        }

        try {
            logger.info("Starting directory scan for directory: {} (Total files: {})", directoryName, files.size());
            List<ScanResult> results = new ArrayList<>();
            int processedFiles = 0;
            int cleanFiles = 0;
            int infectedFiles = 0;
            int errorFiles = 0;
            
            // Create a temporary directory to store uploaded files
            Path tempDir = Files.createTempDirectory("scan_");
            
            try {
                // Process each file while maintaining directory structure
                for (MultipartFile file : files) {
                    try {
                        // Get the relative path from the original filename
                        String relativePath = sanitizeDisplayName(file.getOriginalFilename());
                        if (relativePath == null) {
                            continue;
                        }
                        
                        Path targetPath = PathSecurityUtil.resolveSafely(tempDir, relativePath);

                        if (targetPath.getParent() != null) {
                            Files.createDirectories(targetPath.getParent());
                        }
                        
                        // Save the file
                        file.transferTo(targetPath.toFile());
                        
                        // Scan the file
                        ScanResult result = securityService.scanFile(targetPath.toFile());
                        result.setFileName(relativePath);
                        results.add(result);
                        
                        // Update statistics
                        processedFiles++;
                        if (result.isInfected()) {
                            infectedFiles++;
                            logger.warn("Infected file found: {} (Type: {})", relativePath, result.getThreatType());
                        } else if ("ERROR".equals(result.getThreatType())) {
                            errorFiles++;
                        } else {
                            cleanFiles++;
                        }

                        // Log progress every 100 files
                        if (processedFiles % 100 == 0) {
                            logger.info("Directory scan progress - Directory: {}, Processed: {}/{}, Clean: {}, Infected: {}, Errors: {}", 
                                directoryName, processedFiles, files.size(), cleanFiles, infectedFiles, errorFiles);
                        }
                        
                    } catch (SecurityException e) {
                        logger.warn("Rejected unsafe path in directory upload: {}", file.getOriginalFilename());
                        ScanResult errorResult = new ScanResult();
                        String displayName = sanitizeDisplayName(file.getOriginalFilename());
                        errorResult.setFilePath(displayName);
                        errorResult.setFileName(displayName);
                        errorResult.setInfected(false);
                        errorResult.setThreatType("ERROR");
                        errorResult.setThreatDetails("Rejected unsafe file path");
                        results.add(errorResult);
                        errorFiles++;
                    } catch (Exception e) {
                        logger.error("Error processing file {}: {}", file.getOriginalFilename(), e.getMessage());
                        ScanResult errorResult = new ScanResult();
                        String displayName = sanitizeDisplayName(file.getOriginalFilename());
                        errorResult.setFilePath(displayName);
                        errorResult.setFileName(displayName);
                        errorResult.setInfected(false);
                        errorResult.setThreatType("ERROR");
                        errorResult.setThreatDetails("Error processing file");
                        results.add(errorResult);
                        errorFiles++;
                    }
                }
                
                // Create response with summary and details
                Map<String, Object> response = new HashMap<>();
                response.put("totalFiles", results.size());
                response.put("cleanFiles", cleanFiles);
                response.put("infectedFiles", infectedFiles);
                response.put("errorFiles", errorFiles);
                response.put("results", results);
                
                // Log final summary
                logger.info("Directory scan completed - Directory: {}, Total Files: {}, Clean: {}, Infected: {}, Errors: {}", 
                    directoryName, processedFiles, cleanFiles, infectedFiles, errorFiles);
                
                return ResponseEntity.ok(response);
                
            } finally {
                // Clean up temporary directory
                deleteDirectory(tempDir.toFile());
            }
            
        } catch (Exception e) {
            String reference = UUID.randomUUID().toString();
            logger.error("Error during directory scan [ref={}]", reference, e);
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Error scanning directory");
            errorResponse.put("reference", reference);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Helper method to recursively delete a directory
     */
    private void deleteDirectory(File directory) {
        if (directory.exists()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        deleteDirectory(file);
                    } else {
                        if (!file.delete()) {
                            logger.warn("Failed to delete file: {}", file.getAbsolutePath());
                        }
                    }
                }
            }
            if (!directory.delete()) {
                logger.warn("Failed to delete directory: {}", directory.getAbsolutePath());
            }
        }
    }

    private String sanitizeDisplayName(String originalFilename) {
        if (originalFilename == null || originalFilename.isBlank()) {
            return "unknown-file";
        }
        return originalFilename.replace("\\", "/");
    }
}
