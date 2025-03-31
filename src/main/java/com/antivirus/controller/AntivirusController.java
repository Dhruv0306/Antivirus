package com.antivirus.controller;

import com.antivirus.model.ScanResult;
import com.antivirus.service.SecurityService;
import com.antivirus.service.SystemMonitorService;
import com.antivirus.service.LogService;
import org.springframework.beans.factory.annotation.Autowired;
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

@RestController
@RequestMapping("/api/antivirus")
@CrossOrigin(origins = {"http://localhost:5000", "http://localhost:3000"})
public class AntivirusController {
    private static final Logger logger = LoggerFactory.getLogger(AntivirusController.class);

    @Autowired
    private SecurityService securityService;

    @Autowired
    private SystemMonitorService systemMonitorService;

    @Autowired
    private LogService logService;

    @PostMapping("/scan/file")
    public ResponseEntity<?> scanFile(@RequestParam("file") MultipartFile file) {
        if (file == null || file.isEmpty()) {
            logger.error("No file provided or file is empty");
            ScanResult errorResult = new ScanResult();
            errorResult.setFilePath("No file");
            errorResult.setInfected(false);
            errorResult.setThreatType("ERROR");
            errorResult.setThreatDetails("No file provided or file is empty");
            return ResponseEntity.badRequest().body(errorResult);
        }

        File tempFile = null;
        try {
            // Create temporary file
            tempFile = File.createTempFile("scan_", "_" + file.getOriginalFilename());
            file.transferTo(tempFile);
            logger.info("File uploaded successfully: {}", tempFile.getAbsolutePath());

            // Perform scan
            ScanResult result = securityService.scanFile(tempFile);
            logger.info("File scan completed: {}", result);
            return ResponseEntity.ok(result);

        } catch (IOException e) {
            logger.error("Error processing file upload: {}", e.getMessage());
            ScanResult errorResult = new ScanResult();
            errorResult.setFilePath(file.getOriginalFilename());
            errorResult.setInfected(false);
            errorResult.setThreatType("ERROR");
            errorResult.setThreatDetails("Error processing file: " + e.getMessage());
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
    public ResponseEntity<List<ScanResult>> getScanHistory() {
        return ResponseEntity.ok(securityService.getScanHistory());
    }

    @GetMapping("/infected")
    public ResponseEntity<List<ScanResult>> getInfectedFiles() {
        return ResponseEntity.ok(securityService.getInfectedFiles());
    }

    @PostMapping("/update")
    public ResponseEntity<Void> updateVirusDefinitions() {
        securityService.updateVirusDefinitions();
        return ResponseEntity.ok().build();
    }

    @PostMapping("/quarantine")
    public ResponseEntity<Void> quarantineFile(@RequestParam("path") String filePath) {
        securityService.quarantineFile(new File(filePath));
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Void> deleteInfectedFile(@RequestParam("path") String filePath) {
        securityService.deleteInfectedFile(new File(filePath));
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

    @GetMapping("/scan/file")
    public ResponseEntity<ScanResult> scanFile(@RequestParam("path") String filePath) {
        // Implementation of scanFile method
        return null; // Placeholder return, actual implementation needed
    }

    /**
     * Endpoint for scanning a directory
     * @param directoryName Name of the directory being scanned
     * @param recursive Whether to scan subdirectories
     * @param files List of files to scan from the directory
     * @return Scan results for all files
     */
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
                        String relativePath = file.getOriginalFilename();
                        if (relativePath == null) {
                            continue;
                        }
                        
                        // Create the full path in temp directory
                        Path targetPath = tempDir.resolve(relativePath);
                        
                        // Create parent directories if they don't exist
                        Files.createDirectories(targetPath.getParent());
                        
                        // Save the file
                        file.transferTo(targetPath.toFile());
                        
                        // Scan the file
                        ScanResult result = securityService.scanFile(targetPath.toFile());
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
                        
                    } catch (Exception e) {
                        logger.error("Error processing file {}: {}", file.getOriginalFilename(), e.getMessage());
                        ScanResult errorResult = new ScanResult();
                        errorResult.setFilePath(file.getOriginalFilename());
                        errorResult.setInfected(false);
                        errorResult.setThreatType("ERROR");
                        errorResult.setThreatDetails("Error processing file: " + e.getMessage());
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
            logger.error("Error during directory scan: {}", e.getMessage());
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Error scanning directory: " + e.getMessage());
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
} 