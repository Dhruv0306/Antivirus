package com.antivirus.service;

import com.antivirus.dto.PagedResponse;
import com.antivirus.model.ScanResult;
import java.io.File;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public interface SecurityService {
    // File System Security (X.800)
    ScanResult scanFile(File file);

    List<ScanResult> scanDirectory(String directoryPath, boolean recursive);

    // Runs on a background thread; returns immediately once the scan has
    // started. Poll isSystemScanRunning()/getSystemScanFilesScanned() (or
    // GET /scan/system/status) for progress, and fetch /history once the
    // scan reports isRunning=false to see the results.
    void performSystemScan();

    void stopSystemScan();

    boolean isSystemScanRunning();

    int getSystemScanFilesScanned();

    // Uploaded-directory scan, run as a background job. tempDir must
    // already contain the uploaded files (the controller writes them
    // there); this call returns a jobId immediately. Poll
    // getDirectoryScanJobStatus(jobId) for progress/results.
    String startDirectoryScanJob(Path tempDir, String directoryName, int totalFiles);

    Map<String, Object> getDirectoryScanJobStatus(String jobId);

    // Network Security (X.800)
    boolean checkNetworkSafety();

    boolean isSecureBrowsingEnabled();

    void enableSecureBrowsing();

    void disableSecureBrowsing();

    // Malware Detection (X.800)
    boolean detectMalware(File file);

    boolean detectTrojan(File file);

    boolean detectRansomware(File file);

    boolean detectKeylogger();

    boolean detectRootkit(File file);

    // Security Monitoring (X.800)
    PagedResponse<ScanResult> getScanHistory(int page, int size);

    PagedResponse<ScanResult> getInfectedFiles(int page, int size);

    // Security Management (X.800)
    void updateVirusDefinitions();

    void quarantineFile(File file);

    void deleteInfectedFile(File file);

    void quarantineScanResult(Long scanResultId);

    void deleteScanResult(Long scanResultId);
}
