package com.antivirus.service;

import com.antivirus.model.ScanResult;
import java.io.File;
import java.util.List;

public interface SecurityService {
    // Authentication and Authorization (X.800)
    boolean authenticateUser(String username, String password);
    boolean authorizeUser(String username, String operation);

    // File System Security (X.800)
    ScanResult scanFile(File file);
    List<ScanResult> scanDirectory(String directoryPath, boolean recursive);
    List<ScanResult> performSystemScan();
    void stopSystemScan();
    boolean isSystemScanRunning();
    
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
    List<ScanResult> getScanHistory();
    List<ScanResult> getInfectedFiles();
    
    // Security Management (X.800)
    void updateVirusDefinitions();
    void quarantineFile(File file);
    void deleteInfectedFile(File file);
}
