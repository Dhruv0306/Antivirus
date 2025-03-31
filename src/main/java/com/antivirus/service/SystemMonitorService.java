package com.antivirus.service;

import org.springframework.stereotype.Service;
import java.io.File;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.OperatingSystemMXBean;
import java.nio.file.FileStore;
import java.nio.file.FileSystems;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.PostConstruct;

@Service
public class SystemMonitorService {
    private final OperatingSystemMXBean osBean;
    private final MemoryMXBean memoryBean;
    private boolean realtimeProtectionEnabled = true;
    private Map<String, Object> systemStatus = new HashMap<>();

    public SystemMonitorService() {
        this.osBean = ManagementFactory.getOperatingSystemMXBean();
        this.memoryBean = ManagementFactory.getMemoryMXBean();
    }

    @PostConstruct
    public void init() {
        updateSystemStatus();
    }

    public Map<String, Object> getSystemStatus() {
        updateSystemStatus();
        return systemStatus;
    }

    private void updateSystemStatus() {
        systemStatus.clear();
        
        // Check core protection features
        boolean isProtected = realtimeProtectionEnabled && 
                            !hasCriticalSystemIssues() && 
                            hasAdequateResources();
        
        systemStatus.put("systemProtected", isProtected);
        systemStatus.put("realtimeProtection", realtimeProtectionEnabled);
        systemStatus.put("cpuUsage", getCpuUsage());
        systemStatus.put("memoryUsage", getMemoryUsage());
        systemStatus.put("diskUsage", getDiskUsage());
        systemStatus.put("lastUpdate", new Date());
    }

    private double getCpuUsage() {
        try {
            if (osBean instanceof com.sun.management.OperatingSystemMXBean) {
                return ((com.sun.management.OperatingSystemMXBean) osBean).getSystemCpuLoad() * 100;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0.0;
    }

    private Map<String, Long> getMemoryUsage() {
        Map<String, Long> memoryInfo = new HashMap<>();
        Runtime runtime = Runtime.getRuntime();
        memoryInfo.put("total", runtime.totalMemory());
        memoryInfo.put("free", runtime.freeMemory());
        memoryInfo.put("used", runtime.totalMemory() - runtime.freeMemory());
        return memoryInfo;
    }

    private List<Map<String, Object>> getDiskUsage() {
        List<Map<String, Object>> diskUsage = new ArrayList<>();
        
        try {
            for (FileStore store : FileSystems.getDefault().getFileStores()) {
                Map<String, Object> disk = new HashMap<>();
                disk.put("name", store.name());
                disk.put("total", store.getTotalSpace());
                disk.put("used", store.getTotalSpace() - store.getUnallocatedSpace());
                diskUsage.add(disk);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return diskUsage;
    }

    private boolean hasCriticalSystemIssues() {
        // Only check for critical security issues
        return hasSuspiciousProcesses() || 
               hasUnauthorizedSystemChanges();
    }

    private boolean hasAdequateResources() {
        // Check if system has enough resources
        Runtime runtime = Runtime.getRuntime();
        long freeMemoryPercent = (runtime.freeMemory() * 100) / runtime.totalMemory();
        
        // Get disk space
        List<Map<String, Object>> disks = getDiskUsage();
        boolean hasSufficientDiskSpace = disks.stream()
            .anyMatch(disk -> {
                long total = (long) disk.get("total");
                long used = (long) disk.get("used");
                return total > 0 && ((used * 100) / total) < 90; // Less than 90% used
            });
        
        return freeMemoryPercent > 10 && hasSufficientDiskSpace;
    }

    private boolean hasUnauthorizedSystemChanges() {
        // Only check critical system directories
        File[] systemDirs = {
            new File("C:\\Windows\\System32"),
            new File("C:\\Windows\\SysWOW64")
        };

        for (File dir : systemDirs) {
            if (dir.exists() && hasRecentChanges(dir)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasRecentChanges(File directory) {
        if (!directory.exists() || !directory.isDirectory()) {
            return false;
        }

        File[] files = directory.listFiles();
        if (files == null) return false;

        long currentTime = System.currentTimeMillis();
        long threshold = 24 * 60 * 60 * 1000; // 24 hours

        for (File file : files) {
            if (currentTime - file.lastModified() < threshold) {
                return true;
            }
        }
        return false;
    }

    private boolean hasSuspiciousProcesses() {
        List<String> suspicious = checkSuspiciousProcesses();
        return !suspicious.isEmpty();
    }

    private List<String> checkSuspiciousProcesses() {
        List<String> suspiciousProcesses = new ArrayList<>();
        
        try {
            ProcessHandle.allProcesses()
                .forEach(process -> {
                    ProcessHandle.Info info = process.info();
                    String command = info.command().orElse("");
                    
                    // Check against known malicious process names
                    if (isSuspiciousProcess(command)) {
                        suspiciousProcesses.add(command);
                    }
                });
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return suspiciousProcesses;
    }

    private boolean isSuspiciousProcess(String processName) {
        // List of known malicious process names (example)
        String[] suspiciousNames = {
            "cryptominer",
            "botnet",
            "keylogger",
            "trojan",
            "malware",
            "backdoor"
        };

        processName = processName.toLowerCase();
        for (String suspicious : suspiciousNames) {
            if (processName.contains(suspicious)) {
                return true;
            }
        }
        return false;
    }

    public boolean isRealtimeProtectionEnabled() {
        return realtimeProtectionEnabled;
    }

    public void enableRealtimeProtection() {
        this.realtimeProtectionEnabled = true;
        updateSystemStatus();
    }

    public void disableRealtimeProtection() {
        this.realtimeProtectionEnabled = false;
        updateSystemStatus();
    }

    public void startMonitoring() {
        // Implementation needed
    }

    public void stopMonitoring() {
        // Implementation needed
    }
} 