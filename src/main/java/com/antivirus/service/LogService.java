package com.antivirus.service;

import com.antivirus.model.ScanResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.stereotype.Service;
import java.io.*;
import java.util.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class LogService {
    private static final Logger logger = LoggerFactory.getLogger(LogService.class);
    private static final String LOG_DIRECTORY = "logs";
    private static final String LOG_FILE = "scan_history.log";
    private static final long MAX_LOG_FILE_SIZE_BYTES = 10L * 1024 * 1024L;
    private static final int MAX_LOG_BACKUPS = 7;
    private final ObjectMapper objectMapper;

    public LogService() {
        this.objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    }

    public void logScanResult(ScanResult result) {
        if (result == null) {
            logger.warn("Attempted to log null scan result");
            return;
        }

        try {
            // Create logs directory if it doesn't exist
            File logsDir = new File(LOG_DIRECTORY);
            if (!logsDir.exists() && !logsDir.mkdirs()) {
                logger.error("Failed to create logs directory");
                return;
            }

            // Create full path for log file
            Path logPath = logsDir.toPath().resolve(LOG_FILE);
            
            // Convert ScanResult to JSON and encode
            String jsonResult = objectMapper.writeValueAsString(result);
            String encodedResult = Base64.getEncoder().encodeToString(jsonResult.getBytes(StandardCharsets.UTF_8));
            
            // Append to log file with timestamp
            String logEntry = System.currentTimeMillis() + ":" + encodedResult + "\n";
            
            // Ensure parent directories exist
            Files.createDirectories(logPath.getParent());
            rotateLogIfNeeded(logPath, logEntry.getBytes(StandardCharsets.UTF_8).length);

            // Write with all necessary options
            Files.write(
                logPath,
                logEntry.getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND,
                StandardOpenOption.WRITE
            );
            
            logger.debug("Successfully logged scan result for file: {}", result.getFilePath());
        } catch (IOException e) {
            logger.error("Error writing to scan history log: {}", e.getMessage(), e);
        }
    }

    public List<ScanResult> getLastFiveScanResults() {
        try {
            List<String> lines = readAllLogLines();
            if (lines.isEmpty()) {
                logger.debug("Scan history log file is empty");
                return new ArrayList<>();
            }

            return lines.stream()
                .filter(line -> line != null && !line.trim().isEmpty())
                .sorted(Comparator.comparing(line -> Long.parseLong(line.split(":")[0]), Comparator.reverseOrder()))
                .limit(5)
                .map(this::decodeScanResult)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        } catch (IOException e) {
            logger.error("Error reading scan history log: {}", e.getMessage(), e);
            return new ArrayList<>();
        }
    }

    private void rotateLogIfNeeded(Path logPath, long nextEntrySize) throws IOException {
        if (!Files.exists(logPath)) {
            return;
        }

        long currentSize = Files.size(logPath);
        if (currentSize + nextEntrySize <= MAX_LOG_FILE_SIZE_BYTES) {
            return;
        }

        Path oldestBackup = logPath.resolveSibling(LOG_FILE + "." + MAX_LOG_BACKUPS);
        Files.deleteIfExists(oldestBackup);

        for (int i = MAX_LOG_BACKUPS - 1; i >= 1; i--) {
            Path source = logPath.resolveSibling(LOG_FILE + "." + i);
            if (Files.exists(source)) {
                Path target = logPath.resolveSibling(LOG_FILE + "." + (i + 1));
                Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
            }
        }

        Files.move(logPath, logPath.resolveSibling(LOG_FILE + ".1"), StandardCopyOption.REPLACE_EXISTING);
    }

    private List<String> readAllLogLines() throws IOException {
        List<String> lines = new ArrayList<>();
        List<Path> logFiles = new ArrayList<>();
        Path currentLog = Paths.get(LOG_DIRECTORY).resolve(LOG_FILE);

        for (int i = 1; i <= MAX_LOG_BACKUPS; i++) {
            Path backup = currentLog.resolveSibling(LOG_FILE + "." + i);
            if (Files.exists(backup)) {
                logFiles.add(backup);
            }
        }

        if (Files.exists(currentLog)) {
            logFiles.add(currentLog);
        }

        for (Path logFile : logFiles) {
            lines.addAll(Files.readAllLines(logFile));
        }

        return lines;
    }

    private ScanResult decodeScanResult(String line) {
        if (line == null || line.trim().isEmpty()) {
            logger.warn("Attempted to decode null or empty log line");
            return null;
        }

        try {
            String[] parts = line.split(":", 2);
            if (parts.length != 2) {
                logger.warn("Invalid log entry format");
                return null;
            }

            String encodedResult = parts[1];
            byte[] decodedBytes = Base64.getDecoder().decode(encodedResult);
            String jsonResult = new String(decodedBytes);
            return objectMapper.readValue(jsonResult, ScanResult.class);
        } catch (Exception e) {
            logger.error("Error decoding scan result: {}", e.getMessage(), e);
            return null;
        }
    }
}
