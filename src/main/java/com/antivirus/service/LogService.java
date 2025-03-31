package com.antivirus.service;

import com.antivirus.model.ScanResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.stereotype.Service;
import java.io.*;
import java.util.*;
import java.nio.file.*;
import java.util.Base64;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class LogService {
    private static final Logger logger = LoggerFactory.getLogger(LogService.class);
    private static final String LOG_DIRECTORY = "logs";
    private static final String LOG_FILE = "scan_history.log";
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
            String encodedResult = Base64.getEncoder().encodeToString(jsonResult.getBytes());
            
            // Append to log file with timestamp
            String logEntry = System.currentTimeMillis() + ":" + encodedResult + "\n";
            
            // Ensure parent directories exist
            Files.createDirectories(logPath.getParent());
            
            // Write with all necessary options
            Files.write(
                logPath,
                logEntry.getBytes(),
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
            File logsDir = new File(LOG_DIRECTORY);
            Path logPath = logsDir.toPath().resolve(LOG_FILE);
            
            if (!Files.exists(logPath)) {
                logger.debug("Scan history log file does not exist yet at: {}", logPath.toAbsolutePath());
                return new ArrayList<>();
            }

            List<String> lines = Files.readAllLines(logPath);
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