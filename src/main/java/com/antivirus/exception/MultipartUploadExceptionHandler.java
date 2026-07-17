package com.antivirus.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.unit.DataSize;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartException;
import org.apache.tomcat.util.http.fileupload.impl.FileCountLimitExceededException;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

@RestControllerAdvice
public class MultipartUploadExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(MultipartUploadExceptionHandler.class);

    private final String maxFileSize;
    private final String maxRequestSize;
    private final String maxPartCount;

    public MultipartUploadExceptionHandler(
            @Value("${spring.servlet.multipart.max-file-size:100MB}") String maxFileSize,
            @Value("${spring.servlet.multipart.max-request-size:1000MB}") String maxRequestSize,
            @Value("${server.tomcat.max-part-count:50}") String maxPartCount) {
        this.maxFileSize = maxFileSize;
        this.maxRequestSize = maxRequestSize;
        this.maxPartCount = maxPartCount;
    }

    @SuppressWarnings("deprecation")
    @ExceptionHandler({MaxUploadSizeExceededException.class, MultipartException.class})
    public ResponseEntity<Map<String, Object>> handleMultipartUploadException(Exception ex) {
        Throwable rootCause = findRootCause(ex);
        String reference = UUID.randomUUID().toString();
        String limitType = resolveLimitType(ex, rootCause);
        String message = buildMessage(limitType);
        String exceptionClass = ex.getClass().getName();
        String rootCauseClass = rootCause != null ? rootCause.getClass().getName() : "none";
        String rootCauseMessage = rootCause != null ? rootCause.getMessage() : null;

        logger.warn(
                "Multipart upload rejected [ref={} limitType={} exceptionClass={} rootCauseClass={} rootCauseMessage={}]: {}",
                reference, limitType, exceptionClass, rootCauseClass, rootCauseMessage, ex.getMessage());

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "Upload too large");
        errorResponse.put("message", message);
        errorResponse.put("limitType", limitType);
        errorResponse.put("exceptionClass", exceptionClass);
        errorResponse.put("rootCauseClass", rootCauseClass);
        errorResponse.put("rootCauseMessage", rootCauseMessage);
        errorResponse.put("maxFileSize", maxFileSize);
        errorResponse.put("maxRequestSize", maxRequestSize);
        errorResponse.put("maxPartCount", maxPartCount);
        errorResponse.put("reference", reference);
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE).body(errorResponse);
    }

    private String resolveLimitType(Exception ex, Throwable rootCause) {
        if (rootCause instanceof FileCountLimitExceededException fileCountLimitExceededException) {
            return fileCountLimitExceededException.getLimit() >= 0 ? "file-count" : "file-count";
        }

        if (ex instanceof MaxUploadSizeExceededException maxUploadSizeExceededException) {
            long exceededSize = maxUploadSizeExceededException.getMaxUploadSize();
            if (exceededSize > 0) {
                long configuredFileSize = parseDataSize(maxFileSize);
                if (configuredFileSize > 0 && exceededSize == configuredFileSize) {
                    return "file-size";
                }

                long configuredRequestSize = parseDataSize(maxRequestSize);
                if (configuredRequestSize > 0 && exceededSize == configuredRequestSize) {
                    return "request-size";
                }
            }
        }

        String message = ex.getMessage();
        if (message != null && !message.isBlank()) {
            String normalizedMessage = message.toLowerCase(Locale.ROOT);
            if (normalizedMessage.contains("request")) {
                return "request-size";
            }
            if (normalizedMessage.contains("file")) {
                return "file-size";
            }
        }

        if (rootCause != null) {
            String rootMessage = rootCause.getMessage();
            if (rootMessage != null && !rootMessage.isBlank()) {
                String normalizedRootMessage = rootMessage.toLowerCase(Locale.ROOT);
                if (normalizedRootMessage.contains("request")) {
                    return "request-size";
                }
                if (normalizedRootMessage.contains("file")) {
                    return "file-size";
                }
            }
        }

        return "unknown";
    }

    private String buildMessage(String limitType) {
        return switch (limitType) {
            case "file-count" -> "The upload exceeded Tomcat's multipart part-count limit.";
            case "file-size" -> "The upload exceeded the configured per-file size limit.";
            case "request-size" -> "The upload exceeded the configured total request size limit.";
            default -> "The upload exceeded the configured multipart upload size limit.";
        };
    }

    private Throwable findRootCause(Throwable throwable) {
        Throwable current = throwable;
        Throwable root = throwable;
        while (current != null) {
            root = current;
            current = current.getCause();
        }
        return root;
    }

    private long parseDataSize(String sizeValue) {
        try {
            return DataSize.parse(sizeValue).toBytes();
        } catch (IllegalArgumentException ex) {
            logger.warn("Could not parse multipart size value '{}': {}", sizeValue, ex.getMessage());
            return -1L;
        }
    }
}
