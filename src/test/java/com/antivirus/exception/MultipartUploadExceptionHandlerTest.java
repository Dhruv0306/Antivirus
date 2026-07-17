package com.antivirus.exception;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.apache.tomcat.util.http.fileupload.impl.FileCountLimitExceededException;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class MultipartUploadExceptionHandlerTest {

    @SuppressWarnings("deprecation")
@Test
    void handlesFileSizeExceededWithSpecificMessage() {
        MultipartUploadExceptionHandler handler = new MultipartUploadExceptionHandler("100MB", "1000MB", "500");
        MaxUploadSizeExceededException exception =
                new MaxUploadSizeExceededException(100L * 1024L * 1024L);

        ResponseEntity<Map<String, Object>> response = handler.handleMultipartUploadException(exception);

        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Upload too large", response.getBody().get("error"));
        assertEquals("file-size", response.getBody().get("limitType"));
        assertEquals("The upload exceeded the configured per-file size limit.",
                response.getBody().get("message"));
    }

    @SuppressWarnings("deprecation")
@Test
    void handlesRequestSizeExceededWithSpecificMessage() {
        MultipartUploadExceptionHandler handler = new MultipartUploadExceptionHandler("100MB", "1000MB", "500");
        MaxUploadSizeExceededException exception =
                new MaxUploadSizeExceededException(1000L * 1024L * 1024L);

        ResponseEntity<Map<String, Object>> response = handler.handleMultipartUploadException(exception);

        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Upload too large", response.getBody().get("error"));
        assertEquals("request-size", response.getBody().get("limitType"));
        assertEquals("The upload exceeded the configured total request size limit.",
                response.getBody().get("message"));
    }

    @SuppressWarnings("deprecation")
@Test
    void handlesFileCountExceededWithSpecificMessage() {
        MultipartUploadExceptionHandler handler = new MultipartUploadExceptionHandler("100MB", "1000MB", "500");
        FileCountLimitExceededException exception =
                new FileCountLimitExceededException("attachment", 50L);

        ResponseEntity<Map<String, Object>> response = handler.handleMultipartUploadException(exception);

        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Upload too large", response.getBody().get("error"));
        assertEquals("file-count", response.getBody().get("limitType"));
        assertEquals("The upload exceeded Tomcat's multipart part-count limit.",
                response.getBody().get("message"));
    }
}
