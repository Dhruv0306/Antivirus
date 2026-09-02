package com.antivirus.pressure;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.List;
import java.util.ArrayList;
import java.util.LinkedHashMap;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pushes the running application past normal single-user load to find
 * where it actually breaks, and to confirm the defenses that are supposed
 * to kick in under load (the auth rate limiter) actually do.
 *
 * This is not a unit test and not a functional-correctness test: it fires
 * concurrent real HTTP traffic at a real Spring context and asserts on
 * aggregate behavior (error rate, latency, whether throttling engaged),
 * not on individual response bodies.
 *
 * Named *PressureIT.java, not *Test.java, so mvn test never picks this up.
 * Only "mvn verify -Ppressure" runs it (see the pressure profile in
 * pom.xml). Thresholds below are deliberately generous: the goal is to
 * catch the app falling over or a defense silently disappearing, not to
 * enforce a strict performance SLA in CI.
 *
 * Each test also records its results into PressureMetricsCollector; see
 * flushMetrics() below and docs/pressure-metrics.md for where those end up.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("pressuretest")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class EndpointPressureIT {

    @LocalServerPort
    private int port;

    private final ObjectMapper mapper = new ObjectMapper();

    private String baseUrl() {
        return "http://localhost:" + port;
    }

    /**
     * Fires a burst of concurrent unauthenticated GETs against the
     * lightweight CSRF bootstrap endpoint (no DB write, no auth check) to
     * find the app's ceiling for plain concurrent traffic. Every client
     * gets its own connection/cookie jar since this endpoint is
     * unauthenticated and stateless from the caller's point of view.
     */
    @Test
    @Order(1)
    void handlesConcurrentUnauthenticatedTrafficWithLowErrorRate() throws Exception {
        int concurrentClients = 100;
        int requestsPerClient = 5;

        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger errorCount = new AtomicInteger(0);
        AtomicLong maxLatencyMs = new AtomicLong(0);

        ExecutorService pool = Executors.newFixedThreadPool(concurrentClients);
        List<Callable<Void>> tasks = new ArrayList<>();

        for (int i = 0; i < concurrentClients; i++) {
            tasks.add(() -> {
                HttpClient client = HttpClient.newHttpClient();
                for (int r = 0; r < requestsPerClient; r++) {
                    long start = System.currentTimeMillis();
                    try {
                        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl() + "/api/auth/csrf"))
                                .GET().build();
                        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
                        long latency = System.currentTimeMillis() - start;
                        maxLatencyMs.updateAndGet(current -> Math.max(current, latency));
                        if (resp.statusCode() == 200) {
                            successCount.incrementAndGet();
                        } else {
                            errorCount.incrementAndGet();
                        }
                    } catch (Exception ex) {
                        errorCount.incrementAndGet();
                    }
                }
                return null;
            });
        }

        List<Future<Void>> futures = pool.invokeAll(tasks, 120, TimeUnit.SECONDS);
        pool.shutdown();

        int totalRequests = concurrentClients * requestsPerClient;
        double errorRate = errorCount.get() / (double) totalRequests;
        long incompleteTasks = futures.stream().filter(f -> !f.isDone()).count();

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("concurrentClients", concurrentClients);
        metrics.put("requestsPerClient", requestsPerClient);
        metrics.put("totalRequests", totalRequests);
        metrics.put("errorCount", errorCount.get());
        metrics.put("errorRatePct", round2(errorRate * 100));
        metrics.put("maxLatencyMs", maxLatencyMs.get());
        metrics.put("incompleteTasks", incompleteTasks);
        PressureMetricsCollector.record("concurrentTraffic", metrics);

        assertTrue(errorRate < 0.02,
                "Error rate under " + concurrentClients + " concurrent clients was "
                        + (errorRate * 100) + "% (" + errorCount.get() + "/" + totalRequests
                        + " failed), expected under 2%");
        assertTrue(maxLatencyMs.get() < 10_000,
                "Slowest single request took " + maxLatencyMs.get() + "ms under concurrent load, expected under 10s");
        assertTrue(incompleteTasks == 0,
                incompleteTasks + " of " + concurrentClients + " client tasks did not finish within 120s");
    }

    /**
     * Confirms the 10-requests-per-minute auth rate limiter (SecurityConfig)
     * actually engages under a real burst, rather than only in whatever
     * mocked unit test exercises it in isolation. Fires 30 rapid POSTs to
     * /api/auth/register from a single client (single IP, as the limiter
     * keys on) and expects some of them to come back 429.
     */
    @Test
    @Order(3)
    // Runs last on purpose: it deliberately exhausts the shared in-memory
    // auth rate limiter budget for this "IP", which would break login for
    // any test that runs after it in the same Spring context.
    void authRateLimiterEngagesUnderBurstTraffic() throws Exception {
        int burstSize = 30;
        HttpClient client = HttpClient.newBuilder()
                .cookieHandler(new CookieManager())
                .build();

        AtomicInteger rateLimitedCount = new AtomicInteger(0);

        for (int i = 0; i < burstSize; i++) {
            String[] csrf = PressureTestAuthSupport.fetchCsrfHeaderAndToken(client, baseUrl()).split("\\|", 2);

            String username = "pressure_burst_" + UUID.randomUUID().toString().substring(0, 8);
            String body = mapper.writeValueAsString(Map.of(
                    "username", username,
                    "email", username + "@example.com",
                    "password", "PressureBurstPass123!",
                    "confirmPassword", "PressureBurstPass123!"));

            HttpRequest registerReq = HttpRequest.newBuilder(URI.create(baseUrl() + "/api/auth/register"))
                    .header("Content-Type", "application/json")
                    .header(csrf[0], csrf[1])
                    .POST(BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> registerResp = client.send(registerReq, HttpResponse.BodyHandlers.ofString());
            if (registerResp.statusCode() == 429) {
                rateLimitedCount.incrementAndGet();
            }
        }

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("burstSize", burstSize);
        metrics.put("rateLimitedCount", rateLimitedCount.get());
        PressureMetricsCollector.record("rateLimiter", metrics);

        assertTrue(rateLimitedCount.get() > 0,
                "Sent " + burstSize + " rapid registrations from one client and got zero 429 responses. "
                        + "The auth rate limiter (SecurityConfig.authRateLimitFilter) does not appear to be engaging.");
    }

    /**
     * A single authenticated user firing many concurrent scan requests:
     * checks the scan path stays correct and stable under concurrency, not
     * just under the one-request-at-a-time load the unit and integration
     * suites exercise.
     */
    @Test
    @Order(2)
    void singleUserConcurrentScanUploadsStayCorrect() throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .cookieHandler(new CookieManager())
                .build();

        String username = "pressure_scanner_" + UUID.randomUUID().toString().substring(0, 8);
        String password = "PressureScannerPass123!";
        PressureTestAuthSupport.registerAndLogin(client, baseUrl(), username, password);

        // Fetch the CSRF token once, outside the concurrent loop. Fetching it
        // per-task racily overwrites the shared cookie jar across threads and
        // produces spurious CSRF failures that have nothing to do with the
        // scan endpoint itself.
        String[] csrf = PressureTestAuthSupport.fetchCsrfHeaderAndToken(client, baseUrl()).split("\\|", 2);

        int concurrentScans = 20;
        ExecutorService pool = Executors.newFixedThreadPool(concurrentScans);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger errorCount = new AtomicInteger(0);
        List<Callable<Void>> tasks = new ArrayList<>();

        for (int i = 0; i < concurrentScans; i++) {
            final int index = i;
            tasks.add(() -> {
                try {
                    String boundary = "----PressureITBoundary" + UUID.randomUUID();
                    String content = "Concurrent pressure test file #" + index + "\n";
                    String multipartBody = "--" + boundary + "\r\n"
                            + "Content-Disposition: form-data; name=\"file\"; filename=\"pressure-" + index
                            + ".txt\"\r\n"
                            + "Content-Type: text/plain\r\n\r\n"
                            + content + "\r\n"
                            + "--" + boundary + "--\r\n";

                    HttpRequest scanReq = HttpRequest.newBuilder(URI.create(baseUrl() + "/api/antivirus/scan/file"))
                            .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                            .header(csrf[0], csrf[1])
                            .POST(BodyPublishers.ofString(multipartBody))
                            .build();
                    HttpResponse<String> resp = client.send(scanReq, HttpResponse.BodyHandlers.ofString());
                    if (resp.statusCode() == 200) {
                        successCount.incrementAndGet();
                    } else {
                        errorCount.incrementAndGet();
                    }
                } catch (Exception ex) {
                    errorCount.incrementAndGet();
                }
                return null;
            });
        }

        pool.invokeAll(tasks, 120, TimeUnit.SECONDS);
        pool.shutdown();

        double errorRate = errorCount.get() / (double) concurrentScans;

        // Every successful scan should be visible in this user's history.
        HttpRequest historyReq = HttpRequest.newBuilder(
                URI.create(baseUrl() + "/api/antivirus/history/me?page=0&size=50")).GET().build();
        HttpResponse<String> historyResp = client.send(historyReq, HttpResponse.BodyHandlers.ofString());
        JsonNode historyBody = mapper.readTree(historyResp.body());
        int totalInHistory = historyBody.get("totalElements").asInt();

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("concurrentScans", concurrentScans);
        metrics.put("successCount", successCount.get());
        metrics.put("errorCount", errorCount.get());
        metrics.put("errorRatePct", round2(errorRate * 100));
        metrics.put("historyTotalElements", totalInHistory);
        PressureMetricsCollector.record("concurrentScans", metrics);

        assertTrue(errorRate < 0.05,
                "Error rate for " + concurrentScans + " concurrent scans from one authenticated user was "
                        + (errorRate * 100) + "%, expected under 5%");
        assertTrue(totalInHistory >= successCount.get(),
                "Expected at least " + successCount.get() + " scans in history after concurrent uploads, found "
                        + totalInHistory);
    }

    /**
     * Flushes whichever of the three tests above ran in this JVM fork to
     * load-metrics.json. ScanAccuracyIT flushes its own accuracy-metrics.json
     * independently; scripts/generate_pressure_report.py combines both
     * after "mvn verify -Ppressure" finishes.
     */
    @AfterAll
    static void flushMetrics() {
        PressureMetricsCollector.flush("load-metrics.json",
                "concurrentTraffic", "concurrentScans", "rateLimiter");
    }

    private static double round2(double value) {
        return Math.round(value * 100.0) / 100.0;
    }
}
