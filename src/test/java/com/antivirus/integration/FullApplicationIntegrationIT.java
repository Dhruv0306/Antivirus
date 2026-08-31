package com.antivirus.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Full end-to-end walk of the real HTTP surface against a real Spring
 * context: register, log in, scan a file, read the caller's own history,
 * confirm RBAC blocks a USER from the admin history endpoint, and confirm
 * the seeded ADMIN account can reach it.
 *
 * This is deliberately black-box: it talks HTTP only, exactly like the real
 * frontend does, including CSRF and session cookie handling. No mocks, no
 * @MockitoBean, no reaching into internals.
 *
 * Named *IntegrationIT.java, not *Test.java, so mvn test never picks this
 * up. Only "mvn verify -Pintegration" runs it (see the integration
 * profile in pom.xml).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("integrationtest")
class FullApplicationIntegrationIT {

    @LocalServerPort
    private int port;

    private final ObjectMapper mapper = new ObjectMapper();
    private HttpClient client;
    private String baseUrl;

    @BeforeEach
    void setUp() {
        baseUrl = "http://localhost:" + port;
        // A fresh CookieManager per test means a fresh session per test:
        // nothing leaks between test methods.
        client = HttpClient.newBuilder()
                .cookieHandler(new CookieManager())
                .build();
    }

    private String[] fetchCsrf() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/api/auth/csrf"))
                .GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode(), "CSRF bootstrap endpoint should be reachable without auth");
        JsonNode node = mapper.readTree(resp.body());
        return new String[] { node.get("headerName").asText(), node.get("token").asText() };
    }

    private HttpResponse<String> register(String username, String email, String password) throws Exception {
        String[] csrf = fetchCsrf();
        String body = mapper.writeValueAsString(Map.of(
                "username", username,
                "email", email,
                "password", password,
                "confirmPassword", password));
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/api/auth/register"))
                .header("Content-Type", "application/json")
                .header(csrf[0], csrf[1])
                .POST(BodyPublishers.ofString(body))
                .build();
        return client.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> login(String username, String password) throws Exception {
        String[] csrf = fetchCsrf();
        String form = "username=" + username + "&password=" + password;
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/api/auth/login"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header(csrf[0], csrf[1])
                .POST(BodyPublishers.ofString(form))
                .build();
        return client.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String path) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + path)).GET().build();
        return client.send(req, HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void registerLoginScanAndReadOwnHistory() throws Exception {
        String username = "it_user_" + UUID.randomUUID().toString().substring(0, 8);
        String password = "IntegrationTestUserPass123!";

        HttpResponse<String> registerResponse = register(username, username + "@example.com", password);
        assertEquals(201, registerResponse.statusCode(), "Registration should succeed: " + registerResponse.body());

        HttpResponse<String> loginResponse = login(username, password);
        assertEquals(200, loginResponse.statusCode(), "Login should succeed: " + loginResponse.body());

        HttpResponse<String> meResponse = get("/api/auth/me");
        assertEquals(200, meResponse.statusCode());
        assertTrue(meResponse.body().contains("\"role\":\"USER\""),
                "Newly registered account should have USER role: " + meResponse.body());

        // Scan a small, clean text file as a real multipart upload, exactly
        // as the browser would send it.
        String[] csrf = fetchCsrf();
        String boundary = "----IntegrationITBoundary" + UUID.randomUUID();
        String fileContent = "This is a harmless integration test file.\n";
        String multipartBody = "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"integration-test.txt\"\r\n"
                + "Content-Type: text/plain\r\n\r\n"
                + fileContent + "\r\n"
                + "--" + boundary + "--\r\n";

        HttpRequest scanReq = HttpRequest.newBuilder(URI.create(baseUrl + "/api/antivirus/scan/file"))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .header(csrf[0], csrf[1])
                .POST(BodyPublishers.ofString(multipartBody))
                .build();
        HttpResponse<String> scanResponse = client.send(scanReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, scanResponse.statusCode(), "Scanning a clean file should succeed: " + scanResponse.body());

        // The scan should now show up in the user's own history.
        HttpResponse<String> historyResponse = get("/api/antivirus/history/me?page=0&size=10");
        assertEquals(200, historyResponse.statusCode());
        JsonNode historyBody = mapper.readTree(historyResponse.body());
        assertTrue(historyBody.get("totalElements").asInt() >= 1,
                "Own scan history should contain at least the scan just completed");

        // A plain USER must not reach the admin-only global history endpoint.
        HttpResponse<String> adminHistoryResponse = get("/api/antivirus/history?page=0&size=10");
        assertEquals(403, adminHistoryResponse.statusCode(),
                "USER role must be denied the admin-only /history endpoint");
    }

    @Test
    void adminCanReachGlobalHistoryEndpoint() throws Exception {
        HttpResponse<String> loginResponse = login("integration_admin", "IntegrationTestAdminPass123!");
        assertEquals(200, loginResponse.statusCode(), "Seeded admin login should succeed: " + loginResponse.body());

        HttpResponse<String> adminHistoryResponse = get("/api/antivirus/history?page=0&size=10");
        assertEquals(200, adminHistoryResponse.statusCode(),
                "Seeded ADMIN account should reach the global history endpoint: " + adminHistoryResponse.body());
    }

    @Test
    void registrationRejectsDuplicateUsernameWithGenericMessage() throws Exception {
        String username = "it_dup_" + UUID.randomUUID().toString().substring(0, 8);
        String password = "IntegrationTestUserPass123!";

        HttpResponse<String> first = register(username, username + "@example.com", password);
        assertEquals(201, first.statusCode());

        HttpResponse<String> second = register(username, "different-" + username + "@example.com", password);
        assertEquals(409, second.statusCode());
        assertTrue(second.body().contains("not available"),
                "Duplicate registration should return the generic anti-enumeration message: " + second.body());
    }

    @Test
    void unauthenticatedRequestsAreRejected() throws Exception {
        HttpResponse<String> meResponse = get("/api/auth/me");
        assertEquals(401, meResponse.statusCode(), "An unauthenticated caller should not see /api/auth/me");

        HttpResponse<String> historyResponse = get("/api/antivirus/history/me");
        assertEquals(401, historyResponse.statusCode(),
                "An unauthenticated caller should not reach their own scan history");
    }
}
