package com.antivirus.pressure;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.util.Map;

/**
 * CSRF/register/login helpers shared by the pressure and accuracy IT
 * classes. Pulled out of EndpointPressureIT so ScanAccuracyIT does not
 * have to duplicate the same request plumbing to get an authenticated
 * client before it can hit /api/antivirus/scan/file.
 */
final class PressureTestAuthSupport {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private PressureTestAuthSupport() {
    }

    /** Returns "headerName|token" for the CSRF header the caller must echo back. */
    static String fetchCsrfHeaderAndToken(HttpClient client, String baseUrl) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/api/auth/csrf")).GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        JsonNode node = MAPPER.readTree(resp.body());
        return node.get("headerName").asText() + "|" + node.get("token").asText();
    }

    static void registerAndLogin(HttpClient client, String baseUrl, String username, String password)
            throws Exception {
        String[] csrf = fetchCsrfHeaderAndToken(client, baseUrl).split("\\|", 2);
        String registerBody = MAPPER.writeValueAsString(Map.of(
                "username", username,
                "email", username + "@example.com",
                "password", password,
                "confirmPassword", password));
        HttpRequest registerReq = HttpRequest.newBuilder(URI.create(baseUrl + "/api/auth/register"))
                .header("Content-Type", "application/json")
                .header(csrf[0], csrf[1])
                .POST(BodyPublishers.ofString(registerBody))
                .build();
        client.send(registerReq, HttpResponse.BodyHandlers.ofString());

        String[] loginCsrf = fetchCsrfHeaderAndToken(client, baseUrl).split("\\|", 2);
        String form = "username=" + username + "&password=" + password;
        HttpRequest loginReq = HttpRequest.newBuilder(URI.create(baseUrl + "/api/auth/login"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header(loginCsrf[0], loginCsrf[1])
                .POST(BodyPublishers.ofString(form))
                .build();
        client.send(loginReq, HttpResponse.BodyHandlers.ofString());
    }
}
