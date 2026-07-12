package com.antivirus.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.http.HttpClient;
import java.time.Duration;

/**
 * Provides java.net.http.HttpClient as a Spring bean so it can be injected
 * (and substituted with a mock/fake in tests) rather than constructed as a
 * hardcoded static final field. Currently only ThreatIntelSignatureService
 * uses this, but keeping it as a shared bean avoids every future outbound
 * HTTP caller reinventing its own client with its own timeout defaults.
 */
@Configuration
public class HttpClientConfig {

    @Bean
    public HttpClient threatIntelHttpClient() {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }
}