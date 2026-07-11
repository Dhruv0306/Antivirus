package com.antivirus.config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import java.util.Arrays;

/**
 * Guards against the prod profile silently booting on the ephemeral
 * in-memory H2 default.
 *
 * application-prod.properties defines:
 * spring.datasource.url=${DB_URL:jdbc:h2:mem:antivirus_v3;...}
 *
 * If DB_URL is not set in the deployment environment, the app starts
 * without error and every scan result / user account is lost on restart.
 * Mirrors the fail-fast pattern already used in SecurityConfig for
 * CORS origin validation.
 */
@Configuration
public class DatasourceSafetyConfig {

    @Autowired
    private Environment environment;

    @Value("${spring.datasource.url:}")
    private String datasourceUrl;

    @PostConstruct
    public void validateDatasource() {
        boolean isProd = Arrays.asList(environment.getActiveProfiles()).contains("prod");
        if (!isProd) {
            return;
        }
        if (datasourceUrl == null || datasourceUrl.contains("h2:mem")) {
            throw new IllegalStateException(
                    "DB_URL must be set to a persistent database in the prod profile " +
                            "(e.g. jdbc:postgresql://host:5432/antivirus). " +
                            "An unset DB_URL falls back to jdbc:h2:mem, which loses all " +
                            "data on every restart.");
        }
    }
}
