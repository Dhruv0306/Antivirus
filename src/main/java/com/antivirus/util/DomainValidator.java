package com.antivirus.util;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Validates domain names before persisting or writing to system files.
 */
public final class DomainValidator {

    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
        "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$"
    );

    private DomainValidator() {
    }

    public static String validateAndNormalize(String domain) {
        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException("Domain must not be empty");
        }

        String normalized = domain.trim().toLowerCase(Locale.ROOT);
        if (normalized.length() > 253 || !DOMAIN_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException("Invalid domain name: " + domain);
        }
        return normalized;
    }
}
