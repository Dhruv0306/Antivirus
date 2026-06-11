package com.antivirus.util;

import java.nio.file.Path;

/**
 * Utilities for safe filesystem path handling.
 */
public final class PathSecurityUtil {

    private PathSecurityUtil() {
    }

    /**
     * Resolves a relative path under a base directory and rejects traversal attempts.
     *
     * @throws SecurityException if the resolved path escapes the base directory
     */
    public static Path resolveSafely(Path baseDirectory, String relativePath) {
        if (relativePath == null || relativePath.isBlank()) {
            throw new SecurityException("Path must not be empty");
        }

        String normalizedRelative = relativePath.replace('\\', '/');
        if (normalizedRelative.startsWith("/")
                || normalizedRelative.contains("..")
                || normalizedRelative.contains("\0")) {
            throw new SecurityException("Path traversal detected: " + relativePath);
        }

        Path resolved = baseDirectory.resolve(normalizedRelative).normalize();
        if (!resolved.startsWith(baseDirectory)) {
            throw new SecurityException("Path traversal detected: " + relativePath);
        }
        return resolved;
    }
}
