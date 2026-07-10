package com.antivirus.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PathSecurityUtilTest {

    @TempDir
    Path baseDir;

    @Test
    void resolveSafely_ShouldResolveValidRelativePath() {
        Path resolved = PathSecurityUtil.resolveSafely(baseDir, "subdir/file.txt");

        assertTrue(resolved.startsWith(baseDir));
        assertEquals(baseDir.resolve("subdir/file.txt").normalize(), resolved);
    }

    @Test
    void resolveSafely_ShouldAllowSimpleFileName() {
        Path resolved = PathSecurityUtil.resolveSafely(baseDir, "file.txt");

        assertEquals(baseDir.resolve("file.txt"), resolved);
    }

    @Test
    void resolveSafely_ShouldNormalizeBackslashesToForwardSlashes() {
        Path resolved = PathSecurityUtil.resolveSafely(baseDir, "subdir\\file.txt");

        assertTrue(resolved.startsWith(baseDir));
        assertEquals(baseDir.resolve("subdir/file.txt").normalize(), resolved);
    }

    @Test
    void resolveSafely_ShouldRejectNullPath() {
        assertThrows(SecurityException.class, () -> PathSecurityUtil.resolveSafely(baseDir, null));
    }

    @Test
    void resolveSafely_ShouldRejectBlankPath() {
        assertThrows(SecurityException.class, () -> PathSecurityUtil.resolveSafely(baseDir, "   "));
    }

    @Test
    void resolveSafely_ShouldRejectParentTraversal() {
        assertThrows(SecurityException.class, () -> PathSecurityUtil.resolveSafely(baseDir, "../outside.txt"));
    }

    @Test
    void resolveSafely_ShouldRejectNestedParentTraversal() {
        assertThrows(SecurityException.class,
                () -> PathSecurityUtil.resolveSafely(baseDir, "subdir/../../outside.txt"));
    }

    @Test
    void resolveSafely_ShouldRejectAbsolutePath() {
        assertThrows(SecurityException.class, () -> PathSecurityUtil.resolveSafely(baseDir, "/etc/passwd"));
    }

    @Test
    void resolveSafely_ShouldRejectNullByte() {
        assertThrows(SecurityException.class, () -> PathSecurityUtil.resolveSafely(baseDir, "file.txt\0.png"));
    }

    @Test
    void resolveSafely_ShouldRejectPathContainingDotDotEvenWithoutEscaping() {
        // ".." appears anywhere in the relative path, not just as a full segment
        assertThrows(SecurityException.class, () -> PathSecurityUtil.resolveSafely(baseDir, "sub..dir/file.txt"));
    }
}
