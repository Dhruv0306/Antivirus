package com.antivirus.pressure;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe accumulator that the pressure/accuracy IT classes record
 * their results into, and flush to a JSON file under
 * target/pressure-metrics/ at the end of the class.
 *
 * Deliberately kept dependency-free beyond Jackson (already pulled in
 * by spring-boot-starter-test) so this does not need a new Maven
 * plugin. A separate step (scripts/generate_pressure_report.py, run
 * after "mvn verify -Ppressure" in CI, see .github/workflows/pressure-test.yml)
 * reads the JSON these classes write and renders the committed
 * docs/pressure-metrics.md and docs/pressure-metrics.svg report. That
 * rendering step is kept out of this JVM entirely so the load and
 * accuracy test classes do not need to share a lifecycle, a forked
 * JVM, or a run order to end up in one combined report.
 */
final class PressureMetricsCollector {

    static final Path OUTPUT_DIR = Path.of("target", "pressure-metrics");

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Map<String, Map<String, Object>> SECTIONS = new ConcurrentHashMap<>();

    private PressureMetricsCollector() {
    }

    /** Records one named section's results (e.g. "concurrentTraffic", "confusionMatrix"). */
    static void record(String section, Map<String, Object> data) {
        SECTIONS.put(section, data);
    }

    /** Writes the requested sections (in order) to target/pressure-metrics/{fileName}. */
    static synchronized void flush(String fileName, String... sections) {
        try {
            Files.createDirectories(OUTPUT_DIR);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("generatedAt", Instant.now().toString());
            for (String section : sections) {
                Map<String, Object> data = SECTIONS.get(section);
                if (data != null) {
                    out.put(section, data);
                }
            }
            Path target = OUTPUT_DIR.resolve(fileName);
            MAPPER.writerWithDefaultPrettyPrinter().writeValue(target.toFile(), out);
        } catch (IOException e) {
            throw new RuntimeException("Failed to write pressure metrics to " + fileName, e);
        }
    }
}
