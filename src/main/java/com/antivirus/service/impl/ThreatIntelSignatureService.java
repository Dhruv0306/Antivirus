package com.antivirus.service.impl;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Owns the known-malware-hash set used by SecurityServiceImpl's
 * known-hash-match check.
 *
 * Design notes (replacing an earlier version of this logic that lived in a
 * static initializer on SecurityServiceImpl):
 *
 * - Runs as a normal Spring-managed singleton bean with @PostConstruct, not
 * a static block, so it participates in the ordinary bean lifecycle and can
 * be mocked/substituted in tests instead of firing the moment the class is
 * loaded by the JVM (which happened even in plain unit tests that never
 * touch Spring).
 * - The local cache file is loaded synchronously at startup (fast, no
 * network) so lookups work immediately. The remote feed refresh runs on a
 * background daemon thread and never blocks application startup or a
 * request thread.
 * - HttpClient is injected so tests can substitute a fake/mock instead of
 * making real network calls.
 * - Feature is gated by app.threat-intel.enabled (defaults on, but a fully
 * air-gapped deployment can turn it off without code changes) and by
 * app.threat-intel.refresh-on-startup for whether to always hit the remote
 * feed vs. trust the on-disk cache.
 */
@Service
public class ThreatIntelSignatureService {

    private static final Logger logger = LoggerFactory.getLogger(ThreatIntelSignatureService.class);

    // SHA-256 of the EICAR standard antivirus test string, the one hash
    // every AV product can safely ship. See
    // https://www.eicar.org/download-anti-malware-testfile/
    static final String EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private static final Pattern SHA256_PATTERN = Pattern.compile("\\b[a-fA-F0-9]{64}\\b");

    private final Set<String> signatures = ConcurrentHashMap.newKeySet();

    @Autowired
    private HttpClient threatIntelHttpClient;

    /** Token replaced with the abuse.ch Auth-Key when a feed URL is requested. */
    static final String AUTH_KEY_PLACEHOLDER = "{authKey}";

    /**
     * abuse.ch retired the keyless MalwareBazaar export URLs (they now answer
     * HTTP 410 Gone). Exports require a free Auth-Key (https://auth.abuse.ch/)
     * which goes in the URL path. recent.csv covers the last 48 hours.
     */
    static final String DEFAULT_FEED_URL =
            "https://mb-api.abuse.ch/v2/files/exports/" + AUTH_KEY_PLACEHOLDER + "/recent.csv";

    // Feed URLs may contain {authKey}; it is substituted at request time and
    // the key is never logged (only the template is).
    @Value("${app.threat-intel.urls:https://mb-api.abuse.ch/v2/files/exports/{authKey}/recent.csv}")
    private String feedUrlsConfig;

    // abuse.ch Auth-Key. Property app.threat-intel.auth-key, falling back to
    // the ABUSECH_AUTH_KEY environment variable. Blank means keyed feeds are
    // skipped with a warning instead of calling a URL that cannot succeed.
    @Value("${app.threat-intel.auth-key:${ABUSECH_AUTH_KEY:}}")
    private String authKey = "";

    @Value("${app.threat-intel.cache-file:data/threat-intel-signatures.sha256}")
    private String cacheFileConfig;

    @Value("${app.threat-intel.refresh-on-startup:false}")
    private boolean refreshOnStartup;

    @Value("${app.threat-intel.enabled:true}")
    private boolean enabled;

    private final ExecutorService refreshExecutor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "threat-intel-refresh");
        thread.setDaemon(true);
        return thread;
    });

    @PostConstruct
    void init() {
        signatures.add(EICAR_SHA256);

        if (!enabled) {
            logger.info("Threat-intel feed disabled (app.threat-intel.enabled=false); using EICAR signature only");
            return;
        }

        Set<String> cached = loadCache();
        if (!cached.isEmpty()) {
            signatures.addAll(cached);
            logger.info("Loaded {} cached threat-intel signatures", cached.size());
        }

        // Fire-and-forget: never block application startup on an external
        // network call. If the feed is slow or unreachable, the app starts
        // normally with whatever the cache (or just EICAR) provided, and
        // picks up the remote signatures whenever the background task
        // finishes.
        if (refreshOnStartup || cached.isEmpty()) {
            refreshExecutor.submit(this::refreshFromRemote);
        }
    }

    @PreDestroy
    void shutdown() {
        refreshExecutor.shutdownNow();
    }

    /** Thread-safe lookup used by the scanning path. */
    public boolean isKnownMalicious(String sha256Hash) {
        return sha256Hash != null && signatures.contains(sha256Hash.toLowerCase(Locale.ROOT));
    }

    public int signatureCount() {
        return signatures.size();
    }

    /**
     * Triggers a background refresh and returns immediately. Used by the
     * /api/antivirus/update endpoint so an admin-triggered refresh doesn't
     * tie up the request thread waiting on an external HTTP call.
     */
    public CompletableFuture<Integer> refreshAsync() {
        if (!enabled) {
            return CompletableFuture.completedFuture(0);
        }
        return CompletableFuture.supplyAsync(this::refreshFromRemote, refreshExecutor);
    }

    int refreshFromRemote() {
        Set<String> fetched = new LinkedHashSet<>();
        for (String feedUrl : resolveFeedUrls()) {
            // feedUrl is the configured template and is the only form that is
            // ever logged; requestUrl may contain the Auth-Key.
            String requestUrl = feedUrl;
            if (feedUrl.contains(AUTH_KEY_PLACEHOLDER)) {
                if (!hasAuthKey()) {
                    logger.warn("Threat-intel feed {} needs an abuse.ch Auth-Key (set app.threat-intel.auth-key "
                            + "or ABUSECH_AUTH_KEY, free key at https://auth.abuse.ch/); skipping", feedUrl);
                    continue;
                }
                requestUrl = feedUrl.replace(AUTH_KEY_PLACEHOLDER,
                        URLEncoder.encode(authKey.trim(), StandardCharsets.UTF_8));
            }
            try {
                HttpRequest request = HttpRequest.newBuilder(URI.create(requestUrl))
                        .timeout(Duration.ofSeconds(10))
                        .header("User-Agent", "SecureGuard-Antivirus/1.0")
                        .GET()
                        .build();
                HttpResponse<String> response = threatIntelHttpClient.send(
                        request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

                if (response.statusCode() / 100 != 2) {
                    logger.warn("Threat-intel feed {} returned HTTP {}{}",
                            feedUrl, response.statusCode(), statusHint(response.statusCode()));
                    continue;
                }
                fetched.addAll(extractSha256Signatures(response.body()));
            } catch (Exception e) {
                // Deliberately broad: a bad feed must never take down the
                // refresh task or, via an uncaught exception on this
                // executor, the JVM's default handler. The message is
                // redacted because exceptions often echo the request URL.
                logger.warn("Failed to load threat-intel feed {}: {}", feedUrl, redact(e.getMessage(), authKey));
            }
        }

        if (!fetched.isEmpty()) {
            signatures.addAll(fetched);
            // Persist the full accumulated set, not just this round's
            // fetch: the feed only exports "recent" hashes, so a hash we
            // added on an earlier refresh could drop out of a later
            // fetch's window. Writing just `fetched` each time would
            // silently lose those on the next restart.
            persistCache(signatures);
            logger.info("Loaded {} new threat-intel signatures from {} feed(s), {} total in memory",
                    fetched.size(), resolveFeedUrls().size(), signatures.size());
        } else {
            logger.warn("No threat-intel signatures were returned by the configured feeds");
        }
        return fetched.size();
    }

    private boolean hasAuthKey() {
        return authKey != null && !authKey.isBlank();
    }

    private static String statusHint(int status) {
        return switch (status) {
            case 401, 403 -> " (abuse.ch rejected the Auth-Key; check it is valid and not revoked)";
            case 410 -> " (endpoint retired by abuse.ch; check the URL against https://bazaar.abuse.ch/export/)";
            default -> "";
        };
    }

    /** Replaces every occurrence of the Auth-Key (raw or URL-encoded) with ***. */
    static String redact(String text, String key) {
        if (text == null || key == null || key.isBlank()) {
            return text;
        }
        String trimmed = key.trim();
        return text.replace(trimmed, "***")
                .replace(URLEncoder.encode(trimmed, StandardCharsets.UTF_8), "***");
    }

    private Set<String> loadCache() {
        Path cachePath = resolveCachePath();
        if (!Files.isRegularFile(cachePath)) {
            return Set.of();
        }
        try {
            Set<String> loaded = new LinkedHashSet<>();
            for (String line : Files.readAllLines(cachePath, StandardCharsets.UTF_8)) {
                loaded.addAll(extractSha256Signatures(line));
            }
            return loaded;
        } catch (IOException e) {
            logger.warn("Failed to load cached threat-intel signatures from {}: {}", cachePath, e.getMessage());
            return Set.of();
        }
    }

    private void persistCache(Set<String> newSignatures) {
        Path cachePath = resolveCachePath();
        try {
            Path parent = cachePath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(cachePath, newSignatures.stream().sorted().toList(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            logger.warn("Failed to persist threat-intel cache to {}: {}", cachePath, e.getMessage());
        }
    }

    static Set<String> extractSha256Signatures(String content) {
        Set<String> found = new LinkedHashSet<>();
        if (content == null || content.isBlank()) {
            return found;
        }
        Matcher matcher = SHA256_PATTERN.matcher(content);
        while (matcher.find()) {
            found.add(matcher.group().toLowerCase(Locale.ROOT));
        }
        return found;
    }

    @SuppressWarnings("null")
    private List<String> resolveFeedUrls() {
        return Arrays.stream(feedUrlsConfig.split("[,;\\s]+"))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .toList();
    }

    private Path resolveCachePath() {
        return Paths.get(cacheFileConfig);
    }
}
