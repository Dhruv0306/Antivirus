package com.antivirus.service.impl;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Phase 3: nightly-only integrity check for the real, live MalwareBazaar
 * recent-feed integration that ThreatIntelSignatureService relies on in
 * production.
 *
 * This is deliberately NOT picked up by plain "mvn test" (no *Test suffix
 * collision issue since this ends in *IT, but more importantly it is not
 * wired into the failsafe "pressure" profile either, see pom.xml, it has
 * its own "live-feed-check" profile) and is only ever invoked by
 * .github/workflows/threat-intel-feed-check.yml on a nightly schedule, never
 * on every PR. It depends on a third party (bazaar.abuse.ch) being reachable
 * and its export format being unchanged, neither of which this repository
 * controls, so it must never be able to block a merge.
 *
 * Deliberately exercises the ACTUAL production code path
 * (refreshFromRemote(), which calls the real extractSha256Signatures()
 * regex), not a reimplementation of it in a shell script or separate
 * parser. If abuse.ch changes their export format, or the SHA256_PATTERN
 * regex in ThreatIntelSignatureService silently stops matching, this test
 * fails using the exact same logic that would be broken in production,
 * there is no second, potentially-stale copy of the parsing logic to keep
 * in sync.
 *
 * Needs a free abuse.ch Auth-Key in the ABUSECH_AUTH_KEY environment
 * variable (abuse.ch retired the keyless export URLs, they answer HTTP
 * 410). In GitHub Actions a missing key fails the test; locally it skips.
 *
 * Read-only and hash-only: no fetched hash is ever asserted against,
 * inspected, or persisted anywhere this test controls (the cache file is
 * redirected to a JUnit @TempDir specifically so this never touches the
 * real data/threat-intel-signatures.sha256 file). The only thing this test
 * cares about is "did the feed return a non-trivial number of hashes", not
 * which hashes they were.
 */
class ThreatIntelLiveFeedIT {

    @Test
    void liveMalwareBazaarFeedReturnsANonTrivialHashCount(@TempDir Path tempDir) {
        String authKey = System.getenv("ABUSECH_AUTH_KEY");
        boolean hasKey = authKey != null && !authKey.isBlank();
        if (!hasKey && "true".equals(System.getenv("GITHUB_ACTIONS"))) {
            fail("ABUSECH_AUTH_KEY is not set; add it as a repository secret (free key at https://auth.abuse.ch/).");
        }
        assumeTrue(hasKey, "ABUSECH_AUTH_KEY not set, skipping live MalwareBazaar check");

        ThreatIntelSignatureService service = new ThreatIntelSignatureService();
        ReflectionTestUtils.setField(service, "threatIntelHttpClient",
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build());
        ReflectionTestUtils.setField(service, "feedUrlsConfig", ThreatIntelSignatureService.DEFAULT_FEED_URL);
        ReflectionTestUtils.setField(service, "authKey", authKey);
        // Redirect the cache file to a throwaway temp path: refreshFromRemote()
        // persists whatever it fetches, and this test must never write into
        // the real data/threat-intel-signatures.sha256 file that ships with
        // the app.
        ReflectionTestUtils.setField(service, "cacheFileConfig",
                tempDir.resolve("threat-intel-signatures.sha256").toString());

        int fetchedCount = service.refreshFromRemote();

        // The "recent" export typically carries several thousand hashes.
        // 50 is a deliberately conservative floor: a quiet submission day
        // shouldn't page anyone, but zero or single digits means either the
        // feed is down or, more concerning, its export format changed and
        // extractSha256Signatures() silently stopped matching anything, a
        // real production detection gap that would otherwise go unnoticed
        // until someone asked why a known hash wasn't being caught.
        assertTrue(fetchedCount >= 50,
                "MalwareBazaar's recent feed returned only " + fetchedCount + " parsed hashes, "
                        + "expected at least 50. Check the HTTP status in the log first: 401/403 means a bad "
                        + "Auth-Key, 410 means the endpoint was retired. With a 200, the export format likely "
                        + "changed and ThreatIntelSignatureService.extractSha256Signatures() needs updating. "
                        + "Either way this needs a human look, not a silent retry.");
    }
}
