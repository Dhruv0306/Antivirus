# SecureGuard Antivirus: Real-World Testing Improvement Plan

**Author context:** security review of the pressure/accuracy/evasion test suite, following the merge of `ScanEvasionIT.java` (adversarial evasion, false-positive resistance, and single-sample known-hash pathway coverage).

**Goal:** move detection validation closer to real-world efficacy without ever introducing live malware payloads into the repository, CI runners, or developer machines. Every phase below uses either published, safe metadata (hashes, checksums, technique citations) or synthetic content engineered from documented real-world patterns.

**Non-negotiable constraint carried through every phase:** no functional malware is ever committed, downloaded, or executed as part of this work. Where "real-world" data is needed, it is sourced as hashes, checksums, or documented technique descriptions, never as executable payloads.

---

## Sequencing overview

| Phase | What it adds | Effort | Depends on | Can run in parallel with |
|---|---|---|---|---|
| 1 | Broader known-malicious hash corpus | Low | Existing `ScanEvasionIT` hash test | Phase 2, Phase 4 |
| 2 | Known-good hash allowlist test | Low | None | Phase 1, Phase 4 |
| 3 | Nightly live threat-intel feed integrity job | Moderate | None (independent infra) | Any phase |
| 4 | Source citations retrofitted into evasion corpus | Low (docs only) | Existing `ScanEvasionIT` | Any phase |
| 5 | Entropy-based packer detection (new engine signal) | High | Phases 1, 2, 4 complete | None, sequenced last |

**Recommended order:** Phases 1 and 2 together as one PR (same shape of work, symmetric coverage), Phase 4 interleaved into that same PR at no extra cost, Phase 3 whenever CI bandwidth allows, Phase 5 on its own branch once the above give a stable baseline to measure the new signal against.

---

## Phase 1: Broaden the known-malicious hash corpus

### Objective
Move the known-hash detection pathway (`ThreatIntelSignatureService`) from "proven to work with one sample" to "proven to work across multiple real, documented malware families."

### Rationale
`knownMalwareHashesFromPublicThreatIntelAreDetected()` currently seeds and checks a single published SHA-256 hash (a WannaCry sample, cited to MalwareBazaar and US-CERT TA17-132A). That test proves the mechanism is wired correctly end to end, but a sample size of one says nothing about whether the pathway holds up across the variety of hashes a real MalwareBazaar feed actually contains.

### Scope of changes
- Curate 15 to 20 published SHA-256 hashes spanning distinct malware categories: ransomware, infostealer, botnet/loader, remote-access trojan.
- Source each hash from MalwareBazaar's tagged exports (`bazaar.abuse.ch`), recording the family name and a source citation as an inline comment next to each hash constant.
- Seed all hashes into the live `ThreatIntelSignatureService` bean the same way the existing test does (via `ReflectionTestUtils` on the `signatures` field), simulating what a real feed refresh would populate.
- Assert each hash is recognized by `isKnownMalicious()`.
- For the end-to-end HTTP path, keep using the existing pattern of a single locally-generated, test-controlled hash (since matching real file content to a pre-published hash is not achievable, nor desirable, without breaking SHA-256 preimage resistance).

### New/changed metrics
- `knownHashCoverageByFamily`: a map of family name to detected/total, reported in `evasion-metrics.json` and rendered into `docs/pressure-metrics.md`.
- Replaces the current single boolean `realWorldIocRecognized` with a per-family breakdown.

### Files touched
- `src/test/java/com/antivirus/pressure/ScanEvasionIT.java`
- `scripts/generate_pressure_report.py` (render the new per-family table)

### Risk and safety notes
- Zero payload risk: every new fixture is a 64-character hex string, nothing executable.
- No new network calls in CI: hashes are hardcoded fixtures with citations, not fetched live (that's Phase 3's job).
- Legal/ToS exposure: none. Publishing and testing against known-malware hashes is standard, uncontroversial industry practice (this is literally what MalwareBazaar exists for).

### Acceptance criteria
- All curated hashes are recognized by `isKnownMalicious()` once seeded.
- Each hash has a traceable citation (source URL or MalwareBazaar tag reference) in the test source.
- `docs/pressure-metrics.md` shows a per-family coverage breakdown, not just a single overall boolean.

---

## Phase 2: Known-good hash allowlist test

### Objective
Add the direct counterpart to Phase 1 on the false-positive side: validate that real, third-party-verified legitimate software is never flagged, using actual published checksums rather than synthetic prose guesses.

### Rationale
The current false-positive suite (`legitimateContentIsNotOverFlagged()`) uses realistic but invented text scenarios (sysadmin scripts, backup-tool docs). That is useful, but it is still my synthetic approximation of what legitimate content looks like. The industry-standard approach to this exact problem is NIST's National Software Reference Library (NSRL), a federally maintained Reference Data Set (RDS) of hashes for known-legitimate commercial and open-source software, used across forensics and AV tooling specifically to suppress false positives on known-good files.

The full NSRL RDS is impractical for CI (quarterly multi-gigabyte releases), so the practical version of this idea is pinning official checksums that specific open-source projects publish themselves on their release pages, methodologically the same idea NSRL formalizes at scale, just scoped to a handful of pinned releases.

### Scope of changes
- Select 5 to 10 well-known, actively maintained open-source tools with officially published release checksums (candidates: `curl`, `7-Zip`, `ripgrep`, `jq`, `OpenSSL`).
- Record each tool's name, version, official SHA-256 checksum, and the exact URL where that checksum is published, as citations in the test source.
- New test class or new test method seeded with these hashes via the same `ThreatIntelSignatureService`-adjacent mechanism, or, if a separate allowlist concept doesn't exist yet in `SecurityServiceImpl`, use this phase to also scope whether a hash-allowlist short-circuit is worth adding to the production scanning path itself (currently the engine has no known-good fast path, only known-bad).
- Pair each known-good hash with an adversarial-looking filename (e.g. naming the legitimate binary something that would otherwise trip `TROJAN_NAME_SIGNATURES` or `RANSOMWARE_EXTENSIONS`) to confirm a real hash match, if implemented, would correctly override filename-based heuristics.

### New/changed metrics
- `knownGoodHashFalsePositiveRate`: should be 0.0 given real checksummed content.
- `knownGoodSourcesCited`: count of allowlist entries with a traceable official source.

### Files touched
- `src/test/java/com/antivirus/pressure/ScanEvasionIT.java` (or a new `KnownGoodHashAllowlistIT.java` if scope grows)
- Possibly `src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java`, only if the team decides a production allowlist short-circuit is worth adding, this is a scoping decision to make during this phase, not an assumed requirement.

### Risk and safety notes
- Zero payload risk: same as Phase 1, hashes only.
- Sourcing discipline matters here more than in Phase 1: an allowlist hash is only as trustworthy as its citation. Every entry must link to the project's own official release page, not a third-party mirror.
- If a production allowlist short-circuit is added, it needs its own security review, since a hash allowlist is a bypass mechanism and bypass mechanisms are exactly the kind of thing attackers try to abuse (e.g. via hash collision or by tricking a maintainer into allowlisting a compromised release). Recommend scoping that as a explicit follow-on decision, not folding it in silently.

### Acceptance criteria
- All curated known-good hashes are confirmed to never produce a MALICIOUS verdict, even paired with adversarial filenames.
- Every entry has a citation to the software's own official release page.
- If a production allowlist mechanism is added, it has an explicit design note covering the bypass-abuse risk above.

---

## Phase 3: Nightly live threat-intel feed integrity job

### Objective
Catch silent breakage in the real MalwareBazaar feed integration before it results in a production detection gap, independent of any PR-time testing.

### Rationale
`ThreatIntelSignatureService` calls the real MalwareBazaar recent-feed endpoint in production. Phases 1 and 2 test against hardcoded fixture hashes, which proves the matching logic works but says nothing about whether the live feed fetch and parse still functions against the real, occasionally-changing upstream format. If abuse.ch changes their export format, the parser could start silently returning zero hashes, and nothing in the current suite would notice.

### Scope of changes
- New GitHub Actions workflow, separate from `pressure-test.yml`, scheduled nightly (not triggered on every PR, since it depends on external infrastructure availability and shouldn't block merges on a third party being down).
- Job performs a real, read-only call to the MalwareBazaar recent-feed endpoint.
- Confirms the response parses to a non-trivial hash count (a sane lower-bound threshold, not an exact count, since the feed's contents change constantly).
- Fails loudly (and ideally opens or comments on a tracking issue) if the parse yields zero or a suspiciously low count, signaling either a format change or an outage worth investigating.
- No hashes from this live call are persisted into the repository or used in assertions elsewhere; this job's only purpose is confirming the fetch-and-parse pipeline itself still works.

### New/changed metrics
- Not part of `pressure-metrics.md` (this is operational monitoring, not a detection-quality metric). Reports via workflow status/notification instead.

### Files touched
- New file: `.github/workflows/threat-intel-feed-check.yml`
- Possibly a small addition to `ThreatIntelSignatureService` if better structured logging/error surfacing is needed to make failures diagnosable from CI output alone.

### Risk and safety notes
- This is the one phase that deliberately touches live internet infrastructure from CI. Scope is kept minimal and read-only specifically to bound that risk: no payloads are ever downloaded, only the hash-only feed export.
- Network egress in this job must be limited to the MalwareBazaar endpoint domain, nothing broader.
- A flaky third-party endpoint means this job may occasionally fail for reasons unrelated to your code (upstream downtime). Treat failures as "investigate," not "auto-block," given it's a nightly, non-PR-blocking job.

### Acceptance criteria
- Job runs on a nightly schedule independent of the PR-blocking pressure suite.
- Job fails clearly and distinguishably when the feed returns zero or near-zero parsed hashes.
- Job never writes fetched hash data back into the repository.

---

## Phase 4: Retrofit source citations into the existing evasion corpus

### Objective
Make every technique in `ScanEvasionIT`'s adversarial corpus traceable to a real, documented source, so a security reviewer can verify "why does this test case exist" against external ground truth rather than trusting an inline comment written from memory.

### Rationale
The evasion techniques already in the suite (keyword fragmentation, base64-hidden payload text, filename-only trojan-signature blind spot, oversized-file pattern-scan-cap bypass, double-extension lure) are realistic and grounded in how the engine's own source code works, but they were written without an explicit citation back to a named, documented real-world technique. Attaching a MITRE ATT&CK technique ID or a specific vendor writeup to each case turns "Claude's judgment call" into "a documented technique this test specifically validates against."

### Scope of changes
For each existing case in `buildEvasionCases()`, add a citation comment mapping it to:
- A MITRE ATT&CK technique ID where one applies (candidates: T1027 Obfuscated Files or Information for the base64 case; T1036 Masquerading for the extension-masquerade and double-extension cases).
- Or a specific vendor/threat-research writeup where no clean ATT&CK mapping exists (e.g. for the pattern-scan-size-cap bypass, which is more of an implementation-specific gap than a named adversary technique, cite general AV-evasion literature on scan-size limits instead).
- No behavior or assertion changes, this phase is documentation-only.

### New/changed metrics
None. This phase changes traceability, not test outcomes.

### Files touched
- `src/test/java/com/antivirus/pressure/ScanEvasionIT.java` (comments only)
- Optionally, `docs/pressure-metrics.md` generator, to surface the citation alongside each technique in the per-technique table already rendered there.

### Risk and safety notes
- None. This is the lowest-risk phase in the plan by a wide margin.

### Acceptance criteria
- Every case in `buildEvasionCases()` has either a MITRE ATT&CK technique ID or a named external source in its comment.
- The per-technique table in `docs/pressure-metrics.md` optionally surfaces these citations for reviewer convenience.

---

## Phase 5: Entropy-based packer detection (new engine signal)

### Objective
Close the single largest real-world detection gap: the engine currently has no way to detect packed or encrypted executables, which represent the overwhelming majority of real-world malware, because packing is specifically designed to defeat static string and pattern matching.

### Rationale
Every phase above widens test coverage or hardens infrastructure around the existing detection logic. None of them add new detection capability, because the existing engine is fundamentally string, extension, and hash based, and packed malware is precisely engineered to have no recognizable strings. A Shannon entropy check is the standard, cheap, well-precedented first line of defense against this: packed or encrypted content has a measurably higher, more uniform byte-value distribution than typical plaintext or structured binary data, and essentially every static AV engine uses entropy as a pre-filter signal for exactly this reason.

This phase is sequenced last deliberately: a new detection signal needs a stable false-positive baseline (Phase 2) and a broadened true-positive baseline (Phase 1) already in place to judge whether the new signal is a net improvement, and a well-cited evasion corpus (Phase 4) to properly categorize what the new signal does and doesn't address.

### Scope of changes
- Add a Shannon entropy calculation over the scanned file body (or a representative window of it, consistent with the existing `MAX_PATTERN_SCAN_BYTES` performance constraint) in `SecurityServiceImpl`.
- Introduce a new scoring signal (e.g. `SCORE_HIGH_ENTROPY`) contributing to the existing weighted-score model, calibrated against the false-positive and true-positive baselines from Phases 1 and 2 before merging.
- Test strategy avoids real packed malware entirely: UPX-pack a small, legitimate, pinned open-source binary at test time (UPX is a standard, freely available, non-malicious packing tool) and confirm the entropy signal fires on the packed output. Packed legitimate software has an entropy profile indistinguishable from packed malware without being malicious, making it a safe and accurate stand-in for validating the detector.
- Confirm the same legitimate binary, unpacked, does not trigger the entropy signal, closing the loop on false-positive safety for the new detector specifically.

### New/changed metrics
- `entropyDetectionRate` against UPX-packed legitimate binaries (true-positive proxy).
- `entropyFalsePositiveRate` against a range of naturally high-entropy but legitimate content (compressed archives, already-encrypted files, media files), which is the main known risk of entropy-based detection and needs its own dedicated false-positive corpus, not just the Phase 2 allowlist.

### Files touched
- `src/main/java/com/antivirus/service/impl/SecurityServiceImpl.java`
- `src/test/java/com/antivirus/pressure/ScanEvasionIT.java` or a new dedicated `EntropyDetectionIT.java`
- `scripts/generate_pressure_report.py` (new metrics section)
- CI workflow, if UPX needs to be installed as a build-time dependency for the packing step

### Risk and safety notes
- This is a real production detection-logic change, not just a test addition, and should go through the same review rigor as any other change to `SecurityServiceImpl`'s scoring model.
- Entropy-based detection has a well-known false-positive mode: legitimate compressed, encrypted, or media files are also high-entropy. This phase is not safe to ship without a dedicated false-positive corpus covering that specific risk (zip archives, JPEGs, already-encrypted backups), separate from and in addition to Phase 2's allowlist.
- Recommend landing this on its own branch, reviewed independently from the test-infrastructure phases above, since it changes what gets flagged for real users.

### Acceptance criteria
- Entropy signal reliably fires on UPX-packed legitimate binaries.
- Entropy signal does not fire on the same binaries unpacked.
- A dedicated false-positive corpus of naturally high-entropy legitimate content (archives, media, already-encrypted files) shows an acceptable false-positive rate, threshold to be agreed before merge, not assumed.
- Phases 1, 2, and 4 are complete and stable before this phase begins, so the new signal's impact can be measured against a known baseline.

---

## Summary

| Phase | Adds | Type of improvement |
|---|---|---|
| 1 | Multi-family known-malicious hash coverage | Test coverage (breadth) |
| 2 | Real checksummed known-good allowlist | Test coverage (false-positive grounding) |
| 3 | Live feed drift monitoring | Infrastructure reliability |
| 4 | Citations for existing evasion corpus | Traceability / auditability |
| 5 | Entropy-based packer detection | Actual detection capability |

Phases 1 through 4 make the existing engine's behavior more thoroughly and honestly tested. Phase 5 is the only phase that changes what the engine can actually detect. That distinction is worth keeping explicit in any status reporting to stakeholders: coverage of a weak detector is still a weak detector, however well-tested.
