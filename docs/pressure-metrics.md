# Pressure and accuracy metrics

_Last generated: 2026-09-07 07:45:49 (UTC), by `.github/workflows/pressure-test.yml`._

Regenerated automatically on every scheduled or manually-dispatched run of the pressure suite (`mvn verify -Ppressure`). See the `*IT.java` classes under `src/test/java/com/antivirus/pressure/` for what each number below actually measures, and `scripts/generate_pressure_report.py` for how this file and the per-section `pressure-metrics-*.svg` images in README.md are rendered from the raw JSON in `target/pressure-metrics/`.

## Load and concurrency

| Metric | Value |
|---|---|
| Concurrent unauthenticated clients | 100 |
| Requests per client | 5 |
| Total requests | 500 |
| Error rate (unauthenticated burst) | 0.00% |
| Max latency under load | 1371 ms |
| Concurrent authenticated scans | 20 |
| Error rate (concurrent scans) | 0.00% |
| Scan history entries after burst | 20 |
| Rate-limiter burst size | 30 |
| Requests rejected (HTTP 429) | 21 |

## Detection accuracy (synthetic labeled corpus)

| Metric | Value |
|---|---|
| Total synthetic files scanned | 10000 |
| Scan requests that errored | 0 |
| True positive | 5100 |
| False positive | 0 |
| True negative | 4900 |
| False negative | 0 |
| Accuracy | 1.0000 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| F1 score | 1.0000 |
| Verdict: MALICIOUS | 2550 |
| Verdict: SUSPICIOUS | 2550 |
| Verdict: CLEAN | 4900 |
| Malicious-labeled detected as MALICIOUS | 2550 |
| Malicious-labeled detected as SUSPICIOUS | 2550 |

**Note:** the accuracy corpus is generated in memory at test time, not sourced from any real malware collection. Malicious-labeled samples are built to trip specific scoring signals in `SecurityServiceImpl` (EICAR known-hash match, ransomware extension/text pattern, trojan filename signature, rootkit text pattern); benign-labeled samples contain none of those signals. This measures whether the engine's own designed-for signals still fire correctly, not real-world malware coverage.

## Evasion resistance (adversarial synthetic corpus)

| Metric | Value |
|---|---|
| Techniques tried | 7 |
| Expected to still be caught | 2 |
| Actually caught | 2 |
| Evasion resistance rate | 1.0000 |
| Documented blind spots | 5 |

**Note:** see `ScanEvasionIT.java` under `src/test/java/com/antivirus/pressure/`. This measures how well the engine holds up against synthetic files engineered to exploit its own published detection logic (keyword fragmentation, base64-hidden payload text, benign filenames wrapping malicious-shaped content, an oversized file placing its trigger text past the 10MB pattern-scan cap), not against any real malware sample. Techniques the engine's own logic already accounts for (double-extension masquerade, ransomware-extension case variation) are asserted against; documented blind spots are reported, not asserted, since hiding a known gap by asserting around it would defeat the point of tracking it.

| Technique | Expected caught | Actual verdict | Citation |
|---|---|---|---|
| Extension masquerade: invoice.pdf with a real MZ header inside | Yes | MALICIOUS | MITRE ATT&CK T1036.008 Masquerade File Type |
| Ransomware extension case variation: .LOCKED instead of .locked | Yes | MALICIOUS | No specific MITRE ATT&CK technique; this is an implementation-robustness regression guard on the string-matching logic behind ransomware file-extension detection (itself associated with T1486 Data Encrypted for Impact), not a named attacker technique in its own right. |
| Keyword fragmentation: hyphenating 'bit-coin' to break the ransomware text pattern | Known blind spot | CLEAN | MITRE ATT&CK T1027 Obfuscated Files or Information |
| Base64-encoded ransom note: same message, never appears as plaintext | Known blind spot | CLEAN | MITRE ATT&CK T1027.013 Encrypted/Encoded File |
| Innocuous filename carrying a real trojan-shaped payload description | Known blind spot | CLEAN | MITRE ATT&CK T1036.005 Match Legitimate Name or Location |
| Oversized-file evasion: ransom note placed just past the 10MB pattern-scan cap | Known blind spot | CLEAN | MITRE ATT&CK T1027.001 Binary Padding |
| Double-extension lure: invoice.pdf.exe, a real MZ header behind Windows' hidden-extension trick | Known blind spot | CLEAN | MITRE ATT&CK T1036.008 Masquerade File Type |

**Currently open blind spots:** Keyword fragmentation: hyphenating 'bit-coin' to break the ransomware text pattern; Base64-encoded ransom note: same message, never appears as plaintext; Innocuous filename carrying a real trojan-shaped payload description; Oversized-file evasion: ransom note placed just past the 10MB pattern-scan cap; Double-extension lure: invoice.pdf.exe, a real MZ header behind Windows' hidden-extension trick. Tracked here deliberately rather than hidden by the test; each one is a candidate for a future detection improvement.

## False-positive resistance (legitimate content)

| Metric | Value |
|---|---|
| Legitimate scenarios tried | 5 |
| Flagged MALICIOUS | 0 |
| False positive rate | 0.0000 |

**Note:** legitimate sysadmin scripts, backup-tool documentation, and developer notes that happen to mention things like `Runtime.exec`, `chmod 777`, `eval(`, or plain sockets. A MALICIOUS verdict here is treated as a hard failure; that is the failure mode that erodes user trust in a real product fastest.

## Known-malware hash coverage (real published IOCs)

| Metric | Value |
|---|---|
| Malware families covered | 2 |
| Families recognized | 2 |
|   WannaCry | Recognized |
|   NotPetya | Recognized |
| End-to-end hash-match verdict | MALICIOUS |

**Note:** each family's SHA-256 is a real, published IOC hash, never an actual payload. See `ScanEvasionIT.KNOWN_MALWARE_IOCS` for per-entry source citations (MalwareBazaar, US-CERT, cross-referenced vendor research). This measures hash-lookup coverage across distinct families, not detection of any live sample.

## Known-good real-world archive resistance

| Metric | Value |
|---|---|
| Real open-source archives checked | 3 |
| Flagged MALICIOUS | 0 |

**Note:** these are real, unmodified GitHub tag source archives for well-known open-source projects (jq, ripgrep, shellcheck), not synthetic content, see `src/test/resources/known-good-samples/PROVENANCE.md` for exact provenance and independent reproduction commands. Each is scanned under both its honest filename and a deliberately adversarial one; a SUSPICIOUS verdict on the adversarial filename is expected and correct (the engine flagging a suspicious name for review), a MALICIOUS verdict on either is a hard failure, since real, legitimate open-source software must never be convicted outright by name alone.

| Archive | Honest filename verdict | Adversarial filename verdict |
|---|---|---|
| jq-1.7.1.tar.gz | CLEAN | SUSPICIOUS |
| ripgrep-14.1.0.tar.gz | CLEAN | SUSPICIOUS |
| shellcheck-0.10.0.tar.gz | CLEAN | SUSPICIOUS |

## Entropy-based packer detection (Phase 5)

| Metric | Value |
|---|---|
| Real UPX-packer validation | Skipped (upx not available on this runner) |

**Note:** `SecurityServiceImpl` scores Shannon entropy over files that already look executable (by extension or by real header bytes), the standard cheap first line of defense against packed or encrypted malware, which structurally evades every text/pattern-based signal above. See `EntropyDetectionIT.java` for both the portable synthetic validation (always runs, uses cryptographically random bytes as a correctness-guaranteed high-entropy stand-in) and the real UPX-packed-binary validation (runs when `upx` is installed, skips gracefully otherwise, and is installed explicitly in this project's own CI for that reason).
