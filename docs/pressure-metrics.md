# Pressure and accuracy metrics

_Last generated: 2026-09-05 12:46:31 (UTC), by `.github/workflows/pressure-test.yml`._

Regenerated automatically on every scheduled or manually-dispatched run of the pressure suite (`mvn verify -Ppressure`). See `EndpointPressureIT.java` and `ScanAccuracyIT.java` under `src/test/java/com/antivirus/pressure/` for what each number below actually measures, and `scripts/generate_pressure_report.py` for how this file and `pressure-metrics.svg` are rendered from the raw JSON in `target/pressure-metrics/`.

## Load and concurrency

| Metric | Value |
|---|---|
| Concurrent unauthenticated clients | 100 |
| Requests per client | 5 |
| Total requests | 500 |
| Error rate (unauthenticated burst) | 0.00% |
| Max latency under load | 358 ms |
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

| Technique | Expected caught | Actual verdict |
|---|---|---|
| Extension masquerade: invoice.pdf with a real MZ header inside | Yes | MALICIOUS |
| Ransomware extension case variation: .LOCKED instead of .locked | Yes | MALICIOUS |
| Keyword fragmentation: hyphenating 'bit-coin' to break the ransomware text pattern | Known blind spot | CLEAN |
| Base64-encoded ransom note: same message, never appears as plaintext | Known blind spot | CLEAN |
| Innocuous filename carrying a real trojan-shaped payload description | Known blind spot | CLEAN |
| Oversized-file evasion: ransom note placed just past the 10MB pattern-scan cap | Known blind spot | CLEAN |
| Double-extension lure: invoice.pdf.exe, a real MZ header behind Windows' hidden-extension trick | Known blind spot | CLEAN |

**Currently open blind spots:** Keyword fragmentation: hyphenating 'bit-coin' to break the ransomware text pattern; Base64-encoded ransom note: same message, never appears as plaintext; Innocuous filename carrying a real trojan-shaped payload description; Oversized-file evasion: ransom note placed just past the 10MB pattern-scan cap; Double-extension lure: invoice.pdf.exe, a real MZ header behind Windows' hidden-extension trick. Tracked here deliberately rather than hidden by the test; each one is a candidate for a future detection improvement.

## False-positive resistance (legitimate content)

| Metric | Value |
|---|---|
| Legitimate scenarios tried | 5 |
| Flagged MALICIOUS | 0 |
| False positive rate | 0.0000 |

**Note:** legitimate sysadmin scripts, backup-tool documentation, and developer notes that happen to mention things like `Runtime.exec`, `chmod 777`, `eval(`, or plain sockets. A MALICIOUS verdict here is treated as a hard failure; that is the failure mode that erodes user trust in a real product fastest.
