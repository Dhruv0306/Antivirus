# Pressure and accuracy metrics

_Last generated: 2026-09-04 13:05:57 (UTC), by `.github/workflows/pressure-test.yml`._

Regenerated automatically on every scheduled or manually-dispatched run of the pressure suite (`mvn verify -Ppressure`). See `EndpointPressureIT.java` and `ScanAccuracyIT.java` under `src/test/java/com/antivirus/pressure/` for what each number below actually measures, and `scripts/generate_pressure_report.py` for how this file and `pressure-metrics.svg` are rendered from the raw JSON in `target/pressure-metrics/`.

## Load and concurrency

| Metric | Value |
|---|---|
| Concurrent unauthenticated clients | 100 |
| Requests per client | 5 |
| Total requests | 500 |
| Error rate (unauthenticated burst) | 0.00% |
| Max latency under load | 314 ms |
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
