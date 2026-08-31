# Scanning and Verdicts

## The three verdict tiers

Every scan produces one of three verdicts, stored on `ScanResult.verdict`:

| Verdict | Meaning |
|---|---|
| `CLEAN` | No signals triggered |
| `SUSPICIOUS` | Some signals triggered, below the malicious threshold |
| `MALICIOUS` | Signals triggered above the threshold; treated as infected |

This replaced an earlier binary infected/clean model. The weighted scoring approach exists because a lot of real detection signals are individually weak evidence: one alone shouldn't flag a file as malicious, but several together should. A single verdict field couldn't represent "some signals fired, but not enough," so files either got flagged on a hair trigger or missed entirely depending on how strict the one check was.

## How a score becomes a verdict

Each `ScanResult` carries:

- `riskScore`: a 0 to 100 aggregate confidence score
- `detectionSignals`: a comma-separated list of which signals actually fired
- `threatType`: populated when the verdict lands on a specific category (`VIRUS`, `MALWARE`, `TROJAN`, `RANSOMWARE`, `KEYLOGGER`)

The scoring and thresholding logic lives in the service layer under `com.antivirus.service`, alongside the file, directory, and system scan implementations. If you're changing threshold values or adding a new signal, that's where to look, not in the controller.

## Scan types

- **File scan**: `POST /api/antivirus/scan/file`, one multipart upload
- **Directory scan**: bounded by `app.scan.max-files-per-directory-upload` (default 500) to avoid a single request trying to process an unbounded number of files
- **System scan**: the heaviest of the three; results come back chunked, sized by `SYSTEM_SCAN_RESULT_CHUNK_SIZE`, so the frontend isn't waiting on one enormous response

## Quarantine and delete

Files flagged `MALICIOUS` (and some `SUSPICIOUS` cases depending on the action taken) are moved to `app.quarantine.dir` rather than deleted outright, so a false positive doesn't mean permanent data loss. Quarantine and delete actions both check that the calling user owns the scan result before acting on it, independent of the `USER` / `ADMIN` role check. An `ADMIN` can act on anyone's scan results; a `USER` can only act on their own, even though the endpoint itself doesn't have a role restriction.
