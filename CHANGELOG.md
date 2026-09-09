# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [1.1.0] - 2026-09-09

Detection-engine hardening, a large expansion of automated test coverage, and a full frontend visual redesign. No breaking changes to the API or database schema (one additive migration).

### Added
- Entropy-based packer detection (Shannon entropy scoring) feeding into the weighted verdict engine (Phase 5)
- Nightly live threat-intel feed integrity check against MalwareBazaar, with a workflow-status badge and an auto-updated evasion-citation table in the README (Phase 3)
- MITRE ATT&CK technique citations for every adversarial-evasion test case (Phase 4)
- `ScanAccuracyIT`: detection-accuracy test suite backed by a 10,000-file synthetic labeled corpus (scaled up from 1,060)
- `ScanEvasionIT`: adversarial-evasion suite covering false-positive resistance, multi-family known-malware-hash coverage, and known-good open-source archive resistance (Phases 1-2)
- Automated pressure/accuracy metrics reporting: nightly CI-generated Markdown report plus one SVG chart per metrics section, published to the README
- `tests/api_test.py`: a black-box Python API test suite, a second integration-test layer independent of the Spring test context
- **Night Watch**, a full dark-theme redesign of the frontend: charcoal surfaces, a single muted-gold accent, Manrope typography, hairline-bordered cards instead of shadow-heavy ones, and a split-screen layout for the login/register screens. See the new Screenshots section in the README for every page.
- SecureGuard shield favicon and app branding (`<title>`, `manifest.json`), replacing the default Create-React-App logo/placeholder text that had shipped since the project's scaffold
- `V8` database migration: adds a dedicated file-name column to scan results
- Expanded `system-agent` local end-to-end testing walkthrough (`system-agent/deploy/README.md`), including a Troubleshooting section for the `dev`/`local` Spring profile mismatch, CSRF-token rotation on login, and OS-environment-variable precedence gotchas discovered while writing it

### Changed
- Registration flow and its test assertions cleaned up for readability
- Directory-scan job status is now published only after temporary-directory cleanup completes, closing a race window where a client could observe a "complete" status before cleanup finished
- CSRF token fetching and CORS allowed origins corrected in the pressure-test suite

### Fixed
- **Security:** filename-based detection signals are now evaluated against the uploaded display name rather than the internal temp file name — a filename-pattern-based signal could previously be missed entirely
- **Security:** patched Spring dependencies flagged by OWASP Dependency-Check
- EICAR test-signature detection (the reference constant was truncated by one character) and upload-history filenames (scan results were updated in memory but never re-persisted to the database) both corrected
- Rate-limiter exhaustion no longer leaks between pressure-test runs
- Suppressed a null-safety warning in `EntropyDetectionIT`

### Removed
- Outdated H1 rollout and staging-validation runbooks, superseded by a new real-world-testing improvement plan (`docs/plans/real-world-testing-phase-plan.md`)

[Unreleased]: https://github.com/Dhruv0306/Antivirus/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Dhruv0306/Antivirus/compare/v1.0.0...v1.1.0

## [1.0.0] - 2026-08-31

First tagged release. Everything up to this point was developed on `main` without version tags; this release marks the app as feature-complete for a first stable baseline.

### Added
- Real-time file, directory, and full-system scanning with a three-tier verdict engine (`CLEAN` / `SUSPICIOUS` / `MALICIOUS`)
- Quarantine and delete workflows for infected files
- User registration and role-based access control (`USER` / `ADMIN`)
- Network security dashboard: domain blocking and a local blocking proxy
- `system-agent`: a separate, privileged process that owns all OS-level writes (hosts file, dnsmasq config), talking to the web app only through a database `agent_status` row and a narrowly-scoped DB role
- Flyway-managed schema with migrations `V1` through `V7`
- Mobile-responsive frontend (React 18, Vite, MUI)
- CI: unit tests (backend and frontend), Semgrep, SpotBugs/Find Security Bugs, OWASP Dependency-Check, TruffleHog secret scanning, and a `system-agent` privilege model simulation
- CI: full end-to-end integration test suite, run on every push and PR to `main`
- CI: scheduled pressure/load test suite, run daily and on demand
- CI: tag-triggered release workflow

### Changed
- Migrated from Spring Boot 3 to Spring Boot 4.1.0
- Migrated privileged filesystem/OS operations (hosts file writes, DNS blocking) out of the web-facing process into `system-agent`
- Replaced in-memory admin authentication with database-backed users and BCrypt password hashing

### Security
- Fixed an IPv4-mapped IPv6 SSRF bypass
- Fixed an admin quarantine/delete ownership check regression
- Fixed unconditional privileged DNS writes from the web-facing process
- Removed a hardcoded quarantine directory path in favor of a configurable, absolute path
- Fixed username/email enumeration on the registration endpoint

[1.0.0]: https://github.com/Dhruv0306/Antivirus/releases/tag/v1.0.0
