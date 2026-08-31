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

[Unreleased]: https://github.com/Dhruv0306/Antivirus/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Dhruv0306/Antivirus/releases/tag/v1.0.0
