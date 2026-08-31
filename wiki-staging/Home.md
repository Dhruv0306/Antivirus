# SecureGuard Antivirus

A full-stack antivirus application: real-time file scanning, quarantine management, and network protection, with privileged OS operations isolated into their own process.

## Wiki contents

- [Architecture](Architecture): how the pieces fit together, and why privileged operations live in a separate process
- [Getting Started](Getting-Started): local setup for the backend, frontend, and system-agent
- [Scanning and Verdicts](Scanning-and-Verdicts): how a scan turns into a CLEAN / SUSPICIOUS / MALICIOUS verdict
- [Security Model](Security-Model): auth, roles, rate limiting, and the privilege split
- [Testing](Testing): unit, integration, and pressure test suites, and when each one runs
- [Deployment](Deployment): production setup, including system-agent and the database role split

For anything not covered here, the [README](https://github.com/Dhruv0306/Antivirus#readme) and `docs/plans/` in the repo (the original privilege-split design docs) are the source of truth. This wiki explains the current system; `docs/plans/` explains how it got here.
