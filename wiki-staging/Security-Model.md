# Security Model

## Authentication

Session-based, not JWT. `POST /api/auth/login` is Spring Security's form login under the hood, with a JSON success/failure handler so the frontend gets a predictable response shape instead of a redirect. Passwords are hashed with BCrypt; there's no plaintext password storage anywhere in the flow.

CSRF protection is on everywhere except the `dev`-only H2 console chain. The frontend bootstraps a token from `GET /api/auth/csrf` before any state-changing request and sends it back in the `X-XSRF-TOKEN` header (the header name is actually returned by that endpoint, so the frontend doesn't hardcode it).

## Roles

Two roles: `USER` and `ADMIN`. New registrations always come in as `USER`; there's no self-service path to `ADMIN`. The admin account itself is seeded from `app.admin.username` / `app.admin.password` on every startup (see `UserServiceImpl.seedAdminUser`), and if that account already exists with the wrong role, it gets corrected back to `ADMIN` rather than silently left wrong.

`@PreAuthorize("hasRole('ADMIN')")` gates admin-only endpoints like the global scan history and network security controls. Ownership checks are separate from role checks: even endpoints without a role restriction (like quarantine/delete) verify the calling user actually owns the resource before acting, so a `USER` can't act on another `USER`'s scan results by guessing an ID. An `ADMIN` is exempt from that ownership check by design.

## Rate limiting

A Caffeine-backed sliding window limits `POST /api/auth/login` and `POST /api/auth/register` to 10 requests per minute per resolved key (IP, with `TRUSTED_PROXY_IPS` controlling whether a forwarded-for header is honored). This isn't Bucket4j or an external service: it's a small in-process filter registered directly in `SecurityConfig`, which is easy to miss if you're expecting a named rate-limiting dependency in `pom.xml`. Nothing else in the app is rate limited at this layer.

## CORS

Origin validation is enforced in every profile except `dev`. The app deliberately refuses to start in `prod` with a `localhost` origin configured; that check exists specifically to stop a `localhost` CORS entry from accidentally shipping to production.

## The privilege split

Covered in depth in [Architecture](Architecture). The short version: nothing that runs in the web-facing process has permission to write to the hosts file, dnsmasq config, or run `systemctl`. That's system-agent's job, running as its own OS user with a minimal sudoers grant. If you're looking for where hosts-file writes happen, they're not in `src/main/`, they're in `system-agent/src/main/`.

## Where the audit findings went

The project went through five rounds of security review (63 findings total, ranging from Critical to Low). Rather than duplicating a findings summary here that will drift out of date, check the commit history on `main` for the specifics, most fixes reference the finding they address in the commit message.
