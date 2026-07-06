# Test Coverage Plan: SecureGuard Antivirus

## Current State

**Backend**
`pom.xml` already declares `spring-boot-starter-test` and `spring-security-test` (scope test), but there is no `src/test/java` folder on disk yet. CI already runs `mvn -B package`, which executes tests automatically once they exist. No CI changes are required.

**Frontend**
`package.json` has no test runner configured. No Vitest, no Jest, no React Testing Library. Tooling has to be added before any test can run.

## Priority

Backend first. Test dependencies are already present, so setup cost is zero, and the recent scoring engine, auth, and SSRF fix work are exactly the kind of logic that benefits from regression tests. Frontend needs a tooling setup step first and is treated as a separate, later PR.

## Phase 1: Backend Tests

### Unit tests (no Spring context)
- `PathSecurityUtilTest`
  - Traversal via `../`
  - Absolute path rejection
  - Null byte rejection
  - Valid resolution within base directory
- `DomainValidatorTest`
  - Valid domains
  - Malformed input
  - Length limit (253 chars)
  - Lowercase normalization

### Service tests (Mockito, mocked repositories)
- `UserServiceImplTest`
  - `seedAdminUser`: create path, existing-correct-role path, wrong-role correction path
  - `loadUserByUsername`: found and not found
  - `register`: happy path, duplicate username, duplicate email, password mismatch, reserved admin username rejected
- `SecurityServiceImplTest`
  - Clean file produces low score
  - Known-hash match forces MALICIOUS
  - Extension masquerade scoring
  - Ransomware extension plus text pattern combining toward MALICIOUS
  - Quarantine and delete scan result behavior
- `ProxyDomainBlockingService` blocked IP prefix test
  - Regression guard for the SSRF fix (127., 10., 172.16-31., 192.168., 169.254., ::1, fd/fc ranges)

### Web layer tests (`@WebMvcTest` + MockMvc, `@WithMockUser`)
- `AuthControllerTest`
  - Register success and duplicate
  - `/me` authenticated vs anonymous
  - `/csrf`
- `AntivirusControllerTest`
  - `/history` returns 403 for USER, 200 for ADMIN
  - File scan multipart upload
- `NetworkSecurityControllerTest`
  - Block/unblock validation errors
  - Proxy start/stop

### Repository tests (`@DataJpaTest`, H2)
- `AppUserRepositoryTest`
  - `findByUsername`
  - `existsByUsername`
  - `existsByEmail`
- `ScanResultRepositoryTest`
  - History pagination and sorting

## Phase 2: Frontend Tests (separate PR, only when ready)

### Setup
- Add `vitest`, `@testing-library/react`, `@testing-library/jest-dom`, `jsdom` to devDependencies
- Add a vitest config (either in `vite.config.js` or a separate `vitest.config.js`)
- Add a `test` script to `package.json`

### Tests
- `verdict.js`: threshold to tier mapping (CLEAN / SUSPICIOUS / MALICIOUS)
- `AuthContext`: login/logout state transitions, role derivation
- `ProtectedRoute`: redirect for unauthenticated users, redirect for non-admin users on admin-only routes
- `Login` / `Register` forms: validation errors, submit payload shape
- Lower priority: `Sidebar` / `MobileAppBar` breakpoint rendering

## Branch and PR Structure

- `test/backend-unit-and-integration-coverage` (Phase 1, this PR)
- `test/frontend-test-tooling-and-coverage` (Phase 2, later PR)

## Self-Critique

Points worth flagging before you commit to this plan:
- The scoring engine constants and thresholds in `SecurityServiceImpl` are private, so scoring tests will need to go through the public `scanFile` / `detectMalware` methods with real fixture files rather than testing the constants directly. This means fixture files (clean file, EICAR-style test string, files with ransomware note text) need to be created under `src/test/resources`.
- `seedAdminUser` runs from `@PostConstruct` and reads `@Value` injected fields, so it may be easier to test by calling the method directly on a manually constructed instance with mocked dependencies rather than booting the full Spring context.
- Controller tests that hit `/scan/file` or `/scan/directory` will touch the real filesystem unless the underlying service is mocked, so these should use `@WebMvcTest` with a mocked `SecurityService` bean rather than a full `@SpringBootTest`, to keep them fast and filesystem-independent.
- This plan does not include a full end-to-end integration test (register, then login, then hit a protected endpoint). That is worth adding once the unit and controller layers are in place, as a smaller follow-up rather than bundled into this first PR.
