# Testing

There are three layers, kept deliberately separate so a slow suite never blocks a fast one.

## Unit tests

`mvn test` (backend), `npm test` (frontend). Standard mocked-collaborator tests, one class under test at a time. These run on every push and PR to any branch, and are fast enough to not think twice about running locally before every commit.

## Integration tests

`mvn verify -Pintegration`. Test classes are named `*IntegrationIT.java` specifically so `mvn test` never picks them up. They spin up the real Spring context on a random port and talk to it over real HTTP, including real session and CSRF cookie handling, the same way the actual frontend does. No mocks. This is what actually walks: register, log in, scan a file, read your own history, get blocked from the admin-only endpoints, and confirm the seeded admin account isn't blocked from them.

Runs in CI on every push and PR to `main`, plus on demand via `workflow_dispatch`.

## Pressure tests

`mvn verify -Ppressure`. Test classes are named `*PressureIT.java`. These fire concurrent load at a real running context to check two different things:

1. **Does the app stay up and reasonably fast under concurrent load**: dozens of simultaneous clients hitting the app at once, checking the error rate and worst-case latency stay within a generous bound.
2. **Do the app's own defenses actually engage under load**: specifically, does the auth rate limiter really start returning 429s when hit with a burst, rather than that only being true in a mocked unit test that calls the limiter directly.

These are slower and heavier than the other two suites on purpose. They run once a day on a schedule (03:00 UTC) rather than on every push, plus on demand via `workflow_dispatch`.

## Why the profile split instead of just more `@SpringBootTest` classes

Maven's default `mvn test` only looks for `*Test.java`. Integration and pressure suites use `*IntegrationIT.java` / `*PressureIT.java` specifically so they're invisible to a plain `mvn test` run, and only run when someone explicitly asks for `-Pintegration` or `-Ppressure` via `maven-failsafe-plugin`. That keeps the everyday unit test loop fast, while still making the heavier suites a single documented command away, not a separate script to remember.
