# Getting Started

## Prerequisites

- JDK 21
- Maven 3.9+
- Node.js 18+ and npm

## Backend

```bash
mvn clean install
mvn spring-boot:run
```

Listens on `http://localhost:8080` by default, against an in-memory H2 database that resets on every restart.

You need `ADMIN_USERNAME` and `ADMIN_PASSWORD` set before the app will start cleanly; there's no built-in default admin. Set them as environment variables, or drop a `.env` file in the project root:

```
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-me-locally
```

### Running against a persistent database

The default profile is intentionally throwaway. To see real Flyway migrations run and keep data between restarts, use the `local` profile:

```bash
mvn spring-boot:run "-Dspring-boot.run.profiles=local"
```

This points at a file-backed H2 database (`./data/antivirus_local`, PostgreSQL compatibility mode, `AUTO_SERVER=TRUE`). You can inspect it live at `/h2-console` while the app is running. `AUTO_SERVER=TRUE` matters here: without it, H2's file mode locks the database to whichever process opened it first, and the console connection fails with "file is locked."

## Frontend

```bash
cd frontend
npm install
npm run dev
```

Dev server runs on `http://localhost:5000`. Copy `frontend/.env.example` to `frontend/.env.development` if you need to override anything locally; Vite does not read a plain `.env.dev` file.

## system-agent

See the [system-agent deploy README](https://github.com/Dhruv0306/Antivirus/blob/main/system-agent/deploy/README.md) in the repo. For local development it can run standalone against the same local H2 file with no systemd unit and no elevated privileges required; the sudoers-gated hosts file / dnsmasq writes only matter for a real Linux deployment.

## Running the test suites

```bash
mvn test                    # backend unit tests
cd frontend && npm test     # frontend unit tests
mvn verify -Pintegration    # full end-to-end integration suite
mvn verify -Ppressure       # load/pressure suite
```

See [Testing](Testing) for what each of these actually covers and when CI runs them.
