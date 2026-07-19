# Antivirus Project

A full-stack antivirus application built with Spring Boot (Backend) and React (Frontend) that provides real-time file scanning, quarantine management, and system protection.

## 🚀 Project Overview

This project implements a comprehensive antivirus solution following the X.800 security architecture standard, with the following key features:
- Real-time file scanning and monitoring
- Quarantine management system
- System protection and security
- Scan history tracking and reporting
- User-friendly dashboard interface
- File analysis and threat detection
- Database-driven virus signature management

## 🛠️ Tech Stack

### Backend
- **Framework**: Spring Boot
- **Database**: H2 Database
- **Build Tool**: Maven
- **Java Version**: 17+
- **Key Dependencies**:
  - Spring Web
  - Spring Data JPA
  - Spring Security
  - H2 Database
  - Lombok
  - JUnit 5

### Frontend
- **Framework**: React.js
- **State Management**: React Hooks
- **UI Library**: Material-UI
- **Build Tool**: npm/yarn
- **Key Dependencies**:
  - React Router
  - Axios
  - Material-UI
  - React Query
  - Jest & React Testing Library

## 📁 Project Structure

```
antivirus/
├── src/
│   ├── main/
│   │   ├── java/com/antivirus/
│   │   │   ├── config/         # Configuration classes
│   │   │   ├── controller/     # REST controllers
│   │   │   ├── model/          # Data models
│   │   │   ├── repository/     # JPA repositories
│   │   │   ├── service/        # Business logic
│   │   │   └── util/           # Utility classes
│   │   └── resources/
│   │       ├── application.properties
│   │       └── static/         # Static resources
│   └── test/
│       └── java/com/antivirus/ # Test classes
├── frontend/
│   ├── src/
│   │   ├── components/         # React components
│   │   ├── pages/             # Page components
│   │   ├── services/          # API services
│   │   ├── utils/             # Utility functions
│   │   └── App.js             # Main App component
│   └── public/                # Static assets
├── quarantine/                # Quarantine storage
├── logs/                      # Application logs
└── flowchart/                # Project documentation
```

## 🚀 Getting Started

### Prerequisites
- JDK 17 or higher
- Node.js 14.x or higher
- Maven 3.6.x or higher
- npm 6.x or higher

### Backend Setup
1. Navigate to the project root directory
2. Run Maven build:
   ```bash
   mvn clean install
   ```
3. Start the Spring Boot application:
   ```bash
   mvn spring-boot:run
   ```
4. Backend will be available at `http://localhost:8080`
5. Backend API will be available at `http://localhost:8080`

### Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the development server:
   ```bash
   npm start
   ```
4. Frontend will be available at `http://localhost:5000`

## 🔧 Configuration

### Backend Configuration
- Database configuration: `src/main/resources/application.properties`
- Logging configuration: `src/main/resources/logback.xml`
- Security configuration: `src/main/java/com/antivirus/config/SecurityConfig.java`

### Frontend Configuration
- API endpoint configuration: `frontend/src/config.js`
- Environment variables: `frontend/.env`
- Theme configuration: `frontend/src/theme.js`

## 🗄️ Database Schema & Migrations

Schema changes are managed with [Flyway](https://flywaydb.org/); migration scripts live in `src/main/resources/db/migration/` and run automatically on application startup against whatever `DB_URL` points to, **except under the `dev` profile**, which sets `spring.flyway.enabled=false` and relies on Hibernate's `ddl-auto=update` instead (see the `F-03` comment in `application-dev.properties`) for faster local iteration. To actually see a new migration run, use the `local` or `prod` profile, e.g. `mvn spring-boot:run "-Dspring-boot.run.profiles=local"`, then inspect the result via the H2 console at `/h2-console` (JDBC URL `jdbc:h2:file:./data/antivirus_local;MODE=PostgreSQL`, configured in `application-local.properties`).

### `agent_status` table (H1)

As part of splitting privileged system-config writes (hosts file / dnsmasq) out of the web-facing process, see [`docs/plans/h1-privilege-split-plan.md`](./docs/plans/h1-privilege-split-plan.md) section 3 for the full design, migration `V5__add_agent_status.sql` adds a singleton `agent_status` table.

- **Written by**: a separate, privileged system-agent process (not covered by this README yet; its deployment is documented once that piece lands).
- **Read by**: the web app only, to answer "can hosts-file/DNS blocking actually be enforced right now" for the network security dashboard.
- The web app never writes to this table. The single row is entirely owned by the agent.

### Production deployment: provisioning the agent's database role

The system-agent authenticates to the database as its own, narrowly-scoped role (`antivirus_agent`), never as the web app's own DB user. Before deploying the agent to a new environment, an operator with database admin privileges must run the provisioning script once:

```bash
psql -h <host> -U <admin-user> -d antivirus -f docs/deployment/provision-agent-db-role.sql
```

This is a **one-time, manual step**, deliberately not a Flyway migration. The reasoning is in the script's own header comment: the app's own migration identity should never be able to grant itself, or anything else, additional database privileges, that would itself be a privilege-escalation path.

The grant is intentionally minimal: `SELECT` on `blocked_domains`, `SELECT` + `UPDATE` on `agent_status`, nothing else. If the agent's credentials are ever compromised, that grant is the entire blast radius on the database side, no access to `app_users` (password hashes) or `scan_results`.

> This step only applies to a production PostgreSQL deployment. Local/dev profiles (`application-dev.properties`, `application-local.properties`) use file-based H2 and don't need a separate agent database role.

## 📝 Development Guidelines

### Code Style
- Backend: Follow Google Java Style Guide
- Frontend: Follow Airbnb React/JSX Style Guide

### Git Workflow
1. Create feature branches from `develop`
2. Use conventional commits
3. Submit PRs for review
4. Merge to `develop` after approval

### Testing
- Backend: JUnit 5 for unit tests
- Frontend: Jest and React Testing Library
- Run tests:
  ```bash
  # Backend
  mvn test
  
  # Frontend
  npm test
  ```

## 🔍 Key Features Implementation

### File Scanning System
- Real-time file monitoring using Java NIO
- Signature-based detection using virus database
- Heuristic analysis for unknown threats
- File quarantine system with isolation
- Scan history tracking and reporting

### Dashboard Features
- Real-time system status monitoring
- Scan history visualization
- Quarantine management interface
- System health metrics
- Threat detection statistics

### Security Features
- Role-based access control
- Secure file handling
- Quarantine isolation
- API authentication
- Session management

## 📊 Logging and Monitoring

- Application logs: `logs/` directory
- Scan history: `scan_history.log`
- Database logs: `antivirus_db.trace.db`
- Performance metrics: Prometheus integration
- Health checks: Actuator endpoints

## 🔒 Security Considerations

- File system permissions
- Quarantine isolation
- API authentication
- Secure file handling
- Input validation
- XSS protection
- CSRF protection

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Authors

- [Dhruv0306](https://github.com/Dhruv0306) - Initial work
- [Sameer7188](https://github.com/Sameer7188) - Front-End work

## 🙏 Acknowledgments

- Spring Boot team
- React team
- Material-UI team
- All contributors and maintainers 
