# Antivirus Project

A full-stack antivirus application built with Spring Boot (Backend) and React (Frontend) that provides real-time file scanning, quarantine management, and system protection.

## 🚀 Project Overview

This project implements a comprehensive antivirus solution with the following key features:
- Real-time file scanning
- Quarantine management
- System protection
- Scan history tracking
- User-friendly dashboard
- File analysis and reporting

## 🛠️ Tech Stack

### Backend
- **Framework**: Spring Boot
- **Database**: H2 Database
- **Build Tool**: Maven
- **Java Version**: 17+

### Frontend
- **Framework**: React.js
- **State Management**: React Hooks
- **UI Library**: Material-UI
- **Build Tool**: npm/yarn

## 📁 Project Structure

```
antivirus/
├── src/                    # Backend source code
├── frontend/              # Frontend React application
├── quarantine/            # Quarantine storage
├── logs/                  # Application logs
├── flowchart/            # Project documentation
└── pom.xml               # Maven configuration
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

### Frontend Configuration
- API endpoint configuration: `frontend/src/config.js`
- Environment variables: `frontend/.env`

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

### File Scanning
- Real-time file monitoring
- Signature-based detection
- Heuristic analysis
- File quarantine system

### Dashboard
- Real-time system status
- Scan history
- Quarantine management
- System health metrics

## 📊 Logging and Monitoring

- Application logs: `logs/` directory
- Scan history: `scan_history.log`
- Database logs: `antivirus_db.trace.db`

## 🔒 Security Considerations

- File system permissions
- Quarantine isolation
- API authentication
- Secure file handling

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Authors

- Your Name - Initial work

## 🙏 Acknowledgments

- Spring Boot team
- React team
- Material-UI team
- All contributors and maintainers 
