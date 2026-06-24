-- V1__initial_schema.sql
-- Initial schema dump from dev H2 for Flyway to manage in production.
CREATE TABLE scan_results (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    file_path VARCHAR(255) NOT NULL,
    owner_username VARCHAR(255),
    threat_type VARCHAR(255) NOT NULL,
    infected BOOLEAN NOT NULL,
    threat_details VARCHAR(255),
    scan_date_time TIMESTAMP NOT NULL,
    scan_type VARCHAR(255) NOT NULL,
    action_taken VARCHAR(255)
);