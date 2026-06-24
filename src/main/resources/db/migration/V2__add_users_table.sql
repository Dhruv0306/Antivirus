-- V2__add_users_table.sql
-- Adds the app_users table for DB-backed authentication.
-- The scan_results.owner_username column already exists from V1 and requires
-- no modification — SecurityServiceImpl.resolveCurrentUsername() was already
-- writing to it via SecurityContextHolder.
CREATE TABLE app_users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'USER',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);