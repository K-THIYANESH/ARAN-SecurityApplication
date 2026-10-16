-- ═══════════════════════════════════════════════════════════════
--  ARAN Database Schema — MySQL 8.0+
--  Run: mysql -u root -p < database/schema.sql
-- ═══════════════════════════════════════════════════════════════

CREATE DATABASE IF NOT EXISTS aran CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE aran;

-- Users
CREATE TABLE IF NOT EXISTS users (
    id         VARCHAR(36)  PRIMARY KEY,
    username   VARCHAR(64)  NOT NULL UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    role       VARCHAR(32)  NOT NULL DEFAULT 'ANALYST',
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username)
) ENGINE=InnoDB;

-- Security Events
CREATE TABLE IF NOT EXISTS security_events (
    id         VARCHAR(36)  PRIMARY KEY,
    timestamp  DATETIME     NOT NULL,
    username   VARCHAR(128) NOT NULL,
    event_type VARCHAR(64)  NOT NULL,
    ip_address VARCHAR(64),
    source     VARCHAR(64),
    details    TEXT,
    hostname   VARCHAR(128) DEFAULT 'unknown',
    severity   VARCHAR(16)  NOT NULL DEFAULT 'LOW',
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username   (username),
    INDEX idx_event_type (event_type),
    INDEX idx_timestamp  (timestamp),
    INDEX idx_severity   (severity)
) ENGINE=InnoDB;

-- Threats
CREATE TABLE IF NOT EXISTS threats (
    id          VARCHAR(36)  PRIMARY KEY,
    event_id    VARCHAR(36)  NOT NULL,
    type        VARCHAR(64)  NOT NULL,
    severity    VARCHAR(16)  NOT NULL,
    risk_score  INT          NOT NULL DEFAULT 0,
    explanation TEXT,
    detected_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_event_id   (event_id),
    INDEX idx_severity   (severity),
    INDEX idx_detected_at(detected_at),
    FOREIGN KEY (event_id) REFERENCES security_events(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Incidents
CREATE TABLE IF NOT EXISTS incidents (
    id          VARCHAR(36)  PRIMARY KEY,
    threat_id   VARCHAR(36)  NOT NULL,
    title       VARCHAR(256) NOT NULL,
    risk_score  INT          NOT NULL DEFAULT 0,
    status      ENUM('OPEN','INVESTIGATING','CONTAINED','RESOLVED') NOT NULL DEFAULT 'OPEN',
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status     (status),
    INDEX idx_created_at (created_at),
    FOREIGN KEY (threat_id) REFERENCES threats(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Audit Log
CREATE TABLE IF NOT EXISTS audit_logs (
    id         BIGINT       AUTO_INCREMENT PRIMARY KEY,
    actor      VARCHAR(128) NOT NULL,
    action     TEXT         NOT NULL,
    logged_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_actor    (actor),
    INDEX idx_logged_at(logged_at)
) ENGINE=InnoDB;

-- Insert default admin user (password: admin123)
INSERT IGNORE INTO users (id, username, password_hash, role)
VALUES (
    UUID(),
    'admin',
    '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9',
    'ADMIN'
);

-- Insert analyst user (password: analyst123)
INSERT IGNORE INTO users (id, username, password_hash, role)
VALUES (
    UUID(),
    'analyst',
    '5126dd5c3de0dc9b2d2d3f6be29ebb58e68b19b8d9cdb39af6bb1a440ee3be0a',
    'ANALYST'
);
