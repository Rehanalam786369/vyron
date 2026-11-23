-- VYRON Control Panel Database Schema
-- Character Set: utf8mb4, Engine: InnoDB

CREATE DATABASE IF NOT EXISTS vyron_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE vyron_db;

-- 1. Rules Table: DNS, IP, and Android App restriction policies
CREATE TABLE IF NOT EXISTS rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rule_type ENUM('domain', 'ip', 'app') NOT NULL,
    target VARCHAR(255) NOT NULL,
    action ENUM('BLOCK', 'ALLOW') NOT NULL DEFAULT 'BLOCK',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    note VARCHAR(255) DEFAULT '',
    expires_at DATETIME NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_rule_type_target (rule_type, target),
    INDEX idx_rules_active_expiry (is_active, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Network Logs Table: Real-time and simulated telemetry logs
CREATE TABLE IF NOT EXISTS network_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    rule_type ENUM('domain', 'ip', 'app') NOT NULL DEFAULT 'domain',
    status ENUM('ALLOWED', 'BLOCKED') NOT NULL,
    matched_rule VARCHAR(255) NULL DEFAULT NULL,
    reason VARCHAR(255) NOT NULL,
    device_name VARCHAR(100) NOT NULL DEFAULT 'Primary Android Device',
    source ENUM('ANDROID_VPN', 'WEB_SIMULATOR') NOT NULL DEFAULT 'WEB_SIMULATOR',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_logs_created_status (created_at, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Settings Table: Key-value configuration store
CREATE TABLE IF NOT EXISTS settings (
    setting_key VARCHAR(100) PRIMARY KEY,
    setting_value VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Initial default settings
INSERT IGNORE INTO settings (setting_key, setting_value) VALUES
    ('guided_mode', 'false'),
    ('supervisor_pin', '1234'),
    ('device_name', 'Android Handover Device');
