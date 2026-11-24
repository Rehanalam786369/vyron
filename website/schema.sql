-- VYRON Control Panel Complete Database Schema
-- Character Set: utf8mb4, Engine: InnoDB

CREATE DATABASE IF NOT EXISTS vyron_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE vyron_db;

-- 1. Users Table (Parent / Supervisor Accounts)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(120) NOT NULL,
    email VARCHAR(190) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    supervisor_pin VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Devices Table (Identity Card / Paired Android Phones)
CREATE TABLE IF NOT EXISTS devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    device_name VARCHAR(120) NOT NULL,
    pairing_key VARCHAR(32) NOT NULL UNIQUE,
    device_token VARCHAR(128) NULL UNIQUE,
    device_model VARCHAR(120) DEFAULT '',
    is_paired TINYINT(1) NOT NULL DEFAULT 0,
    guided_mode TINYINT(1) NOT NULL DEFAULT 1,
    uninstall_allowed_until DATETIME NULL DEFAULT NULL,
    last_seen_at DATETIME NULL DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_device_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Installed Apps Table (Synced from Paired Phone - 100+ Apps support)
CREATE TABLE IF NOT EXISTS installed_apps (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    app_name VARCHAR(255) NOT NULL,
    is_system_app TINYINT(1) NOT NULL DEFAULT 0,
    last_usage_minutes INT NOT NULL DEFAULT 0,
    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_device_pkg (device_id, package_name),
    CONSTRAINT fk_installed_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. App Policies Table (Granular Per-App Control: Block, Schedule, Daily Quota)
CREATE TABLE IF NOT EXISTS app_policies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    app_name VARCHAR(255) NOT NULL DEFAULT '',
    policy_mode ENUM('ALLOW', 'BLOCK', 'SCHEDULE', 'DAILY_LIMIT') NOT NULL DEFAULT 'ALLOW',
    schedule_start CHAR(5) NULL DEFAULT NULL,
    schedule_end CHAR(5) NULL DEFAULT NULL,
    daily_limit_minutes INT NULL DEFAULT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_policy_device_pkg (device_id, package_name),
    CONSTRAINT fk_policy_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Network Rules Table (DNS Domain & IP Filtering per Device)
CREATE TABLE IF NOT EXISTS network_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    rule_type ENUM('domain', 'ip') NOT NULL,
    target VARCHAR(255) NOT NULL,
    action ENUM('BLOCK', 'ALLOW') NOT NULL DEFAULT 'BLOCK',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    expires_at DATETIME NULL DEFAULT NULL,
    note VARCHAR(255) DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_net_device_type_target (device_id, rule_type, target),
    CONSTRAINT fk_net_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Emergency Waivers Table (Emergency Temporary Overrides)
CREATE TABLE IF NOT EXISTS emergency_waivers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    target_type ENUM('app', 'domain', 'ip') NOT NULL DEFAULT 'app',
    target VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    reason VARCHAR(255) NOT NULL DEFAULT 'Emergency access needed',
    duration_minutes INT NOT NULL DEFAULT 10,
    status ENUM('PENDING', 'APPROVED', 'DENIED', 'EXPIRED') NOT NULL DEFAULT 'PENDING',
    requested_by ENUM('DEVICE', 'PARENT') NOT NULL DEFAULT 'DEVICE',
    approved_at DATETIME NULL DEFAULT NULL,
    expires_at DATETIME NULL DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_waiver_device_status (device_id, status, expires_at),
    CONSTRAINT fk_waiver_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. Network Logs Table (Timestamped DNS, IP, App Block & Waiver Events)
CREATE TABLE IF NOT EXISTS network_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    event_type ENUM('domain', 'ip', 'app', 'waiver', 'security') NOT NULL,
    target VARCHAR(255) NOT NULL,
    status ENUM('ALLOWED', 'BLOCKED', 'WAIVED', 'ALERT') NOT NULL,
    reason VARCHAR(255) NOT NULL,
    source ENUM('ANDROID_CLIENT', 'WEB_SIMULATOR') NOT NULL DEFAULT 'ANDROID_CLIENT',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_logs_device_time (device_id, created_at),
    CONSTRAINT fk_logs_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. Usage Snapshots Table (Daily Per-App Screen-Time Telemetry)
CREATE TABLE IF NOT EXISTS usage_snapshots (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    usage_date DATE NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    minutes_used INT NOT NULL DEFAULT 0,
    UNIQUE KEY uq_usage_day_pkg (device_id, usage_date, package_name),
    CONSTRAINT fk_usage_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
