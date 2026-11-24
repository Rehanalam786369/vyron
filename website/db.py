import logging
import os
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from dotenv import load_dotenv
import mysql.connector
from werkzeug.security import generate_password_hash

# Ensure website directory is on sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Load environment variables strictly from website/.env
env_path = BASE_DIR / ".env"
load_dotenv(dotenv_path=env_path)

logger = logging.getLogger("vyron.db")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


_db_initialized = False


def format_db_error(e):
    """Formats a MySQL exception into a clear, descriptive user message."""
    errno = getattr(e, "errno", None)
    msg = str(e)
    cfg = get_db_config()
    if errno == 1045 or "1045" in msg:
        return f"MySQL connection failed (Errno 1045): Access denied for user '{cfg['user']}' — please update DB_PASSWORD in website/.env"
    elif errno == 2003 or "2003" in msg:
        return f"MySQL server unreachable (Errno 2003) at {cfg['host']}:{cfg['port']} — please ensure MySQL service is running"
    elif errno == 1049 or "1049" in msg:
        return f"Database '{cfg['database']}' does not exist (Errno 1049) — automatic initialization will retry"
    elif errno == 2002 or "2002" in msg:
        return f"Cannot connect to local MySQL server at {cfg['host']}:{cfg['port']} — check if MySQL is running"
    return f"MySQL error (Errno {errno or 'unknown'}): {msg}"


def get_db_config():
    """Returns database configuration dictionary, hot-reloading website/.env."""
    load_dotenv(dotenv_path=env_path, override=True)
    return {
        "host": os.getenv("DB_HOST", "127.0.0.1"),
        "port": int(os.getenv("DB_PORT", "3306")),
        "user": os.getenv("DB_USER", "root"),
        "password": os.getenv("DB_PASSWORD", ""),
        "database": os.getenv("DB_NAME", "vyron_db"),
        "use_pure": True,
        "autocommit": False,
        "connection_timeout": 5,
    }


def get_server_connection():
    """Connects to MySQL server without specifying a database (to create DB if needed)."""
    cfg = get_db_config()
    return mysql.connector.connect(
        host=cfg["host"],
        port=cfg["port"],
        user=cfg["user"],
        password=cfg["password"],
        use_pure=True,
        autocommit=True,
        connection_timeout=cfg["connection_timeout"],
    )


def _connect_to_db():
    """Direct connection to the target database with use_pure=True."""
    cfg = get_db_config()
    return mysql.connector.connect(
        host=cfg["host"],
        port=cfg["port"],
        user=cfg["user"],
        password=cfg["password"],
        database=cfg["database"],
        use_pure=True,
        autocommit=False,
        connection_timeout=cfg["connection_timeout"],
    )


def get_db_connection():
    """
    Connects directly to the target database.
    Performs lazy/automatic database initialization if init_db() previously failed.
    """
    global _db_initialized
    if not _db_initialized:
        if init_db():
            _db_initialized = True
    return _connect_to_db()


def init_db():
    """
    Initializes the database, creates the 8 normalized tables, and seeds demo account & device.
    Logs a clear diagnostic warning if MySQL is unreachable.
    """
    cfg = get_db_config()
    db_name = cfg["database"]

    # Step 1: Ensure database exists
    server_conn = None
    server_cursor = None
    try:
        server_conn = get_server_connection()
        server_cursor = server_conn.cursor()
        server_cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        logger.info(f"Database '{db_name}' verified / ready.")
    except Exception as e:
        logger.warning(
            f"MySQL connection failed during database creation ({cfg['host']}:{cfg['port']} as {cfg['user']}): {e}. "
            "Please ensure MySQL is running and verify credentials in website/.env."
        )
        return False
    finally:
        if server_cursor:
            server_cursor.close()
        if server_conn:
            server_conn.close()

    # Step 2: Ensure tables and default seed data
    db_conn = None
    db_cursor = None
    try:
        db_conn = _connect_to_db()
        db_cursor = db_conn.cursor()

        # 1. users
        db_cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                full_name VARCHAR(120) NOT NULL,
                email VARCHAR(190) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                supervisor_pin VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)

        # 2. devices
        db_cursor.execute("""
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
        """)

        # 3. installed_apps
        db_cursor.execute("""
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
        """)

        # 4. app_policies
        db_cursor.execute("""
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
        """)

        # 5. network_rules
        db_cursor.execute("""
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
        """)

        # 6. emergency_waivers
        db_cursor.execute("""
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
        """)

        # 7. network_logs
        db_cursor.execute("""
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
        """)

        # 8. usage_snapshots
        db_cursor.execute("""
            CREATE TABLE IF NOT EXISTS usage_snapshots (
                id INT AUTO_INCREMENT PRIMARY KEY,
                device_id INT NOT NULL,
                usage_date DATE NOT NULL,
                package_name VARCHAR(255) NOT NULL,
                minutes_used INT NOT NULL DEFAULT 0,
                UNIQUE KEY uq_usage_day_pkg (device_id, usage_date, package_name),
                CONSTRAINT fk_usage_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)

        # Step 3: Check if users table is empty -> seed demo user & device
        db_cursor.execute("SELECT COUNT(*) FROM users")
        user_count = db_cursor.fetchone()[0]

        if user_count == 0:
            demo_pwd = generate_password_hash("vyron1234")
            demo_pin = generate_password_hash("1234")
            db_cursor.execute(
                """
                INSERT INTO users (full_name, email, password_hash, supervisor_pin)
                VALUES (%s, %s, %s, %s)
                """,
                ("VYRON Demo Supervisor", "demo@vyron.local", demo_pwd, demo_pin),
            )
            demo_user_id = db_cursor.lastrowid

            # Seed demo device
            db_cursor.execute(
                """
                INSERT INTO devices (user_id, device_name, pairing_key, device_token, device_model, is_paired, guided_mode, last_seen_at)
                VALUES (%s, %s, %s, %s, %s, 1, 1, UTC_TIMESTAMP())
                """,
                (
                    demo_user_id,
                    "Anish's Study Phone",
                    "VYR-8K2P-9X4M",
                    "dev-token-demo-8k2p-9x4m",
                    "OnePlus Nord CE5",
                ),
            )
            demo_device_id = db_cursor.lastrowid

            # Seed installed apps
            demo_apps = [
                (demo_device_id, "com.instagram.android", "Instagram", 0, 42),
                (demo_device_id, "com.google.android.youtube", "YouTube", 0, 65),
                (demo_device_id, "com.dts.freefireth", "Free Fire MAX", 0, 15),
                (demo_device_id, "com.whatsapp", "WhatsApp Messenger", 0, 30),
                (demo_device_id, "com.android.chrome", "Google Chrome", 0, 25),
                (demo_device_id, "com.google.android.calculator", "Calculator", 1, 5),
                (demo_device_id, "org.khanacademy.android", "Khan Academy", 0, 40),
                (demo_device_id, "com.spotify.music", "Spotify", 0, 20),
            ]
            db_cursor.executemany(
                """
                INSERT INTO installed_apps (device_id, package_name, app_name, is_system_app, last_usage_minutes)
                VALUES (%s, %s, %s, %s, %s)
                """,
                demo_apps,
            )

            # Seed app policies
            demo_policies = [
                (demo_device_id, "com.dts.freefireth", "Free Fire MAX", "BLOCK", None, None, None, 1),
                (demo_device_id, "com.instagram.android", "Instagram", "SCHEDULE", "16:00", "21:00", None, 1),
                (demo_device_id, "com.google.android.youtube", "YouTube", "DAILY_LIMIT", None, None, 60, 1),
                (demo_device_id, "org.khanacademy.android", "Khan Academy", "ALLOW", None, None, None, 1),
            ]
            db_cursor.executemany(
                """
                INSERT INTO app_policies (device_id, package_name, app_name, policy_mode, schedule_start, schedule_end, daily_limit_minutes, is_active)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                demo_policies,
            )

            # Seed network rules
            demo_rules = [
                (demo_device_id, "domain", "instagram.com", "BLOCK", 1, None, "Social media restriction"),
                (demo_device_id, "domain", "youtube.com", "BLOCK", 1, None, "Video streaming restriction"),
                (demo_device_id, "domain", "wikipedia.org", "ALLOW", 1, None, "Study resource allowlist"),
                (demo_device_id, "ip", "157.240.22.174", "BLOCK", 1, None, "Direct social media IP drop"),
            ]
            db_cursor.executemany(
                """
                INSERT INTO network_rules (device_id, rule_type, target, action, is_active, expires_at, note)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                demo_rules,
            )

            # Seed sample usage snapshots for today
            today_str = date.today().isoformat()
            demo_snapshots = [
                (demo_device_id, today_str, "com.instagram.android", 42),
                (demo_device_id, today_str, "com.google.android.youtube", 65),
                (demo_device_id, today_str, "com.dts.freefireth", 15),
                (demo_device_id, today_str, "com.whatsapp", 30),
                (demo_device_id, today_str, "com.android.chrome", 25),
                (demo_device_id, today_str, "org.khanacademy.android", 40),
            ]
            db_cursor.executemany(
                """
                INSERT INTO usage_snapshots (device_id, usage_date, package_name, minutes_used)
                VALUES (%s, %s, %s, %s)
                """,
                demo_snapshots,
            )

            # Seed sample logs
            demo_logs = [
                (demo_device_id, "app", "com.dts.freefireth", "BLOCKED", "Full block policy active", "ANDROID_CLIENT"),
                (demo_device_id, "app", "com.instagram.android", "BLOCKED", "Blocked by quiet hours schedule 16:00 - 21:00", "ANDROID_CLIENT"),
                (demo_device_id, "app", "com.google.android.youtube", "BLOCKED", "Daily limit of 60m reached (used 65m)", "ANDROID_CLIENT"),
                (demo_device_id, "domain", "instagram.com", "BLOCKED", "Matched domain BLOCK rule for instagram.com", "ANDROID_CLIENT"),
                (demo_device_id, "domain", "wikipedia.org", "ALLOWED", "Matched domain ALLOW rule for wikipedia.org", "ANDROID_CLIENT"),
                (demo_device_id, "ip", "157.240.22.174", "BLOCKED", "Matched IP BLOCK rule for 157.240.22.174", "ANDROID_CLIENT"),
            ]
            db_cursor.executemany(
                """
                INSERT INTO network_logs (device_id, event_type, target, status, reason, source)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                demo_logs,
            )

            logger.info("Demo user, device, policies, rules, and telemetry initialized successfully.")

        db_conn.commit()
        global _db_initialized
        _db_initialized = True
        return True
    except Exception as e:
        if db_conn:
            db_conn.rollback()
        logger.warning(f"Database initialization error: {e}", exc_info=True)
        return False
    finally:
        if db_cursor:
            db_cursor.close()
        if db_conn:
            db_conn.close()
