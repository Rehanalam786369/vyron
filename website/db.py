import logging
import os
from pathlib import Path
from dotenv import load_dotenv
import mysql.connector

# Load environment variables strictly from website/.env
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)

logger = logging.getLogger("vyron.db")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


def get_db_config():
    """Returns database configuration dictionary."""
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


def get_db_connection():
    """Connects directly to the target database."""
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


def init_db():
    """
    Initializes the database, creates required tables, and seeds initial data.
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
        logger.info(f"Database '{db_name}' verified / created.")
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
        db_conn = get_db_connection()
        db_cursor = db_conn.cursor()

        # 1. Rules table
        db_cursor.execute("""
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
        """)

        # 2. Network logs table
        db_cursor.execute("""
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
        """)

        # 3. Settings table
        db_cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                setting_key VARCHAR(100) PRIMARY KEY,
                setting_value VARCHAR(255) NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)

        # Insert default settings if missing
        db_cursor.execute("""
            INSERT IGNORE INTO settings (setting_key, setting_value) VALUES
                ('guided_mode', 'false'),
                ('supervisor_pin', '1234'),
                ('device_name', 'Android Handover Device')
        """)

        # Seed starter rules if empty
        db_cursor.execute("SELECT COUNT(*) FROM rules")
        rules_count = db_cursor.fetchone()[0]
        if rules_count == 0:
            starter_rules = [
                ('domain', 'instagram.com', 'BLOCK', 1, 'Social media distraction', None),
                ('domain', 'youtube.com', 'BLOCK', 1, 'Video streaming distraction', None),
                ('domain', 'wikipedia.org', 'ALLOW', 1, 'Study resource allowlist', None),
                ('ip', '157.240.22.174', 'BLOCK', 1, 'Direct social media IP block', None),
                ('app', 'com.dts.freefireth', 'BLOCK', 1, 'Gaming app restriction', None),
                ('app', 'com.instagram.android', 'BLOCK', 1, 'Social app restriction', None),
            ]
            db_cursor.executemany(
                """
                INSERT INTO rules (rule_type, target, action, is_active, note, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                starter_rules,
            )
            logger.info("Seeded 6 initial starter rules.")

        # Seed starter logs if empty
        db_cursor.execute("SELECT COUNT(*) FROM network_logs")
        logs_count = db_cursor.fetchone()[0]
        if logs_count == 0:
            starter_logs = [
                ('instagram.com', 'domain', 'BLOCKED', 'instagram.com', 'Matched DOMAIN block rule', 'Android Handover Device', 'WEB_SIMULATOR'),
                ('wikipedia.org', 'domain', 'ALLOWED', 'wikipedia.org', 'Matched DOMAIN allow rule', 'Android Handover Device', 'WEB_SIMULATOR'),
                ('157.240.22.174', 'ip', 'BLOCKED', '157.240.22.174', 'Matched IP block rule', 'Android Handover Device', 'WEB_SIMULATOR'),
                ('1.1.1.1', 'ip', 'ALLOWED', None, 'No active block rule', 'Android Handover Device', 'ANDROID_VPN'),
                ('com.dts.freefireth', 'app', 'BLOCKED', 'com.dts.freefireth', 'Matched APP block rule', 'Android Handover Device', 'ANDROID_VPN'),
                ('com.android.calculator2', 'app', 'ALLOWED', None, 'No active block rule', 'Android Handover Device', 'ANDROID_VPN'),
            ]
            db_cursor.executemany(
                """
                INSERT INTO network_logs (target, rule_type, status, matched_rule, reason, device_name, source)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                starter_logs,
            )
            logger.info("Seeded 6 initial network logs.")

        db_conn.commit()
        logger.info("Database schema and seed data initialized successfully.")
        return True
    except Exception as e:
        if db_conn:
            db_conn.rollback()
        logger.warning(
            f"Failed to initialize database tables or seed data: {e}. "
            "Please verify database permissions and schema configuration."
        )
        return False
    finally:
        if db_cursor:
            db_cursor.close()
        if db_conn:
            db_conn.close()
