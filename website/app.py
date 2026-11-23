from datetime import datetime, timedelta, timezone
import logging
import os
import sys
from pathlib import Path
from flask import Flask, jsonify, render_template, request
from dotenv import load_dotenv
import mysql.connector

# Ensure both website/ directory and project root are in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
if str(BASE_DIR.parent) not in sys.path:
    sys.path.append(str(BASE_DIR.parent))

try:
    from db import get_db_connection, init_db
    from rule_engine import evaluate_request, normalize_target
except ImportError:
    from website.db import get_db_connection, init_db
    from website.rule_engine import evaluate_request, normalize_target

# Load environment
env_path = BASE_DIR / ".env"
load_dotenv(dotenv_path=env_path)

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "vyron-dev-secret-key-change-me")

logger = logging.getLogger("vyron.app")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# Safe database initialization on startup
try:
    init_db()
except Exception as e:
    logger.warning(f"Initial DB bootstrap encountered an issue: {e}")


def format_utc_iso(dt):
    """Converts a naive or aware datetime to an ISO-8601 UTC string ending in 'Z'."""
    if dt is None:
        return None
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(dt)


def purge_expired_rules(cursor):
    """Purges any temporary rules whose expiration timestamp has passed in UTC."""
    cursor.execute("DELETE FROM rules WHERE expires_at IS NOT NULL AND expires_at <= UTC_TIMESTAMP()")


def get_current_settings(cursor):
    """Helper to fetch all key-value settings as a clean dictionary."""
    cursor.execute("SELECT setting_key, setting_value FROM settings")
    rows = cursor.fetchall()
    if rows and isinstance(rows[0], dict):
        return {r["setting_key"]: r["setting_value"] for r in rows}
    return {r[0]: r[1] for r in rows}


# ============================================================================
# PAGE ROUTE
# ============================================================================

@app.route("/")
def index():
    return render_template("index.html")


# ============================================================================
# HEALTH CHECK
# ============================================================================

@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check verifying pure Python MySQL driver connectivity."""
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        return jsonify({
            "status": "ok",
            "database": "connected",
            "driver": "mysql-connector-python (use_pure=True)",
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "database": "disconnected",
            "detail": str(e),
        }), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# ============================================================================
# DASHBOARD TELEMETRY (CONSOLIDATED POLLING ENDPOINT)
# ============================================================================

@app.route("/api/dashboard", methods=["GET"])
def get_dashboard_data():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 1. Purge expired rules
        purge_expired_rules(cursor)
        conn.commit()

        # 2. Settings
        settings_map = get_current_settings(cursor)
        guided_mode = settings_map.get("guided_mode", "false").lower() == "true"
        device_name = settings_map.get("device_name", "Android Handover Device")

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

        # 3. Rules
        cursor.execute("SELECT * FROM rules ORDER BY id DESC")
        rule_rows = cursor.fetchall()
        rules = []
        rules_by_type = {"domain": 0, "ip": 0, "app": 0}
        active_rules_count = 0

        for r in rule_rows:
            is_active_bool = bool(r["is_active"])
            if is_active_bool:
                active_rules_count += 1
                rtype = r["rule_type"]
                if rtype in rules_by_type:
                    rules_by_type[rtype] += 1

            expires_at = r["expires_at"]
            remaining_seconds = None
            if expires_at:
                diff = (expires_at - now_utc).total_seconds()
                remaining_seconds = max(0, int(diff))

            rules.append({
                "id": r["id"],
                "rule_type": r["rule_type"],
                "target": r["target"],
                "action": r["action"],
                "is_active": is_active_bool,
                "note": r["note"] or "",
                "expires_at": format_utc_iso(expires_at),
                "remaining_seconds": remaining_seconds,
                "created_at": format_utc_iso(r["created_at"]),
            })

        # 4. Network Logs (Latest 50)
        cursor.execute("SELECT * FROM network_logs ORDER BY id DESC LIMIT 50")
        log_rows = cursor.fetchall()
        logs = []
        for l in log_rows:
            logs.append({
                "id": l["id"],
                "target": l["target"],
                "rule_type": l["rule_type"],
                "status": l["status"],
                "matched_rule": l["matched_rule"],
                "reason": l["reason"],
                "device_name": l["device_name"],
                "source": l["source"],
                "created_at": format_utc_iso(l["created_at"]),
            })

        # 5. Overall Log Stats
        cursor.execute("SELECT COUNT(*) AS total FROM network_logs")
        total_logs = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) AS blocked FROM network_logs WHERE status = 'BLOCKED'")
        blocked_logs = cursor.fetchone()["blocked"]

        allowed_logs = total_logs - blocked_logs
        block_rate = round((blocked_logs / total_logs * 100), 1) if total_logs > 0 else 0.0

        # Logs breakdown by rule_type
        cursor.execute("""
            SELECT rule_type, COUNT(*) AS count
            FROM network_logs
            GROUP BY rule_type
        """)
        log_type_rows = cursor.fetchall()
        logs_by_type = {"domain": 0, "ip": 0, "app": 0}
        for lt in log_type_rows:
            if lt["rule_type"] in logs_by_type:
                logs_by_type[lt["rule_type"]] = lt["count"]

        return jsonify({
            "stats": {
                "total_logs": total_logs,
                "blocked_logs": blocked_logs,
                "allowed_logs": allowed_logs,
                "block_rate_percent": block_rate,
                "active_rules_count": active_rules_count,
                "total_rules_count": len(rules),
                "rules_by_type": rules_by_type,
                "logs_by_type": logs_by_type,
            },
            "settings": {
                "guided_mode": guided_mode,
                "device_name": device_name,
            },
            "rules": rules,
            "logs": logs,
        }), 200

    except Exception as e:
        logger.error(f"Error fetching dashboard data: {e}")
        return jsonify({"error": "Failed to fetch dashboard data", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# ============================================================================
# RULES API
# ============================================================================

@app.route("/api/rules", methods=["GET"])
def list_rules():
    type_filter = request.args.get("type", "").strip().lower()
    timed_filter = request.args.get("timed", "").strip().lower()

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        purge_expired_rules(cursor)
        conn.commit()

        query = "SELECT * FROM rules WHERE 1=1"
        params = []

        if type_filter in ("domain", "ip", "app"):
            query += " AND rule_type = %s"
            params.append(type_filter)

        if timed_filter == "true":
            query += " AND expires_at IS NOT NULL"
        elif timed_filter == "false":
            query += " AND expires_at IS NULL"

        query += " ORDER BY id DESC"
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        results = []
        for r in rows:
            expires_at = r["expires_at"]
            remaining_seconds = None
            if expires_at:
                remaining_seconds = max(0, int((expires_at - now_utc).total_seconds()))

            results.append({
                "id": r["id"],
                "rule_type": r["rule_type"],
                "target": r["target"],
                "action": r["action"],
                "is_active": bool(r["is_active"]),
                "note": r["note"] or "",
                "expires_at": format_utc_iso(expires_at),
                "remaining_seconds": remaining_seconds,
                "created_at": format_utc_iso(r["created_at"]),
            })
        return jsonify(results), 200

    except Exception as e:
        return jsonify({"error": "Failed to list rules", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/rules", methods=["POST"])
def create_or_update_rule():
    data = request.get_json(silent=True) or {}
    rule_type = data.get("rule_type", "domain").strip().lower()
    raw_target = data.get("target", "").strip()
    action = data.get("action", "BLOCK").strip().upper()
    duration_mins = data.get("duration_mins")
    note = data.get("note", "").strip()

    if action not in ("BLOCK", "ALLOW"):
        return jsonify({"error": "Action must be either BLOCK or ALLOW"}), 400

    if rule_type not in ("domain", "ip", "app"):
        return jsonify({"error": "Rule type must be 'domain', 'ip', or 'app'"}), 400

    try:
        norm_target = normalize_target(rule_type, raw_target)
    except ValueError as val_err:
        return jsonify({"error": str(val_err)}), 400

    expires_at = None
    if duration_mins is not None and str(duration_mins).strip() != "":
        try:
            mins = int(duration_mins)
            if mins > 0:
                expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=mins)
        except ValueError:
            return jsonify({"error": "duration_mins must be a valid positive integer"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            INSERT INTO rules (rule_type, target, action, is_active, note, expires_at)
            VALUES (%s, %s, %s, 1, %s, %s)
            ON DUPLICATE KEY UPDATE
                action = VALUES(action),
                is_active = 1,
                note = VALUES(note),
                expires_at = VALUES(expires_at)
            """,
            (rule_type, norm_target, action, note, expires_at),
        )
        conn.commit()

        # Fetch the saved/updated record
        cursor.execute(
            "SELECT * FROM rules WHERE rule_type = %s AND target = %s",
            (rule_type, norm_target),
        )
        saved = cursor.fetchone()

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        remaining_seconds = None
        if saved["expires_at"]:
            remaining_seconds = max(0, int((saved["expires_at"] - now_utc).total_seconds()))

        response_payload = {
            "id": saved["id"],
            "rule_type": saved["rule_type"],
            "target": saved["target"],
            "action": saved["action"],
            "is_active": bool(saved["is_active"]),
            "note": saved["note"] or "",
            "expires_at": format_utc_iso(saved["expires_at"]),
            "remaining_seconds": remaining_seconds,
            "created_at": format_utc_iso(saved["created_at"]),
        }
        return jsonify(response_payload), 201

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to save rule", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/rules/<int:rule_id>/toggle", methods=["PATCH"])
def toggle_rule(rule_id):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT is_active FROM rules WHERE id = %s", (rule_id,))
        rule = cursor.fetchone()
        if not rule:
            return jsonify({"error": f"Rule with ID {rule_id} not found"}), 404

        new_status = 0 if rule["is_active"] else 1
        cursor.execute("UPDATE rules SET is_active = %s WHERE id = %s", (new_status, rule_id))
        conn.commit()

        return jsonify({
            "status": "updated",
            "id": rule_id,
            "is_active": bool(new_status),
        }), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to toggle rule", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM rules WHERE id = %s", (rule_id,))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({"error": f"Rule with ID {rule_id} not found"}), 404

        return jsonify({"status": "deleted", "id": rule_id}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to delete rule", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# ============================================================================
# LIVE NETWORK JUDGE SIMULATOR
# ============================================================================

@app.route("/api/simulate", methods=["POST"])
def simulate_traffic():
    data = request.get_json(silent=True) or {}
    rule_type = data.get("rule_type", "domain").strip().lower()
    raw_target = data.get("target", "").strip()

    if not raw_target:
        return jsonify({"error": "Target is required for simulation"}), 400

    if rule_type not in ("domain", "ip", "app"):
        return jsonify({"error": "Rule type must be 'domain', 'ip', or 'app'"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        purge_expired_rules(cursor)
        conn.commit()

        cursor.execute("SELECT * FROM rules WHERE is_active = 1")
        active_rules = cursor.fetchall()

        settings_map = get_current_settings(cursor)
        device_name = settings_map.get("device_name", "Android Handover Device")

        try:
            verdict = evaluate_request(rule_type, raw_target, active_rules)
        except ValueError as ve:
            return jsonify({"error": str(ve)}), 400

        cursor.execute(
            """
            INSERT INTO network_logs (target, rule_type, status, matched_rule, reason, device_name, source)
            VALUES (%s, %s, %s, %s, %s, %s, 'WEB_SIMULATOR')
            """,
            (
                verdict["target"],
                rule_type,
                verdict["status"],
                verdict["matched_rule"],
                verdict["reason"],
                device_name,
            ),
        )
        conn.commit()
        log_id = cursor.lastrowid

        cursor.execute("SELECT * FROM network_logs WHERE id = %s", (log_id,))
        saved_log = cursor.fetchone()

        return jsonify({
            "id": saved_log["id"],
            "target": saved_log["target"],
            "rule_type": saved_log["rule_type"],
            "status": saved_log["status"],
            "matched_rule": saved_log["matched_rule"],
            "reason": saved_log["reason"],
            "device_name": saved_log["device_name"],
            "source": saved_log["source"],
            "created_at": format_utc_iso(saved_log["created_at"]),
        }), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Simulation failed", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# ============================================================================
# NETWORK LOGS API
# ============================================================================

@app.route("/api/logs", methods=["GET"])
def list_logs():
    status_filter = request.args.get("status", "").strip().upper()
    search_q = request.args.get("q", "").strip()

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = "SELECT * FROM network_logs WHERE 1=1"
        params = []

        if status_filter in ("BLOCKED", "ALLOWED"):
            query += " AND status = %s"
            params.append(status_filter)

        if search_q:
            query += " AND (target LIKE %s OR reason LIKE %s OR device_name LIKE %s)"
            pattern = f"%{search_q}%"
            params.extend([pattern, pattern, pattern])

        query += " ORDER BY id DESC LIMIT 50"
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

        logs = []
        for l in rows:
            logs.append({
                "id": l["id"],
                "target": l["target"],
                "rule_type": l["rule_type"],
                "status": l["status"],
                "matched_rule": l["matched_rule"],
                "reason": l["reason"],
                "device_name": l["device_name"],
                "source": l["source"],
                "created_at": format_utc_iso(l["created_at"]),
            })

        return jsonify(logs), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch logs", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/logs", methods=["DELETE"])
def clear_logs():
    data = request.get_json(silent=True) or {}
    pin_attempt = str(data.get("pin", "")).strip()

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        settings_map = get_current_settings(cursor)
        guided_mode = settings_map.get("guided_mode", "false").lower() == "true"
        stored_pin = settings_map.get("supervisor_pin", "1234")

        # If guided mode is locked, verify supervisor PIN
        if guided_mode:
            if pin_attempt != stored_pin:
                return jsonify({"error": "Supervisor PIN is required to clear logs during Guided Mode"}), 403

        cursor.execute("DELETE FROM network_logs")
        conn.commit()

        return jsonify({"status": "logs_cleared"}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to clear logs", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# ============================================================================
# SETTINGS: GUIDED HANDOVER MODE, PIN & DEVICE NAME
# ============================================================================

@app.route("/api/settings/guided-mode", methods=["POST"])
def toggle_guided_mode():
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled", False))
    pin = str(data.get("pin", "")).strip()

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        settings_map = get_current_settings(cursor)
        stored_pin = settings_map.get("supervisor_pin", "1234")

        if pin != stored_pin:
            return jsonify({"error": "Invalid Supervisor PIN"}), 403

        new_val = "true" if enabled else "false"
        cursor.execute(
            """
            INSERT INTO settings (setting_key, setting_value)
            VALUES ('guided_mode', %s)
            ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
            """,
            (new_val,),
        )
        conn.commit()

        return jsonify({"guided_mode": enabled}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to update guided mode", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/settings/pin", methods=["POST"])
def update_supervisor_pin():
    data = request.get_json(silent=True) or {}
    current_pin = str(data.get("current_pin", "")).strip()
    new_pin = str(data.get("new_pin", "")).strip()

    if not (new_pin.isdigit() and 4 <= len(new_pin) <= 8):
        return jsonify({"error": "New PIN must be 4 to 8 numeric digits"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        settings_map = get_current_settings(cursor)
        stored_pin = settings_map.get("supervisor_pin", "1234")

        if current_pin != stored_pin:
            return jsonify({"error": "Current Supervisor PIN is incorrect"}), 403

        cursor.execute(
            """
            INSERT INTO settings (setting_key, setting_value)
            VALUES ('supervisor_pin', %s)
            ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
            """,
            (new_pin,),
        )
        conn.commit()

        return jsonify({"status": "pin_updated"}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to update PIN", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/settings/device", methods=["POST"])
def update_device_name():
    data = request.get_json(silent=True) or {}
    device_name = str(data.get("device_name", "")).strip()

    if not device_name:
        return jsonify({"error": "Device name cannot be empty"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO settings (setting_key, setting_value)
            VALUES ('device_name', %s)
            ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
            """,
            (device_name[:100],),
        )
        conn.commit()

        return jsonify({"device_name": device_name[:100]}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to update device name", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# ============================================================================
# ANDROID DEVICE SYNC APIS (FUTURE-READY CONTRACT)
# ============================================================================

@app.route("/api/device/rules", methods=["GET"])
def device_sync_rules():
    """Polled by Android VpnService to fetch all active network restrictions."""
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        purge_expired_rules(cursor)
        conn.commit()

        settings_map = get_current_settings(cursor)
        guided_mode = settings_map.get("guided_mode", "false").lower() == "true"

        cursor.execute("SELECT * FROM rules WHERE is_active = 1")
        active_rules = cursor.fetchall()

        blocked_domains = [r["target"] for r in active_rules if r["rule_type"] == "domain" and r["action"] == "BLOCK"]
        allowed_domains = [r["target"] for r in active_rules if r["rule_type"] == "domain" and r["action"] == "ALLOW"]
        blocked_ips = [r["target"] for r in active_rules if r["rule_type"] == "ip" and r["action"] == "BLOCK"]
        blocked_apps = [r["target"] for r in active_rules if r["rule_type"] == "app" and r["action"] == "BLOCK"]

        return jsonify({
            "guided_mode": guided_mode,
            "blocked_domains": blocked_domains,
            "allowed_domains": allowed_domains,
            "blocked_ips": blocked_ips,
            "blocked_apps": blocked_apps,
            "synced_at": format_utc_iso(datetime.now(timezone.utc)),
        }), 200

    except Exception as e:
        return jsonify({"error": "Device sync failed", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/device/logs", methods=["POST"])
def device_receive_logs():
    """Receives live network packet event from Android device VpnService."""
    data = request.get_json(silent=True) or {}
    raw_target = data.get("target", "unknown").strip()
    rule_type = data.get("rule_type", "domain").strip().lower()
    status = data.get("status", "ALLOWED").strip().upper()
    reason = data.get("reason", "Synced from Android VpnService").strip()
    device_name = data.get("device_name", "Primary Android Device").strip()

    if status not in ("ALLOWED", "BLOCKED"):
        status = "ALLOWED"

    if rule_type not in ("domain", "ip", "app"):
        rule_type = "domain"

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO network_logs (target, rule_type, status, reason, device_name, source)
            VALUES (%s, %s, %s, %s, %s, 'ANDROID_VPN')
            """,
            (raw_target[:255], rule_type, status, reason[:255], device_name[:100]),
        )
        conn.commit()

        return jsonify({"status": "logged"}), 201

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to log device event", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
