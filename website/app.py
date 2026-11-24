from datetime import date, datetime, timedelta, timezone
from functools import wraps
import logging
import os
from pathlib import Path
import secrets
import sys

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, session, url_for, Response
import mysql.connector
from werkzeug.security import check_password_hash, generate_password_hash

# Ensure website directory is on sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
if str(BASE_DIR.parent) not in sys.path:
    sys.path.append(str(BASE_DIR.parent))

try:
    from db import get_db_connection, init_db, format_db_error
    from dns_server import get_local_ip, VyronDnsServer
    from policy_engine import (
        evaluate_app_policy,
        evaluate_network_request,
        normalize_target,
    )
except ImportError:
    from website.db import get_db_connection, init_db, format_db_error
    from website.dns_server import get_local_ip, VyronDnsServer
    from website.policy_engine import (
        evaluate_app_policy,
        evaluate_network_request,
        normalize_target,
    )

env_path = BASE_DIR / ".env"
load_dotenv(dotenv_path=env_path)

from flask.json.provider import DefaultJSONProvider

class VyronJSONProvider(DefaultJSONProvider):
    def default(self, o):
        if isinstance(o, datetime):
            return o.strftime("%Y-%m-%dT%H:%M:%SZ")
        if isinstance(o, date):
            return o.isoformat()
        return super().default(o)

from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.json = VyronJSONProvider(app)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "vyron-dev-secret-key-change-me")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Auto-secure session cookies on Render / HTTPS
if os.getenv("RENDER") or os.getenv("RENDER_EXTERNAL_URL") or os.getenv("SESSION_COOKIE_SECURE", "false").lower() in ("true", "1", "yes"):
    app.config["SESSION_COOKIE_SECURE"] = True

logger = logging.getLogger("vyron.app")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# Safe database initialization on startup
try:
    init_db()
except Exception as e:
    logger.warning(f"Initial DB bootstrap encountered an issue: {e}")


# ============================================================================
# HELPERS & DECORATORS
# ============================================================================

def format_utc_iso(dt):
    """Converts a naive or aware datetime to an ISO-8601 UTC string ending in 'Z'."""
    if dt is None:
        return None
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(dt)


def format_epoch_ms(dt):
    """Converts a naive or aware datetime to Unix timestamp in milliseconds."""
    if dt is None:
        return None
    if isinstance(dt, datetime):
        return int(dt.replace(tzinfo=timezone.utc).timestamp() * 1000)
    return None


def purge_expired_records(cursor):
    """Auto-expires outdated temporary network rules and emergency waivers."""
    cursor.execute("DELETE FROM network_rules WHERE expires_at IS NOT NULL AND expires_at <= UTC_TIMESTAMP()")
    cursor.execute(
        """
        UPDATE emergency_waivers
        SET status = 'EXPIRED'
        WHERE status IN ('PENDING', 'APPROVED') AND expires_at IS NOT NULL AND expires_at <= UTC_TIMESTAMP()
        """
    )


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("auth_page"))
        return f(*args, **kwargs)
    return decorated_function


def get_device_by_token(token: str, cursor) -> dict | None:
    """Authenticates a device by X-VYRON-TOKEN header."""
    if not token:
        return None
    cursor.execute("SELECT * FROM devices WHERE device_token = %s", (token,))
    device = cursor.fetchone()
    if device:
        # Update last_seen_at
        cursor.execute("UPDATE devices SET last_seen_at = UTC_TIMESTAMP() WHERE id = %s", (device["id"],))
    return device


def generate_pairing_key():
    """Generates an 8-character cryptographically random pairing key: VYR-XXXX-XXXX."""
    chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    part1 = "".join(secrets.choice(chars) for _ in range(4))
    part2 = "".join(secrets.choice(chars) for _ in range(4))
    return f"VYR-{part1}-{part2}"


# ============================================================================
# PAGE ROUTES
# ============================================================================

@app.route("/")
def index():
    if "user_id" in session:
        return render_template("dashboard.html")
    return redirect(url_for("auth_page"))


@app.route("/auth")
@app.route("/login")
@app.route("/register")
def auth_page():
    if "user_id" in session:
        return redirect(url_for("index"))
    return render_template("auth.html")


# ============================================================================
# HEALTH CHECK
# ============================================================================

@app.route("/api/health", methods=["GET"])
def health_check():
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
        logger.error(f"[HEALTH CHECK DATABASE ERROR] {e}", exc_info=True)
        err_desc = format_db_error(e)
        return jsonify({
            "status": "error",
            "database": "disconnected",
            "error": err_desc,
            "detail": str(e),
        }), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# ============================================================================
# AUTHENTICATION REST APIS
# ============================================================================

@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    # Check if registration is open or disabled via environment variable
    registration_enabled = os.getenv("REGISTRATION_ENABLED", "true").lower() in ("true", "1", "yes")
    if not registration_enabled:
        return jsonify({"error": "Public registration is disabled on this server. Contact your supervisor."}), 403

    data = request.get_json(silent=True) or {}
    full_name = data.get("full_name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    supervisor_pin = str(data.get("supervisor_pin", "")).strip()

    if not full_name or not email or not password or not supervisor_pin:
        return jsonify({"error": "All fields are required"}), 400

    if not (supervisor_pin.isdigit() and 4 <= len(supervisor_pin) <= 8):
        return jsonify({"error": "Supervisor PIN must be 4 to 8 digits"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "An account with this email already exists"}), 409

        pwd_hash = generate_password_hash(password)
        pin_hash = generate_password_hash(supervisor_pin)

        cursor.execute(
            """
            INSERT INTO users (full_name, email, password_hash, supervisor_pin)
            VALUES (%s, %s, %s, %s)
            """,
            (full_name, email, pwd_hash, pin_hash),
        )
        user_id = cursor.lastrowid

        # Automatically create their first default device with pairing key
        pairing_key = generate_pairing_key()
        cursor.execute(
            """
            INSERT INTO devices (user_id, device_name, pairing_key, guided_mode)
            VALUES (%s, %s, %s, 1)
            """,
            (user_id, f"{full_name}'s Device", pairing_key),
        )
        conn.commit()

        session["user_id"] = user_id
        session["email"] = email
        session["full_name"] = full_name

        return jsonify({
            "status": "registered",
            "user": {"id": user_id, "full_name": full_name, "email": email},
        }), 201

    except Exception as e:
        logger.error(f"[AUTH REGISTER 503 ERROR] {e}", exc_info=True)
        if conn:
            conn.rollback()
        err_desc = format_db_error(e)
        return jsonify({"error": err_desc, "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            return jsonify({"error": "Invalid email or password"}), 401

        session["user_id"] = user["id"]
        session["email"] = user["email"]
        session["full_name"] = user["full_name"]

        return jsonify({
            "status": "authenticated",
            "user": {"id": user["id"], "full_name": user["full_name"], "email": user["email"]},
        }), 200

    except Exception as e:
        logger.error(f"[AUTH LOGIN 503 ERROR] {e}", exc_info=True)
        err_desc = format_db_error(e)
        return jsonify({"error": err_desc, "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify({"status": "logged_out"}), 200


@app.route("/api/auth/me", methods=["GET"])
@login_required
def auth_me():
    return jsonify({
        "id": session["user_id"],
        "email": session["email"],
        "full_name": session["full_name"],
    }), 200


@app.route("/api/dns/info", methods=["GET"])
def dns_info():
    """Provides DNS configuration details for the supervisor and Android device."""
    server_ip = get_local_ip()
    port = int(os.getenv("PORT", 5000))
    return jsonify({
        "server_ip": server_ip,
        "wifi_dns_ip": server_ip,
        "private_dns_hostname": "vyron.dns",
        "dot_port": 853,
        "udp_dns_port": 53,
        "doh_url": f"http://{server_ip}:{port}/dns-query",
        "instructions": {
            "android_wifi_dns": f"Settings -> Wi-Fi -> [Network] -> Advanced -> Static IP -> DNS 1: {server_ip}",
            "android_private_dns": "Requires registered public domain with CA-signed TLS. For local zero-icon blocking, use Wi-Fi DNS 1 above or In-App Shield.",
            "browser_secure_dns": f"Chrome Settings -> Privacy -> Use Secure DNS -> Custom: http://{server_ip}:{port}/dns-query"
        }
    }), 200


@app.route("/dns-query", methods=["GET", "POST"])
def dns_query_doh():
    """RFC 8484 DNS-over-HTTPS (DoH) endpoint."""
    raw_query = None
    if request.method == "POST":
        raw_query = request.get_data()
    elif request.method == "GET":
        dns_b64 = request.args.get("dns", "")
        if dns_b64:
            import base64
            dns_b64 += "=" * ((4 - len(dns_b64) % 4) % 4)
            try:
                raw_query = base64.urlsafe_b64decode(dns_b64)
            except Exception:
                pass

    if not raw_query or len(raw_query) < 12:
        return "Bad Request", 400

    dns_srv = VyronDnsServer()
    query = dns_srv.parse_dns_query(raw_query)
    if query:
        if dns_srv.is_blocked(query["domain"]):
            resp = dns_srv.craft_blocked_response(query, raw_query)
            dns_srv._log_block_event(query["domain"], request.remote_addr, "DoH")
            return Response(resp, mimetype="application/dns-message")
        else:
            resp = dns_srv._forward_upstream(raw_query)
            if resp:
                return Response(resp, mimetype="application/dns-message")

    return "DNS Error", 500


# ============================================================================
# DEVICE IDENTITY & SETTINGS (WEB DASHBOARD)
# ============================================================================

@app.route("/api/devices", methods=["GET"])
@login_required
def list_devices():
    user_id = session["user_id"]
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM devices WHERE user_id = %s ORDER BY id ASC", (user_id,))
        devices = cursor.fetchall()

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        results = []
        for d in devices:
            uninstall_allowed = False
            uninstall_rem_sec = 0
            if d["uninstall_allowed_until"] and d["uninstall_allowed_until"] > now_utc:
                uninstall_allowed = True
                uninstall_rem_sec = int((d["uninstall_allowed_until"] - now_utc).total_seconds())

            # App counts
            cursor.execute("SELECT COUNT(*) AS total_apps FROM installed_apps WHERE device_id = %s", (d["id"],))
            total_apps = cursor.fetchone()["total_apps"]

            # Active policies count
            cursor.execute(
                "SELECT COUNT(*) AS active_policies FROM app_policies WHERE device_id = %s AND is_active = 1",
                (d["id"],),
            )
            active_policies = cursor.fetchone()["active_policies"]

            # Active network rules count
            cursor.execute(
                "SELECT COUNT(*) AS active_rules FROM network_rules WHERE device_id = %s AND is_active = 1",
                (d["id"],),
            )
            active_rules = cursor.fetchone()["active_rules"]

            results.append({
                "id": d["id"],
                "device_name": d["device_name"],
                "pairing_key": d["pairing_key"],
                "device_model": d["device_model"] or "Pending initial sync",
                "is_paired": bool(d["is_paired"]),
                "guided_mode": bool(d["guided_mode"]),
                "uninstall_allowed": uninstall_allowed,
                "uninstall_remaining_seconds": uninstall_rem_sec,
                "last_seen_at": format_utc_iso(d["last_seen_at"]),
                "created_at": format_utc_iso(d["created_at"]),
                "total_apps": total_apps,
                "active_policies": active_policies,
                "active_rules": active_rules,
            })

        return jsonify(results), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch devices", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/devices", methods=["POST"])
@login_required
def create_device():
    user_id = session["user_id"]
    data = request.get_json(silent=True) or {}
    device_name = data.get("device_name", "").strip() or "New Android Device"

    pairing_key = generate_pairing_key()
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            INSERT INTO devices (user_id, device_name, pairing_key, guided_mode)
            VALUES (%s, %s, %s, 1)
            """,
            (user_id, device_name[:120], pairing_key),
        )
        conn.commit()
        dev_id = cursor.lastrowid

        return jsonify({
            "id": dev_id,
            "device_name": device_name,
            "pairing_key": pairing_key,
            "is_paired": False,
            "guided_mode": True,
        }), 201

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to create device", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/devices/<int:device_id>/regenerate-key", methods=["POST"])
@login_required
def regenerate_pairing_key(device_id):
    user_id = session["user_id"]
    new_key = generate_pairing_key()

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id FROM devices WHERE id = %s AND user_id = %s", (device_id, user_id))
        if not cursor.fetchone():
            return jsonify({"error": "Device not found"}), 404

        cursor.execute(
            """
            UPDATE devices
            SET pairing_key = %s, device_token = NULL, is_paired = 0
            WHERE id = %s
            """,
            (new_key, device_id),
        )
        conn.commit()

        return jsonify({"status": "key_regenerated", "pairing_key": new_key}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to regenerate key", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/devices/<int:device_id>/guided-mode", methods=["POST"])
@login_required
def toggle_device_guided_mode(device_id):
    user_id = session["user_id"]
    data = request.get_json(silent=True) or {}
    pin = str(data.get("pin", "")).strip()
    enabled = bool(data.get("enabled", False))

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT supervisor_pin FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if not user or not check_password_hash(user["supervisor_pin"], pin):
            return jsonify({"error": "Invalid Supervisor PIN"}), 403

        cursor.execute(
            "UPDATE devices SET guided_mode = %s WHERE id = %s AND user_id = %s",
            (1 if enabled else 0, device_id, user_id),
        )
        conn.commit()

        return jsonify({"status": "ok", "guided_mode": enabled}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to update guided mode", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/devices/<int:device_id>/uninstall-permission", methods=["POST"])
@login_required
def grant_uninstall_permission(device_id):
    """Unlocks device uninstall protection for 10 minutes (PIN-protected)."""
    user_id = session["user_id"]
    data = request.get_json(silent=True) or {}
    pin = str(data.get("pin", "")).strip()

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT supervisor_pin FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if not user or not check_password_hash(user["supervisor_pin"], pin):
            return jsonify({"error": "Invalid Supervisor PIN"}), 403

        # Grant 10-minute uninstall window
        cursor.execute(
            """
            UPDATE devices
            SET uninstall_allowed_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL 10 MINUTE)
            WHERE id = %s AND user_id = %s
            """,
            (device_id, user_id),
        )

        cursor.execute(
            """
            INSERT INTO network_logs (device_id, event_type, target, status, reason, source)
            VALUES (%s, 'security', 'SYSTEM_UNINSTALL', 'ALLOWED', 'Parent granted 10-minute uninstall window', 'WEB_SIMULATOR')
            """,
            (device_id,),
        )
        conn.commit()

        return jsonify({
            "status": "granted",
            "duration_minutes": 10,
            "message": "Uninstall unlocked for 10 minutes.",
        }), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to grant uninstall permission", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/devices/<int:device_id>/revoke-uninstall", methods=["POST"])
@login_required
def revoke_uninstall_permission(device_id):
    """Instantly relocks uninstall protection."""
    user_id = session["user_id"]
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            "UPDATE devices SET uninstall_allowed_until = NULL WHERE id = %s AND user_id = %s",
            (device_id, user_id),
        )
        cursor.execute(
            """
            INSERT INTO network_logs (device_id, event_type, target, status, reason, source)
            VALUES (%s, 'security', 'SYSTEM_UNINSTALL', 'BLOCKED', 'Parent revoked uninstall permission', 'WEB_SIMULATOR')
            """,
            (device_id,),
        )
        conn.commit()

        return jsonify({"status": "revoked"}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to revoke uninstall", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# ============================================================================
# INSTALLED APPS & APP POLICIES (WEB DASHBOARD)
# ============================================================================

@app.route("/api/devices/<int:device_id>/apps", methods=["GET"])
@login_required
def list_device_apps(device_id):
    user_id = session["user_id"]
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Verify device ownership
        cursor.execute("SELECT id FROM devices WHERE id = %s AND user_id = %s", (device_id, user_id))
        if not cursor.fetchone():
            return jsonify({"error": "Device not found"}), 404

        purge_expired_records(cursor)
        conn.commit()

        # Fetch apps joined with policies
        cursor.execute(
            """
            SELECT 
                a.id AS app_id,
                a.package_name,
                a.app_name,
                a.is_system_app,
                a.last_usage_minutes,
                a.synced_at,
                p.id AS policy_id,
                p.policy_mode,
                p.schedule_start,
                p.schedule_end,
                p.daily_limit_minutes,
                p.is_active
            FROM installed_apps a
            LEFT JOIN app_policies p ON a.device_id = p.device_id AND a.package_name = p.package_name
            WHERE a.device_id = %s
            ORDER BY a.last_usage_minutes DESC, a.app_name ASC
            """,
            (device_id,),
        )
        rows = cursor.fetchall()

        # Check active waivers for apps
        cursor.execute(
            """
            SELECT target, expires_at
            FROM emergency_waivers
            WHERE device_id = %s AND target_type = 'app' AND status = 'APPROVED' AND expires_at > UTC_TIMESTAMP()
            """,
            (device_id,),
        )
        active_waivers = {w["target"]: w["expires_at"] for w in cursor.fetchall()}

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        apps = []
        for r in rows:
            pkg = r["package_name"]
            has_waiver = pkg in active_waivers
            waiver_rem_sec = 0
            if has_waiver:
                waiver_rem_sec = max(0, int((active_waivers[pkg] - now_utc).total_seconds()))

            policy_mode = r["policy_mode"] or "ALLOW"
            is_active = bool(r["is_active"]) if r["policy_id"] else False

            apps.append({
                "app_id": r["app_id"],
                "package_name": pkg,
                "app_name": r["app_name"],
                "is_system_app": bool(r["is_system_app"]),
                "last_usage_minutes": r["last_usage_minutes"] or 0,
                "synced_at": format_utc_iso(r["synced_at"]),
                "has_policy": bool(r["policy_id"]),
                "policy_mode": policy_mode,
                "schedule_start": r["schedule_start"],
                "schedule_end": r["schedule_end"],
                "daily_limit_minutes": r["daily_limit_minutes"],
                "is_active": is_active,
                "has_active_waiver": has_waiver,
                "waiver_remaining_seconds": waiver_rem_sec,
            })

        return jsonify(apps), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch apps", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/devices/<int:device_id>/apps/manual", methods=["POST"])
@login_required
def add_app_manually(device_id):
    user_id = session["user_id"]
    data = request.get_json(silent=True) or {}
    raw_pkg = data.get("package_name", "").strip()
    app_name = data.get("app_name", "").strip() or raw_pkg

    try:
        norm_pkg = normalize_target("app", raw_pkg)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id FROM devices WHERE id = %s AND user_id = %s", (device_id, user_id))
        if not cursor.fetchone():
            return jsonify({"error": "Device not found"}), 404

        cursor.execute(
            """
            INSERT INTO installed_apps (device_id, package_name, app_name, is_system_app)
            VALUES (%s, %s, %s, 0)
            ON DUPLICATE KEY UPDATE app_name = VALUES(app_name)
            """,
            (device_id, norm_pkg, app_name[:255]),
        )
        conn.commit()

        return jsonify({"status": "added", "package_name": norm_pkg, "app_name": app_name}), 201

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to add app", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/devices/<int:device_id>/apps/policy", methods=["POST"])
@login_required
def save_app_policy(device_id):
    user_id = session["user_id"]
    data = request.get_json(silent=True) or {}
    raw_pkg = data.get("package_name", "").strip()
    app_name = data.get("app_name", "").strip()
    mode = data.get("policy_mode", "ALLOW").strip().upper()
    start = data.get("schedule_start")
    end = data.get("schedule_end")
    limit_mins = data.get("daily_limit_minutes")
    is_active = 1 if data.get("is_active", True) else 0

    if mode not in ("ALLOW", "BLOCK", "SCHEDULE", "DAILY_LIMIT"):
        return jsonify({"error": "Invalid policy mode"}), 400

    try:
        norm_pkg = normalize_target("app", raw_pkg)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400

    if mode == "SCHEDULE":
        if not start or not end:
            return jsonify({"error": "Start and End times are required for schedule"}), 400

    if mode == "DAILY_LIMIT":
        try:
            limit_mins = int(limit_mins)
            if limit_mins <= 0:
                raise ValueError()
        except (ValueError, TypeError):
            return jsonify({"error": "daily_limit_minutes must be a positive integer"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id FROM devices WHERE id = %s AND user_id = %s", (device_id, user_id))
        if not cursor.fetchone():
            return jsonify({"error": "Device not found"}), 404

        cursor.execute(
            """
            INSERT INTO app_policies (device_id, package_name, app_name, policy_mode, schedule_start, schedule_end, daily_limit_minutes, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                policy_mode = VALUES(policy_mode),
                schedule_start = VALUES(schedule_start),
                schedule_end = VALUES(schedule_end),
                daily_limit_minutes = VALUES(daily_limit_minutes),
                is_active = VALUES(is_active),
                app_name = VALUES(app_name)
            """,
            (device_id, norm_pkg, app_name, mode, start, end, limit_mins, is_active),
        )
        conn.commit()

        return jsonify({
            "status": "policy_saved",
            "package_name": norm_pkg,
            "policy_mode": mode,
            "is_active": bool(is_active),
        }), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to save policy", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/devices/<int:device_id>/apps/<path:pkg>/toggle", methods=["PATCH"])
@login_required
def toggle_app_policy(device_id, pkg):
    user_id = session["user_id"]
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id FROM devices WHERE id = %s AND user_id = %s", (device_id, user_id))
        if not cursor.fetchone():
            return jsonify({"error": "Device not found"}), 404

        cursor.execute(
            "SELECT id, is_active FROM app_policies WHERE device_id = %s AND package_name = %s",
            (device_id, pkg),
        )
        pol = cursor.fetchone()
        if not pol:
            return jsonify({"error": "No policy defined for this app"}), 404

        new_val = 0 if pol["is_active"] else 1
        cursor.execute(
            "UPDATE app_policies SET is_active = %s WHERE id = %s",
            (new_val, pol["id"]),
        )
        conn.commit()

        return jsonify({"status": "toggled", "is_active": bool(new_val)}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to toggle policy", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# ============================================================================
# EMERGENCY WAIVERS (WEB DASHBOARD)
# ============================================================================

@app.route("/api/devices/<int:device_id>/waivers", methods=["GET"])
@login_required
def list_device_waivers(device_id):
    user_id = session["user_id"]
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id FROM devices WHERE id = %s AND user_id = %s", (device_id, user_id))
        if not cursor.fetchone():
            return jsonify({"error": "Device not found"}), 404

        purge_expired_records(cursor)
        conn.commit()

        cursor.execute(
            """
            SELECT * FROM emergency_waivers
            WHERE device_id = %s
            ORDER BY id DESC LIMIT 50
            """,
            (device_id,),
        )
        rows = cursor.fetchall()

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        waivers = []
        for r in rows:
            remaining_seconds = 0
            if r["expires_at"] and r["expires_at"] > now_utc:
                remaining_seconds = int((r["expires_at"] - now_utc).total_seconds())

            waivers.append({
                "id": r["id"],
                "target_type": r["target_type"],
                "target": r["target"],
                "display_name": r["display_name"] or r["target"],
                "reason": r["reason"],
                "duration_minutes": r["duration_minutes"],
                "status": r["status"],
                "requested_by": r["requested_by"],
                "approved_at": format_utc_iso(r["approved_at"]),
                "expires_at": format_utc_iso(r["expires_at"]),
                "remaining_seconds": remaining_seconds,
                "created_at": format_utc_iso(r["created_at"]),
            })

        return jsonify(waivers), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch waivers", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/devices/<int:device_id>/waivers/grant", methods=["POST"])
@login_required
def parent_grant_waiver(device_id):
    """Parent proactively grants a temporary waiver for an app, domain, or IP."""
    user_id = session["user_id"]
    data = request.get_json(silent=True) or {}
    target_type = data.get("target_type", "app").strip().lower()
    raw_target = data.get("target", "").strip()
    display_name = data.get("display_name", "").strip() or raw_target
    duration_mins = int(data.get("duration_minutes", 10))

    try:
        norm_target = normalize_target(target_type, raw_target)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id FROM devices WHERE id = %s AND user_id = %s", (device_id, user_id))
        if not cursor.fetchone():
            return jsonify({"error": "Device not found"}), 404

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        expires_at = now_utc + timedelta(minutes=duration_mins)

        cursor.execute(
            """
            INSERT INTO emergency_waivers (device_id, target_type, target, display_name, reason, duration_minutes, status, requested_by, approved_at, expires_at)
            VALUES (%s, %s, %s, %s, 'Parent granted waiver', %s, 'APPROVED', 'PARENT', %s, %s)
            """,
            (device_id, target_type, norm_target, display_name, duration_mins, now_utc, expires_at),
        )
        waiver_id = cursor.lastrowid

        cursor.execute(
            """
            INSERT INTO network_logs (device_id, event_type, target, status, reason, source)
            VALUES (%s, 'waiver', %s, 'WAIVED', %s, 'WEB_SIMULATOR')
            """,
            (device_id, norm_target, f"Supervisor granted {duration_mins}m Emergency Waiver"),
        )
        conn.commit()

        return jsonify({
            "status": "granted",
            "waiver_id": waiver_id,
            "target": norm_target,
            "expires_at": format_utc_iso(expires_at),
            "remaining_seconds": duration_mins * 60,
        }), 201

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to grant waiver", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/waivers/<int:waiver_id>/action", methods=["POST"])
@login_required
def handle_waiver_action(waiver_id):
    """Parent approves or denies a pending emergency waiver request from the child's device."""
    user_id = session["user_id"]
    data = request.get_json(silent=True) or {}
    action = data.get("action", "").strip().upper()  # 'APPROVE' or 'DENY'
    override_mins = data.get("duration_minutes")

    if action not in ("APPROVE", "DENY"):
        return jsonify({"error": "Action must be APPROVE or DENY"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT w.*, d.user_id
            FROM emergency_waivers w
            JOIN devices d ON w.device_id = d.id
            WHERE w.id = %s
            """,
            (waiver_id,),
        )
        w = cursor.fetchone()
        if not w or w["user_id"] != user_id:
            return jsonify({"error": "Waiver request not found"}), 404

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

        if action == "APPROVE":
            duration = int(override_mins) if override_mins else w["duration_minutes"]
            expires_at = now_utc + timedelta(minutes=duration)
            cursor.execute(
                """
                UPDATE emergency_waivers
                SET status = 'APPROVED', duration_minutes = %s, approved_at = %s, expires_at = %s
                WHERE id = %s
                """,
                (duration, now_utc, expires_at, waiver_id),
            )
            cursor.execute(
                """
                INSERT INTO network_logs (device_id, event_type, target, status, reason, source)
                VALUES (%s, 'waiver', %s, 'WAIVED', %s, 'WEB_SIMULATOR')
                """,
                (w["device_id"], w["target"], f"Parent approved {duration}m waiver"),
            )
        else:
            cursor.execute(
                "UPDATE emergency_waivers SET status = 'DENIED' WHERE id = %s",
                (waiver_id,),
            )
            cursor.execute(
                """
                INSERT INTO network_logs (device_id, event_type, target, status, reason, source)
                VALUES (%s, 'waiver', %s, 'BLOCKED', 'Parent denied waiver request', 'WEB_SIMULATOR')
                """,
                (w["device_id"], w["target"]),
            )

        conn.commit()
        return jsonify({"status": "updated", "waiver_status": "APPROVED" if action == "APPROVE" else "DENIED"}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to update waiver", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/waivers/<int:waiver_id>/revoke", methods=["POST"])
@login_required
def revoke_active_waiver(waiver_id):
    """Parent revokes an active waiver early."""
    user_id = session["user_id"]
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT w.*, d.user_id
            FROM emergency_waivers w
            JOIN devices d ON w.device_id = d.id
            WHERE w.id = %s
            """,
            (waiver_id,),
        )
        w = cursor.fetchone()
        if not w or w["user_id"] != user_id:
            return jsonify({"error": "Waiver not found"}), 404

        cursor.execute("UPDATE emergency_waivers SET status = 'EXPIRED' WHERE id = %s", (waiver_id,))
        cursor.execute(
            """
            INSERT INTO network_logs (device_id, event_type, target, status, reason, source)
            VALUES (%s, 'waiver', %s, 'BLOCKED', 'Parent revoked active waiver early', 'WEB_SIMULATOR')
            """,
            (w["device_id"], w["target"]),
        )
        conn.commit()

        return jsonify({"status": "revoked"}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to revoke waiver", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# ============================================================================
# NETWORK RULES (DNS & IP)
# ============================================================================

@app.route("/api/devices/<int:device_id>/network-rules", methods=["GET"])
@login_required
def list_network_rules(device_id):
    user_id = session["user_id"]
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id FROM devices WHERE id = %s AND user_id = %s", (device_id, user_id))
        if not cursor.fetchone():
            return jsonify({"error": "Device not found"}), 404

        purge_expired_records(cursor)
        conn.commit()

        cursor.execute(
            "SELECT * FROM network_rules WHERE device_id = %s ORDER BY id DESC",
            (device_id,),
        )
        rows = cursor.fetchall()

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        rules = []
        for r in rows:
            rem_sec = None
            if r["expires_at"]:
                rem_sec = max(0, int((r["expires_at"] - now_utc).total_seconds()))

            rules.append({
                "id": r["id"],
                "rule_type": r["rule_type"],
                "target": r["target"],
                "action": r["action"],
                "is_active": bool(r["is_active"]),
                "expires_at": format_utc_iso(r["expires_at"]),
                "remaining_seconds": rem_sec,
                "note": r["note"] or "",
                "created_at": format_utc_iso(r["created_at"]),
            })

        return jsonify(rules), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch rules", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/devices/<int:device_id>/network-rules", methods=["POST"])
@login_required
def create_network_rule(device_id):
    user_id = session["user_id"]
    data = request.get_json(silent=True) or {}
    rule_type = data.get("rule_type", "domain").strip().lower()
    raw_target = data.get("target", "").strip()
    action = data.get("action", "BLOCK").strip().upper()
    duration_mins = data.get("duration_mins")
    note = data.get("note", "").strip()

    if action not in ("BLOCK", "ALLOW"):
        return jsonify({"error": "Action must be BLOCK or ALLOW"}), 400

    try:
        norm_target = normalize_target(rule_type, raw_target)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400

    expires_at = None
    if duration_mins is not None and str(duration_mins).strip() != "":
        try:
            mins = int(duration_mins)
            if mins > 0:
                expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=mins)
        except ValueError:
            return jsonify({"error": "duration_mins must be a positive integer"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id FROM devices WHERE id = %s AND user_id = %s", (device_id, user_id))
        if not cursor.fetchone():
            return jsonify({"error": "Device not found"}), 404

        cursor.execute(
            """
            INSERT INTO network_rules (device_id, rule_type, target, action, is_active, expires_at, note)
            VALUES (%s, %s, %s, %s, 1, %s, %s)
            ON DUPLICATE KEY UPDATE
                action = VALUES(action),
                is_active = 1,
                expires_at = VALUES(expires_at),
                note = VALUES(note)
            """,
            (device_id, rule_type, norm_target, action, expires_at, note),
        )
        conn.commit()

        cursor.execute(
            "SELECT * FROM network_rules WHERE device_id = %s AND rule_type = %s AND target = %s",
            (device_id, rule_type, norm_target),
        )
        saved = cursor.fetchone()

        return jsonify({
            "id": saved["id"],
            "rule_type": saved["rule_type"],
            "target": saved["target"],
            "action": saved["action"],
            "is_active": bool(saved["is_active"]),
            "expires_at": format_utc_iso(saved["expires_at"]),
            "note": saved["note"] or "",
            "created_at": format_utc_iso(saved["created_at"]),
        }), 201

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to create rule", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/network-rules/<int:rule_id>/toggle", methods=["PATCH"])
@login_required
def toggle_network_rule(rule_id):
    user_id = session["user_id"]
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT r.*, d.user_id
            FROM network_rules r
            JOIN devices d ON r.device_id = d.id
            WHERE r.id = %s
            """,
            (rule_id,),
        )
        rule = cursor.fetchone()
        if not rule or rule["user_id"] != user_id:
            return jsonify({"error": "Rule not found"}), 404

        new_status = 0 if rule["is_active"] else 1
        cursor.execute("UPDATE network_rules SET is_active = %s WHERE id = %s", (new_status, rule_id))
        conn.commit()

        return jsonify({"status": "toggled", "is_active": bool(new_status)}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to toggle rule", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/network-rules/<int:rule_id>", methods=["DELETE"])
@login_required
def delete_network_rule(rule_id):
    user_id = session["user_id"]
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT r.id, d.user_id
            FROM network_rules r
            JOIN devices d ON r.device_id = d.id
            WHERE r.id = %s
            """,
            (rule_id,),
        )
        rule = cursor.fetchone()
        if not rule or rule["user_id"] != user_id:
            return jsonify({"error": "Rule not found"}), 404

        cursor.execute("DELETE FROM network_rules WHERE id = %s", (rule_id,))
        conn.commit()

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
# LOGS & SIMULATOR
# ============================================================================

@app.route("/api/devices/<int:device_id>/logs", methods=["GET"])
@login_required
def list_device_logs(device_id):
    user_id = session["user_id"]
    status_filter = request.args.get("status", "").strip().upper()
    event_filter = request.args.get("event_type", "").strip().lower()
    search_q = request.args.get("q", "").strip()

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id FROM devices WHERE id = %s AND user_id = %s", (device_id, user_id))
        if not cursor.fetchone():
            return jsonify({"error": "Device not found"}), 404

        query = "SELECT * FROM network_logs WHERE device_id = %s"
        params = [device_id]

        if status_filter in ("ALLOWED", "BLOCKED", "WAIVED", "ALERT"):
            query += " AND status = %s"
            params.append(status_filter)

        if event_filter in ("domain", "ip", "app", "waiver", "security"):
            query += " AND event_type = %s"
            params.append(event_filter)

        if search_q:
            query += " AND (target LIKE %s OR reason LIKE %s)"
            params.extend([f"%{search_q}%", f"%{search_q}%"])

        query += " ORDER BY id DESC LIMIT 50"
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

        logs = []
        for r in rows:
            logs.append({
                "id": r["id"],
                "event_type": r["event_type"],
                "target": r["target"],
                "status": r["status"],
                "reason": r["reason"],
                "source": r["source"],
                "created_at": format_utc_iso(r["created_at"]),
            })

        return jsonify(logs), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch logs", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/devices/<int:device_id>/logs", methods=["DELETE"])
@login_required
def clear_device_logs(device_id):
    user_id = session["user_id"]
    data = request.get_json(silent=True) or {}
    pin_attempt = str(data.get("pin", "")).strip()

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT guided_mode FROM devices WHERE id = %s AND user_id = %s", (device_id, user_id))
        dev = cursor.fetchone()
        if not dev:
            return jsonify({"error": "Device not found"}), 404

        if dev["guided_mode"]:
            cursor.execute("SELECT supervisor_pin FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if not user or not check_password_hash(user["supervisor_pin"], pin_attempt):
                return jsonify({"error": "Supervisor PIN is required to clear telemetry logs"}), 403

        cursor.execute("DELETE FROM network_logs WHERE device_id = %s", (device_id,))
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


@app.route("/api/devices/<int:device_id>/simulate", methods=["POST"])
@login_required
def simulate_traffic(device_id):
    user_id = session["user_id"]
    data = request.get_json(silent=True) or {}
    sim_type = data.get("type", "domain").strip().lower()  # 'domain', 'ip', or 'app'
    raw_target = data.get("target", "").strip()
    sim_time = data.get("sim_time", datetime.now().strftime("%H:%M")).strip()
    sim_used_mins = int(data.get("sim_used_mins", 0))

    if not raw_target:
        return jsonify({"error": "Target is required for simulation"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id FROM devices WHERE id = %s AND user_id = %s", (device_id, user_id))
        if not cursor.fetchone():
            return jsonify({"error": "Device not found"}), 404

        purge_expired_records(cursor)
        conn.commit()

        # Fetch active waivers
        cursor.execute(
            """
            SELECT target_type, target, expires_at
            FROM emergency_waivers
            WHERE device_id = %s AND status = 'APPROVED' AND expires_at > UTC_TIMESTAMP()
            """,
            (device_id,),
        )
        waiver_rows = cursor.fetchall()
        active_waivers = [
            {
                "target_type": w["target_type"],
                "target": w["target"],
                "expires_at_epoch_ms": format_epoch_ms(w["expires_at"]),
            }
            for w in waiver_rows
        ]

        if sim_type == "app":
            norm_pkg = normalize_target("app", raw_target)
            cursor.execute(
                "SELECT * FROM app_policies WHERE device_id = %s AND package_name = %s",
                (device_id, norm_pkg),
            )
            policy = cursor.fetchone()
            verdict = evaluate_app_policy(
                norm_pkg,
                policy,
                active_waivers,
                now_local_time=sim_time,
                used_minutes_today=sim_used_mins,
            )
            event_type = "app"
            target = norm_pkg
            status = verdict["status"]
            reason = verdict["reason"]

        elif sim_type in ("domain", "ip"):
            cursor.execute(
                "SELECT * FROM network_rules WHERE device_id = %s AND is_active = 1",
                (device_id,),
            )
            rules = cursor.fetchall()
            verdict = evaluate_network_request(sim_type, raw_target, rules, active_waivers)
            event_type = sim_type
            target = verdict["target"]
            status = verdict["status"]
            reason = verdict["reason"]

        else:
            return jsonify({"error": "Simulation type must be 'domain', 'ip', or 'app'"}), 400

        # Log simulated event
        cursor.execute(
            """
            INSERT INTO network_logs (device_id, event_type, target, status, reason, source)
            VALUES (%s, %s, %s, %s, %s, 'WEB_SIMULATOR')
            """,
            (device_id, event_type, target, status, reason),
        )
        conn.commit()
        log_id = cursor.lastrowid

        return jsonify({
            "log_id": log_id,
            "type": event_type,
            "target": target,
            "status": status,
            "reason": reason,
            "sim_time": sim_time,
            "sim_used_mins": sim_used_mins,
        }), 200

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
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
# CONSOLIDATED DASHBOARD TELEMETRY ENDPOINT
# ============================================================================

@app.route("/api/devices/<int:device_id>/telemetry", methods=["GET"])
@login_required
def get_device_telemetry(device_id):
    """Single efficient endpoint for polling the dashboard UI."""
    user_id = session["user_id"]
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM devices WHERE id = %s AND user_id = %s", (device_id, user_id))
        device = cursor.fetchone()
        if not device:
            return jsonify({"error": "Device not found"}), 404

        purge_expired_records(cursor)
        conn.commit()

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

        # 1. Device Info
        uninstall_allowed = False
        uninstall_rem_sec = 0
        if device["uninstall_allowed_until"] and device["uninstall_allowed_until"] > now_utc:
            uninstall_allowed = True
            uninstall_rem_sec = int((device["uninstall_allowed_until"] - now_utc).total_seconds())

        # 2. Stats
        cursor.execute("SELECT COUNT(*) AS total FROM network_logs WHERE device_id = %s", (device_id,))
        total_logs = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) AS blocked FROM network_logs WHERE device_id = %s AND status = 'BLOCKED'", (device_id,))
        blocked_logs = cursor.fetchone()["blocked"]

        cursor.execute("SELECT COUNT(*) AS waived FROM network_logs WHERE device_id = %s AND status = 'WAIVED'", (device_id,))
        waived_logs = cursor.fetchone()["waived"]

        allowed_logs = max(0, total_logs - blocked_logs - waived_logs)

        # 3. Active Emergency Waivers Count & Pending Waivers List
        cursor.execute(
            """
            SELECT * FROM emergency_waivers
            WHERE device_id = %s AND status = 'PENDING'
            ORDER BY id DESC
            """,
            (device_id,),
        )
        pending_waivers = [
            {
                "id": w["id"],
                "target_type": w["target_type"],
                "target": w["target"],
                "display_name": w["display_name"] or w["target"],
                "reason": w["reason"],
                "duration_minutes": w["duration_minutes"],
                "created_at": format_utc_iso(w["created_at"]),
            }
            for w in cursor.fetchall()
        ]

        cursor.execute(
            """
            SELECT * FROM emergency_waivers
            WHERE device_id = %s AND status = 'APPROVED' AND expires_at > UTC_TIMESTAMP()
            ORDER BY expires_at ASC
            """,
            (device_id,),
        )
        active_waivers = []
        for w in cursor.fetchall():
            rem_sec = max(0, int((w["expires_at"] - now_utc).total_seconds()))
            active_waivers.append({
                "id": w["id"],
                "target_type": w["target_type"],
                "target": w["target"],
                "display_name": w["display_name"] or w["target"],
                "duration_minutes": w["duration_minutes"],
                "expires_at": format_utc_iso(w["expires_at"]),
                "remaining_seconds": rem_sec,
            })

        # 4. Top 6 Apps by Usage Today (for native chart)
        cursor.execute(
            """
            SELECT 
                a.package_name,
                a.app_name,
                a.last_usage_minutes,
                COALESCE(p.daily_limit_minutes, 0) AS daily_limit_minutes,
                COALESCE(p.policy_mode, 'ALLOW') AS policy_mode
            FROM installed_apps a
            LEFT JOIN app_policies p ON a.device_id = p.device_id AND a.package_name = p.package_name
            WHERE a.device_id = %s
            ORDER BY a.last_usage_minutes DESC
            LIMIT 6
            """,
            (device_id,),
        )
        top_apps = cursor.fetchall()

        # 5. Latest 30 Logs
        cursor.execute(
            "SELECT * FROM network_logs WHERE device_id = %s ORDER BY id DESC LIMIT 30",
            (device_id,),
        )
        logs = [
            {
                "id": l["id"],
                "event_type": l["event_type"],
                "target": l["target"],
                "status": l["status"],
                "reason": l["reason"],
                "source": l["source"],
                "created_at": format_utc_iso(l["created_at"]),
            }
            for l in cursor.fetchall()
        ]

        return jsonify({
            "device": {
                "id": device["id"],
                "device_name": device["device_name"],
                "pairing_key": device["pairing_key"],
                "device_model": device["device_model"],
                "is_paired": bool(device["is_paired"]),
                "guided_mode": bool(device["guided_mode"]),
                "uninstall_allowed": uninstall_allowed,
                "uninstall_remaining_seconds": uninstall_rem_sec,
                "last_seen_at": format_utc_iso(device["last_seen_at"]),
            },
            "stats": {
                "total_logs": total_logs,
                "blocked_logs": blocked_logs,
                "waived_logs": waived_logs,
                "allowed_logs": allowed_logs,
                "active_waivers_count": len(active_waivers),
                "pending_waivers_count": len(pending_waivers),
            },
            "pending_waivers": pending_waivers,
            "active_waivers": active_waivers,
            "top_apps": top_apps,
            "logs": logs,
        }), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch telemetry", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# ============================================================================
# DEVICE SYNC APIS (FLUTTER / ANDROID CLIENT CONTRACT)
# ============================================================================

@app.route("/api/device/pair", methods=["POST"])
def device_pair():
    """Initial pairing endpoint called by Flutter app using Pairing Key."""
    data = request.get_json(silent=True) or {}
    pairing_key = data.get("pairing_key", "").strip().upper()
    device_model = data.get("device_model", "").strip() or "Android Device"

    if not pairing_key:
        return jsonify({"error": "Pairing key is required"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM devices WHERE pairing_key = %s", (pairing_key,))
        device = cursor.fetchone()
        if not device:
            return jsonify({"error": "Invalid Pairing Key. Check the VYRON Control Panel."}), 404

        # Generate unique cryptographically secure device token
        device_token = "vyr_tok_" + secrets.token_hex(24)

        cursor.execute(
            """
            UPDATE devices
            SET device_token = %s, device_model = %s, is_paired = 1, last_seen_at = UTC_TIMESTAMP()
            WHERE id = %s
            """,
            (device_token, device_model[:120], device["id"]),
        )
        conn.commit()

        return jsonify({
            "status": "paired",
            "device_id": device["id"],
            "device_name": device["device_name"],
            "device_token": device_token,
            "guided_mode": bool(device["guided_mode"]),
        }), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Pairing failed", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/device/apps/sync", methods=["POST"])
def device_sync_installed_apps():
    """Batch-upserts all 100+ installed apps reported by Android PackageManager."""
    token = request.headers.get("X-VYRON-TOKEN", "").strip()
    data = request.get_json(silent=True) or {}
    apps_list = data.get("apps", [])

    if not isinstance(apps_list, list):
        return jsonify({"error": "apps must be an array"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        device = get_device_by_token(token, cursor)
        if not device:
            return jsonify({"error": "Unauthorized device"}), 401

        device_id = device["id"]

        if apps_list:
            batch_data = []
            for item in apps_list:
                pkg = str(item.get("package_name", "")).strip().lower()
                name = str(item.get("app_name", "")).strip() or pkg
                is_sys = 1 if item.get("is_system_app") else 0
                if pkg:
                    batch_data.append((device_id, pkg[:255], name[:255], is_sys))

            cursor.executemany(
                """
                INSERT INTO installed_apps (device_id, package_name, app_name, is_system_app)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE app_name = VALUES(app_name), is_system_app = VALUES(is_system_app)
                """,
                batch_data,
            )
            conn.commit()

        return jsonify({"status": "synced", "synced_count": len(apps_list)}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "App sync failed", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/device/policy", methods=["GET"])
def device_get_policy():
    """Polled by Android client to receive all active restrictions and waivers."""
    token = request.headers.get("X-VYRON-TOKEN", "").strip()

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        device = get_device_by_token(token, cursor)
        if not device:
            return jsonify({"error": "Unauthorized device"}), 401

        device_id = device["id"]
        purge_expired_records(cursor)
        conn.commit()

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

        # 1. Uninstall Allowed check
        uninstall_allowed = False
        if device["uninstall_allowed_until"] and device["uninstall_allowed_until"] > now_utc:
            uninstall_allowed = True

        # 2. App Policies
        cursor.execute(
            """
            SELECT package_name, app_name, policy_mode, schedule_start, schedule_end, daily_limit_minutes, is_active
            FROM app_policies
            WHERE device_id = %s AND is_active = 1
            """,
            (device_id,),
        )
        app_policies = cursor.fetchall()

        # 3. Network Rules
        cursor.execute(
            """
            SELECT rule_type, target, action
            FROM network_rules
            WHERE device_id = %s AND is_active = 1
            """,
            (device_id,),
        )
        rules = cursor.fetchall()
        blocked_domains = [r["target"] for r in rules if r["rule_type"] == "domain" and r["action"] == "BLOCK"]
        allowed_domains = [r["target"] for r in rules if r["rule_type"] == "domain" and r["action"] == "ALLOW"]
        blocked_ips = [r["target"] for r in rules if r["rule_type"] == "ip" and r["action"] == "BLOCK"]

        # 4. Active Emergency Waivers with epoch ms
        cursor.execute(
            """
            SELECT target_type, target, expires_at
            FROM emergency_waivers
            WHERE device_id = %s AND status = 'APPROVED' AND expires_at > UTC_TIMESTAMP()
            """,
            (device_id,),
        )
        waivers = [
            {
                "target_type": w["target_type"],
                "target": w["target"],
                "expires_at_epoch_ms": format_epoch_ms(w["expires_at"]),
            }
            for w in cursor.fetchall()
        ]

        return jsonify({
            "guided_mode": bool(device["guided_mode"]),
            "uninstall_allowed": uninstall_allowed,
            "server_time_utc": format_utc_iso(now_utc),
            "app_policies": app_policies,
            "network_rules": {
                "blocked_domains": blocked_domains,
                "allowed_domains": allowed_domains,
                "blocked_ips": blocked_ips,
            },
            "active_waivers": waivers,
        }), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch policy", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/device/waivers/request", methods=["POST"])
def device_request_waiver():
    """Triggered from Android Guided Pause screen to request an emergency waiver."""
    token = request.headers.get("X-VYRON-TOKEN", "").strip()
    data = request.get_json(silent=True) or {}
    target_type = data.get("target_type", "app").strip().lower()
    raw_target = data.get("target", "").strip()
    display_name = data.get("display_name", "").strip() or raw_target
    reason = data.get("reason", "").strip() or "Emergency access requested"
    duration = int(data.get("duration_minutes", 10))

    try:
        norm_target = normalize_target(target_type, raw_target)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        device = get_device_by_token(token, cursor)
        if not device:
            return jsonify({"error": "Unauthorized device"}), 401

        device_id = device["id"]

        cursor.execute(
            """
            INSERT INTO emergency_waivers (device_id, target_type, target, display_name, reason, duration_minutes, status, requested_by)
            VALUES (%s, %s, %s, %s, %s, %s, 'PENDING', 'DEVICE')
            """,
            (device_id, target_type, norm_target, display_name, reason, duration),
        )
        waiver_id = cursor.lastrowid

        cursor.execute(
            """
            INSERT INTO network_logs (device_id, event_type, target, status, reason, source)
            VALUES (%s, 'waiver', %s, 'ALERT', %s, 'ANDROID_CLIENT')
            """,
            (device_id, norm_target, f"Child requested {duration}m Emergency Waiver: '{reason}'"),
        )
        conn.commit()

        return jsonify({
            "status": "PENDING",
            "waiver_id": waiver_id,
            "target": norm_target,
            "duration_minutes": duration,
        }), 201

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Waiver request failed", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/device/waivers/<int:waiver_id>", methods=["GET"])
def device_check_waiver_status(waiver_id):
    """Polled by Android Guided Pause screen while waiting for parent approval."""
    token = request.headers.get("X-VYRON-TOKEN", "").strip()

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        device = get_device_by_token(token, cursor)
        if not device:
            return jsonify({"error": "Unauthorized device"}), 401

        cursor.execute(
            "SELECT * FROM emergency_waivers WHERE id = %s AND device_id = %s",
            (waiver_id, device["id"]),
        )
        w = cursor.fetchone()
        if not w:
            return jsonify({"error": "Waiver not found"}), 404

        return jsonify({
            "waiver_id": w["id"],
            "status": w["status"],
            "target": w["target"],
            "expires_at_epoch_ms": format_epoch_ms(w["expires_at"]),
        }), 200

    except Exception as e:
        return jsonify({"error": "Failed to check waiver", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/device/usage", methods=["POST"])
def device_upload_usage():
    """Uploads daily usage minutes calculated from Android UsageStatsManager."""
    token = request.headers.get("X-VYRON-TOKEN", "").strip()
    data = request.get_json(silent=True) or {}
    usage_list = data.get("usage", [])

    if not isinstance(usage_list, list):
        return jsonify({"error": "usage must be a list"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        device = get_device_by_token(token, cursor)
        if not device:
            return jsonify({"error": "Unauthorized device"}), 401

        device_id = device["id"]
        today_str = date.today().isoformat()

        if usage_list:
            app_usage_data = []
            snapshot_data = []
            for item in usage_list:
                pkg = str(item.get("package_name", "")).strip().lower()
                mins = int(item.get("minutes_used", 0))
                if pkg:
                    app_usage_data.append((mins, device_id, pkg))
                    snapshot_data.append((device_id, today_str, pkg, mins))

            # Update installed_apps
            cursor.executemany(
                "UPDATE installed_apps SET last_usage_minutes = %s WHERE device_id = %s AND package_name = %s",
                app_usage_data,
            )

            # Upsert usage_snapshots
            cursor.executemany(
                """
                INSERT INTO usage_snapshots (device_id, usage_date, package_name, minutes_used)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE minutes_used = VALUES(minutes_used)
                """,
                snapshot_data,
            )
            conn.commit()

        return jsonify({"status": "usage_recorded", "count": len(usage_list)}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to record usage", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/device/logs", methods=["POST"])
def device_upload_logs():
    """Batch-receives live packet drop and app block events from Android."""
    token = request.headers.get("X-VYRON-TOKEN", "").strip()
    data = request.get_json(silent=True) or {}
    logs_list = data.get("logs", [])

    if not isinstance(logs_list, list):
        return jsonify({"error": "logs must be a list"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        device = get_device_by_token(token, cursor)
        if not device:
            return jsonify({"error": "Unauthorized device"}), 401

        device_id = device["id"]

        if logs_list:
            batch = []
            for l in logs_list:
                event_type = str(l.get("event_type", "domain")).strip().lower()
                target = str(l.get("target", "unknown")).strip()
                status = str(l.get("status", "BLOCKED")).strip().upper()
                reason = str(l.get("reason", "Restricted by VYRON policy")).strip()
                batch.append((device_id, event_type[:50], target[:255], status[:20], reason[:255]))

            cursor.executemany(
                """
                INSERT INTO network_logs (device_id, event_type, target, status, reason, source)
                VALUES (%s, %s, %s, %s, %s, 'ANDROID_CLIENT')
                """,
                batch,
            )
            conn.commit()

        return jsonify({"status": "logged", "count": len(logs_list)}), 201

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": "Failed to upload logs", "detail": str(e)}), 503
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


if __name__ == "__main__":
    try:
        from dns_server import run_dns_server_background
        run_dns_server_background()
    except Exception as e:
        logger.warning(f"Could not start background DNS server: {e}")

    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
