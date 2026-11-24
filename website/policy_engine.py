import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

DOMAIN_LABEL_REGEX = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
APP_PACKAGE_REGEX = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")
TIME_HHMM_REGEX = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


def normalize_target(rule_type: str, raw_target: str) -> str:
    """
    Normalizes and validates target strings based on rule type.
    Raises ValueError with descriptive messages on invalid formats.
    """
    if not raw_target or not isinstance(raw_target, str):
        raise ValueError("Target cannot be empty.")

    target = raw_target.strip().lower()
    if not target:
        raise ValueError("Target cannot be empty.")

    rule_type = rule_type.strip().lower()

    if rule_type == "domain":
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            target = parsed.netloc or parsed.path
        else:
            for sep in ("/", "?", "#"):
                if sep in target:
                    target = target.split(sep, 1)[0]

        if ":" in target:
            target = target.split(":", 1)[0]

        target = target.strip(". ")

        if target.startswith("www.") and len(target) > 4 and "." in target[4:]:
            target = target[4:]

        if not target or len(target) > 253:
            raise ValueError("Domain must be between 1 and 253 characters.")

        labels = target.split(".")
        if len(labels) < 2 and target != "localhost":
            raise ValueError(f"Invalid domain '{target}'. Must contain at least two labels (e.g. example.com).")

        for label in labels:
            if not label or not DOMAIN_LABEL_REGEX.match(label):
                raise ValueError(f"Invalid domain label '{label}' in '{target}'.")

        return target

    elif rule_type == "ip":
        try:
            ip_obj = ipaddress.ip_address(target)
            return str(ip_obj)
        except ValueError:
            raise ValueError(f"Invalid IP address '{target}'. Must be a valid IPv4 or IPv6 address.")

    elif rule_type == "app":
        if not APP_PACKAGE_REGEX.match(target):
            raise ValueError(
                f"Invalid Android package name '{target}'. Must follow reverse-DNS notation (e.g. com.example.app)."
            )
        return target

    else:
        raise ValueError(f"Unsupported rule type '{rule_type}'. Must be 'domain', 'ip', or 'app'.")


def is_time_in_window(time_str: str, start_str: str, end_str: str) -> bool:
    """
    Evaluates whether time_str (HH:MM 24h format) falls inside [start_str, end_str).
    Handles normal schedules (e.g. 16:00 to 21:00) and overnight schedules (e.g. 22:00 to 07:00).
    """
    if not (TIME_HHMM_REGEX.match(time_str) and TIME_HHMM_REGEX.match(start_str) and TIME_HHMM_REGEX.match(end_str)):
        return False

    t = int(time_str.replace(":", ""))
    start = int(start_str.replace(":", ""))
    end = int(end_str.replace(":", ""))

    if start == end:
        # 24-hour block
        return True
    elif start < end:
        # Standard daytime window
        return start <= t < end
    else:
        # Overnight window (e.g. 2200 to 0700)
        return t >= start or t < end


def evaluate_app_policy(
    package_name: str,
    policy: dict | None,
    active_waivers: list,
    now_local_time: str,  # HH:MM format
    used_minutes_today: int = 0,
    now_utc_epoch_ms: int | None = None,
) -> dict:
    """
    Evaluates an app launch request against emergency waivers and policy.
    Returns: {"status": "ALLOWED"|"BLOCKED"|"WAIVED", "reason": str, "matched_policy": str|None}
    """
    norm_pkg = normalize_target("app", package_name)

    if now_utc_epoch_ms is None:
        now_utc_epoch_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

    # Step 1: Check active waivers (Overrides all restrictions!)
    for w in active_waivers:
        if w.get("target_type") == "app" and w.get("target") == norm_pkg:
            exp_ms = w.get("expires_at_epoch_ms")
            if exp_ms and exp_ms > now_utc_epoch_ms:
                rem_mins = max(1, int((exp_ms - now_utc_epoch_ms) / 60000))
                return {
                    "status": "WAIVED",
                    "reason": f"Active Emergency Waiver granted ({rem_mins}m remaining)",
                    "matched_policy": "EMERGENCY_WAIVER",
                }

    if not policy or not policy.get("is_active"):
        return {
            "status": "ALLOWED",
            "reason": "No active policy restriction",
            "matched_policy": None,
        }

    mode = policy.get("policy_mode", "ALLOW")

    if mode == "BLOCK":
        return {
            "status": "BLOCKED",
            "reason": "Restricted by supervisor policy (Full Block)",
            "matched_policy": "BLOCK",
        }

    elif mode == "SCHEDULE":
        start = policy.get("schedule_start")
        end = policy.get("schedule_end")
        if start and end and is_time_in_window(now_local_time, start, end):
            return {
                "status": "BLOCKED",
                "reason": f"Restricted by quiet hours schedule ({start} – {end})",
                "matched_policy": f"SCHEDULE_{start}_{end}",
            }
        return {
            "status": "ALLOWED",
            "reason": f"Outside restricted schedule window ({start} – {end})",
            "matched_policy": None,
        }

    elif mode == "DAILY_LIMIT":
        limit = policy.get("daily_limit_minutes") or 0
        if limit > 0 and used_minutes_today >= limit:
            return {
                "status": "BLOCKED",
                "reason": f"Daily usage quota reached ({used_minutes_today}m / {limit}m)",
                "matched_policy": f"DAILY_LIMIT_{limit}",
            }
        return {
            "status": "ALLOWED",
            "reason": f"Within daily limit ({used_minutes_today}m / {limit}m)",
            "matched_policy": None,
        }

    return {
        "status": "ALLOWED",
        "reason": "App policy set to ALLOW",
        "matched_policy": None,
    }


def evaluate_network_request(
    rule_type: str,
    raw_target: str,
    active_rules: list,
    active_waivers: list,
    now_utc_epoch_ms: int | None = None,
) -> dict:
    """
    Evaluates a DNS or IP network request against emergency waivers and network rules.
    Returns: {"target": str, "status": "ALLOWED"|"BLOCKED"|"WAIVED", "matched_rule": str|None, "reason": str}
    """
    rule_type = rule_type.strip().lower()
    norm_target = normalize_target(rule_type, raw_target)

    if now_utc_epoch_ms is None:
        now_utc_epoch_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

    # Step 1: Check emergency waivers
    for w in active_waivers:
        if w.get("target_type") == rule_type:
            w_target = w.get("target")
            is_match = False
            if rule_type == "domain":
                if norm_target == w_target or norm_target.endswith("." + w_target):
                    is_match = True
            elif rule_type == "ip":
                if norm_target == w_target:
                    is_match = True

            if is_match:
                exp_ms = w.get("expires_at_epoch_ms")
                if exp_ms and exp_ms > now_utc_epoch_ms:
                    rem_mins = max(1, int((exp_ms - now_utc_epoch_ms) / 60000))
                    return {
                        "target": norm_target,
                        "status": "WAIVED",
                        "matched_rule": w_target,
                        "reason": f"Active Emergency Waiver granted ({rem_mins}m remaining)",
                    }

    # Step 2: Match active rules
    matching_candidates = []
    for r in active_rules:
        r_type = (r.get("rule_type") or "").strip().lower()
        if r_type != rule_type:
            continue

        if not r.get("is_active", 1):
            continue

        r_target = (r.get("target") or "").strip().lower()
        if not r_target:
            continue

        action = (r.get("action") or "BLOCK").strip().upper()
        note = r.get("note", "")

        is_match = False
        if rule_type == "domain":
            if norm_target == r_target or norm_target.endswith("." + r_target):
                is_match = True
        elif rule_type == "ip":
            if norm_target == r_target:
                is_match = True

        if is_match:
            matching_candidates.append({
                "rule_type": r_type,
                "target": r_target,
                "action": action,
                "note": note,
            })

    if not matching_candidates:
        return {
            "target": norm_target,
            "status": "ALLOWED",
            "matched_rule": None,
            "reason": f"No active {rule_type.upper()} rule matched '{norm_target}'",
        }

    # Deterministic Precedence:
    # 1. Longest (most specific) target first
    # 2. In tie, ALLOW overrides BLOCK
    matching_candidates.sort(
        key=lambda item: (-len(item["target"]), 0 if item["action"] == "ALLOW" else 1)
    )

    best_match = matching_candidates[0]
    action = best_match["action"]
    status = "BLOCKED" if action == "BLOCK" else "ALLOWED"
    matched_rule = best_match["target"]
    note_suffix = f" ({best_match['note']})" if best_match["note"] else ""
    reason = f"Matched {best_match['rule_type'].upper()} {action} rule for '{matched_rule}'{note_suffix}"

    return {
        "target": norm_target,
        "status": status,
        "matched_rule": matched_rule,
        "reason": reason,
    }
