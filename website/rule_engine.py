import ipaddress
import re
from urllib.parse import urlparse


DOMAIN_LABEL_REGEX = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
APP_PACKAGE_REGEX = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")


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
        # Handle full URLs: strip scheme if present
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            target = parsed.netloc or parsed.path
        else:
            # Strip path, query params, fragments if present
            for sep in ("/", "?", "#"):
                if sep in target:
                    target = target.split(sep, 1)[0]

        # Strip port if present (e.g. domain.com:443)
        if ":" in target:
            target = target.split(":", 1)[0]

        target = target.strip(". ")

        # Strip leading www. if followed by a valid multi-level domain
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
        # Validate IPv4 or IPv6
        try:
            ip_obj = ipaddress.ip_address(target)
            return str(ip_obj)
        except ValueError:
            raise ValueError(f"Invalid IP address '{target}'. Must be a valid IPv4 or IPv6 address.")

    elif rule_type == "app":
        # Android package format: e.g. com.example.app or com.dts.freefireth
        if not APP_PACKAGE_REGEX.match(target):
            raise ValueError(
                f"Invalid Android package name '{target}'. Must follow reverse-DNS notation (e.g. com.example.app)."
            )
        return target

    else:
        raise ValueError(f"Unsupported rule type '{rule_type}'. Must be 'domain', 'ip', or 'app'.")


def evaluate_request(rule_type: str, raw_target: str, active_rules: list) -> dict:
    """
    Evaluates a connection request against active rules with deterministic precedence.
    - Longest / most specific target wins.
    - Equal specificity: ALLOW overrides BLOCK.
    - Unmatched: defaults to ALLOWED.
    """
    rule_type = rule_type.strip().lower()
    norm_target = normalize_target(rule_type, raw_target)

    # Filter rules for the relevant type and active status
    matching_candidates = []
    for r in active_rules:
        # Check rule_type match
        r_type = (r.get("rule_type") or "").strip().lower()
        if r_type != rule_type:
            continue

        # Check active status
        is_active = r.get("is_active", 1)
        if is_active in (0, "0", False, "false"):
            continue

        r_target = (r.get("target") or "").strip().lower()
        if not r_target:
            continue

        action = (r.get("action") or "BLOCK").strip().upper()
        note = r.get("note", "")

        is_match = False
        if rule_type == "domain":
            # Exact match OR subdomain match
            if norm_target == r_target or norm_target.endswith("." + r_target):
                is_match = True
        elif rule_type in ("ip", "app"):
            if norm_target == r_target:
                is_match = True

        if is_match:
            matching_candidates.append({
                "id": r.get("id"),
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
