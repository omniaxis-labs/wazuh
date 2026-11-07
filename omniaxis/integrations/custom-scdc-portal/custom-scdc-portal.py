#!/usr/bin/env python3
"""Push Wazuh alerts, signed, to the SCDC admin portal.

Called by wazuh-integratord for every alert at or above the configured level
(7, i.e. SEV3 and up). ossec.conf:

    <integration>
      <name>custom-scdc-portal</name>
      <hook_url>https://admin.omniaxislabs.com/api/wazuh/alerts</hook_url>
      <level>7</level>
      <alert_format>json</alert_format>
      <options>{"key_file": "/var/ossec/etc/omniaxis/portal-signing.key", "key_id": "scdc-wazuh-1", "environment": "production"}</options>
    </integration>

Body: the portal's `scdc-alert/1` envelope (source "wazuh"), built from the
alert through the same allowlist the portal enforces. Headers: Standard
Webhooks, Ed25519 (`v1a`), over "id.timestamp.body":

    webhook-id:        wz_<alert id>         (equals the body's id; the portal dedupes)
    webhook-timestamp: <unix seconds>
    webhook-signature: v1a,<std base64 signature>

The private key never appears on the command line or in ossec.conf: options
carry only its path. The portal holds the public key (whpk_...), registered
with `pnpm keys add --source wazuh --environment <env> --public-key whpk_...`.

Delivery: three attempts with backoff inside one run. If all fail, the body
is spooled and re-sent (re-signed, same webhook-id) at the start of the next
run, oldest first, so a portal outage loses nothing. A 4xx other than 408/429
is a permanent refusal: logged, not retried.

argv (wazuh-integratord, 4.14): alert_file api_key hook_url [debug] options_file timeout retries
Empty values can collapse, so arguments are found by shape, as Wazuh's own
integrations do.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

WAZUH_PATH = os.environ.get("WAZUH_PATH") or os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_FILE = os.path.join(WAZUH_PATH, "logs", "integrations.log")
DEFAULT_SPOOL = os.path.join(WAZUH_PATH, "var", "omniaxis", "portal-spool")
MAX_BODY = 16 * 1024  # the contract limit
MAX_SPOOL_FILES = 5000
RESEND_PER_RUN = 25

debug_enabled = False


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} custom-scdc-portal: {msg}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except OSError:
        sys.stderr.write(line)


def debug(msg: str) -> None:
    if debug_enabled:
        log(f"debug: {msg}")


# --------------------------------------------------------------------------
# Alert -> scdc-alert/1 envelope
#
# The envelope is the portal's contract (@omniaxis-labs/scdc-verifier,
# parseAlert; vendored at omniaxis/intake-relay/vendor/scdc-verifier). The
# patterns below mirror its schema.ts so every push passes the allowlist.

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
DOTTED_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){0,7}$")
REF_RE = ID_RE
COUNT_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
GROUP_RE = re.compile(r"^[a-z0-9_-]{1,40}$")
ALERT_PRODUCTS = ("musterward", "omniaxis", "rackhand", "crosswalk", "company")
ENVIRONMENTS = ("production", "preview")
CONTROL_RE = re.compile(r"[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]")


def severity_for_level(level: int):
    if level >= 13:
        return "sev1"
    if level >= 10:
        return "sev2"
    if level >= 7:
        return "sev3"
    if level >= 3:
        return "sev4"
    return None


def plain(text, limit: int) -> str:
    t = re.sub(r"\s+", " ", CONTROL_RE.sub(" ", str(text or ""))).strip()
    return t if len(t) <= limit else t[: limit - 1].rstrip() + "\u2026"


def iso_utc(ts) -> str:
    """Wazuh '2026-11-07T05:12:50.123+0000' -> '2026-11-07T05:12:50.123Z'."""
    from datetime import datetime, timezone
    try:
        dt = datetime.strptime(str(ts), "%Y-%m-%dT%H:%M:%S.%f%z").astimezone(timezone.utc)
    except (TypeError, ValueError):
        dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def product_for(alert: dict) -> str:
    data = alert.get("data") or {}
    labels = (alert.get("agent") or {}).get("labels") or {}
    for candidate in (data.get("product"), labels.get("product")):
        if candidate in ALERT_PRODUCTS:
            return candidate
    # Hosts, the SCDC itself and anything unlabelled are company infrastructure.
    return "company"


def build_payload(alert: dict, webhook_id: str, environment: str) -> dict:
    rule = alert.get("rule") or {}
    level = int(rule.get("level") or 0)
    rule_id = str(rule.get("id", ""))
    groups = [g for g in (rule.get("groups") or []) if isinstance(g, str) and GROUP_RE.match(g)][:16]
    data = alert.get("data") or {}
    agent = alert.get("agent") or {}
    decoder = (alert.get("decoder") or {}).get("name")
    is_event = decoder == "omniaxis-scdc" and "scdc" in groups
    is_relay = decoder == "omniaxis-scdc-relay"

    if is_event:
        type_ = data.get("type")
        title = data.get("title") or rule.get("description")
        dedupe = data.get("dedupe_key")
        product_env = data.get("environment")
    elif is_relay:
        type_ = f"scdc.intake.{data.get('event', 'unknown')}"
        title = rule.get("description")
        dedupe = f"scdc.intake.{data.get('event', 'unknown')}:{data.get('srcip', '')}"
        product_env = "production"
    else:
        type_ = f"wazuh.rule.{rule_id}"
        title = rule.get("description")
        dedupe = f"wazuh.rule.{rule_id}:{agent.get('name', '')}"
        product_env = "production"

    if not (isinstance(type_, str) and DOTTED_RE.match(type_) and len(type_) <= 100):
        type_ = f"wazuh.rule.{rule_id}" if rule_id.isdigit() else "wazuh.alert"
    payload = {
        "specversion": "scdc-alert/1",
        "id": webhook_id,
        "source": "wazuh",
        "environment": environment,
        "time": iso_utc(alert.get("timestamp")),
        "product": product_for(alert),
        "product_environment": product_env if product_env in ENVIRONMENTS else "production",
        "type": type_,
        "title": plain(title, 140) or f"Wazuh rule {rule_id}",
        "dedupe_key": plain(dedupe, 200) or f"wazuh.rule.{rule_id}",
        "severity": severity_for_level(level),
        "rule": {"id": rule_id, "level": level, "groups": groups},
    }
    name = agent.get("name")
    if isinstance(name, str) and REF_RE.match(name):
        payload["agent"] = {"name": name}
    if is_event:
        if isinstance(data.get("id"), str) and ID_RE.match(data["id"]):
            payload["event_id"] = data["id"]
        refs = {k: v for k, v in (data.get("refs") or {}).items()
                if k in ("tenant_ref", "actor_ref", "resource") and isinstance(v, str) and REF_RE.match(v)}
        if refs:
            payload["refs"] = refs
        counts = {}
        for k, v in list((data.get("counts") or {}).items())[:16]:
            # The JSON decoder hands numbers back as strings.
            try:
                n = int(v)
            except (TypeError, ValueError):
                continue
            if COUNT_KEY_RE.match(k) and n >= 0:
                counts[k] = n
        if counts:
            payload["counts"] = counts
    reason = data.get("reason")
    if (is_event or is_relay) and isinstance(reason, str) and DOTTED_RE.match(reason):
        payload["reason"] = reason
    return payload


def webhook_id_for(alert: dict) -> str:
    raw = str(alert.get("id") or "")
    safe = re.sub(r"[^A-Za-z0-9_.]", "_", raw)[:120]
    if not safe:
        safe = f"t{int(time.time() * 1000)}"
    return f"wz_{safe}"


# --------------------------------------------------------------------------
# Signing

def load_private_key(path: str):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    with open(path, "rb") as f:
        raw = f.read().strip()
    if raw.startswith(b"-----BEGIN"):
        key = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("signing key is not Ed25519")
        return key
    seed = base64.b64decode(raw)
    if len(seed) != 32:
        raise ValueError("raw signing key must be a 32-byte base64 seed")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_whpk(private_key) -> str:
    """The portal's key format: whpk_<standard base64 of the raw 32 bytes>."""
    from cryptography.hazmat.primitives import serialization
    raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "whpk_" + base64.b64encode(raw).decode()


def sign_headers(key, webhook_id: str, body: bytes, now: int | None = None) -> dict:
    ts = str(int(now if now is not None else time.time()))
    sig = key.sign(webhook_id.encode() + b"." + ts.encode() + b"." + body)
    return {
        "webhook-id": webhook_id,
        "webhook-timestamp": ts,
        "webhook-signature": "v1a," + base64.b64encode(sig).decode(),
        "content-type": "application/json",
        "user-agent": "omniaxis-scdc-wazuh/1 (scdc-alert/1)",
    }


# --------------------------------------------------------------------------
# Delivery

class Delivery:
    def __init__(self, url: str, key, key_id: str, timeout: float, attempts: int, spool_dir: str):
        if not url.startswith("https://") and not os.environ.get("SCDC_ALLOW_HTTP_FOR_TESTS"):
            raise ValueError("hook_url must be https")
        self.url = url
        self.key = key
        self.key_id = key_id
        self.timeout = timeout
        self.attempts = max(1, attempts)
        self.spool_dir = spool_dir

    def post(self, webhook_id: str, body: bytes) -> int:
        headers = sign_headers(self.key, webhook_id, body)
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                return res.status
        except urllib.error.HTTPError as e:
            return e.code
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            debug(f"network error: {e}")
            return 0

    def deliver(self, webhook_id: str, body: bytes) -> bool:
        delay = 1.0
        for attempt in range(1, self.attempts + 1):
            status = self.post(webhook_id, body)
            if 200 <= status < 300:
                return True
            # 4xx other than 408/429 will not get better by retrying.
            if 400 <= status < 500 and status not in (408, 429):
                log(f"portal refused {webhook_id} with HTTP {status}; not retrying")
                return True
            debug(f"attempt {attempt} for {webhook_id}: status {status}")
            if attempt < self.attempts:
                time.sleep(delay)
                delay *= 2
        return False

    # Spool: one file per undelivered alert, named so lexical order is age order.
    def spool(self, webhook_id: str, body: bytes) -> None:
        os.makedirs(self.spool_dir, mode=0o750, exist_ok=True)
        existing = sorted(os.listdir(self.spool_dir))
        if len(existing) >= MAX_SPOOL_FILES:
            os.remove(os.path.join(self.spool_dir, existing[0]))
            log("spool full; dropped the oldest undelivered alert")
        name = f"{int(time.time() * 1000):015d}-{webhook_id}.json"
        tmp = os.path.join(self.spool_dir, "." + name)
        with open(tmp, "wb") as f:
            f.write(body)
        os.chmod(tmp, 0o640)
        os.replace(tmp, os.path.join(self.spool_dir, name))
        log(f"portal unreachable; spooled {webhook_id}")

    def resend_spooled(self) -> None:
        if not os.path.isdir(self.spool_dir):
            return
        for name in sorted(n for n in os.listdir(self.spool_dir) if n.endswith(".json") and not n.startswith("."))[:RESEND_PER_RUN]:
            path = os.path.join(self.spool_dir, name)
            webhook_id = name.split("-", 1)[1][: -len(".json")]
            with open(path, "rb") as f:
                body = f.read()
            status = self.post(webhook_id, body)
            if 200 <= status < 300 or (400 <= status < 500 and status not in (408, 429)):
                os.remove(path)
                debug(f"resent {webhook_id}: {status}")
            else:
                break  # still down; keep order, try again next run


def parse_args(argv: list[str]) -> dict:
    args = {"alert_file": None, "hook_url": None, "options_file": None, "debug": False, "timeout": 10, "retries": 3}
    if len(argv) < 2:
        raise SystemExit("usage: custom-scdc-portal <alert_file> <api_key> <hook_url> [debug] <options_file> <timeout> <retries>")
    args["alert_file"] = argv[1]
    numbers = []
    for a in argv[2:]:
        if a.startswith("https://") or a.startswith("http://"):
            args["hook_url"] = a
        elif a.endswith(".options"):
            args["options_file"] = a
        elif a == "debug":
            args["debug"] = True
        elif a.isdigit():
            numbers.append(int(a))
    if len(numbers) >= 2:
        args["timeout"], args["retries"] = numbers[-2] or 10, numbers[-1] or 3
    return args


def main(argv: list[str]) -> int:
    global debug_enabled
    args = parse_args(argv)
    debug_enabled = args["debug"]
    options = {}
    if args["options_file"]:
        with open(args["options_file"]) as f:
            options = json.load(f)
    if not args["hook_url"]:
        log("no hook_url configured")
        return 1
    key_file = options.get("key_file", os.path.join(WAZUH_PATH, "etc", "omniaxis", "portal-signing.key"))
    key = load_private_key(key_file)
    delivery = Delivery(
        url=args["hook_url"],
        key=key,
        key_id=str(options.get("key_id", "scdc-wazuh-1"))[:64],
        timeout=float(min(args["timeout"], 30)),
        attempts=min(args["retries"], 5),
        spool_dir=options.get("spool_dir", DEFAULT_SPOOL),
    )

    with open(args["alert_file"]) as f:
        alert = json.load(f)
    min_level = max(3, int(options.get("min_level", 7)))
    if int((alert.get("rule") or {}).get("level") or 0) < min_level:
        debug("below min_level; skipped")
        return 0
    environment = options.get("environment", "production")
    if environment not in ENVIRONMENTS:
        raise ValueError("options.environment must be production or preview")

    delivery.resend_spooled()
    webhook_id = webhook_id_for(alert)
    payload = build_payload(alert, webhook_id, environment)
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()
    if len(body) > MAX_BODY:
        # Cannot happen with the field limits above; drop optional parts rather than the alert.
        for k in ("refs", "counts", "agent"):
            payload.pop(k, None)
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()
    if not delivery.deliver(webhook_id, body):
        delivery.spool(webhook_id, body)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:  # noqa: BLE001 - integratord only sees the exit code
        log(f"error: {type(exc).__name__}: {exc}")
        sys.exit(1)
