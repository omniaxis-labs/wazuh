#!/usr/bin/env python3
"""Push Wazuh alerts, signed, to the SCDC admin portal.

Called by wazuh-integratord for every alert at or above the configured level
(7, i.e. SEV3 and up). ossec.conf:

    <integration>
      <name>custom-scdc-portal</name>
      <hook_url>https://admin.omniaxislabs.com/api/wazuh/alerts</hook_url>
      <level>7</level>
      <alert_format>json</alert_format>
      <options>{"key_file": "/var/ossec/etc/omniaxis/portal-signing.key", "key_id": "scdc-wazuh-1"}</options>
    </integration>

The request uses the same Standard Webhooks Ed25519 scheme as the intake
contract (design section 4), in the other direction:

    webhook-id:        wza_<alert id>        (idempotency key; the portal dedupes)
    webhook-timestamp: <unix seconds>
    webhook-signature: v1a,<std base64 Ed25519 over "id.timestamp.body">

The private key never appears on the command line or in ossec.conf: options
carry only its path. The portal holds the public key.

Delivery: three attempts with backoff inside one run. If all fail, the signed
body is spooled and re-sent (re-signed, same webhook-id) at the start of the
next run, oldest first, so a portal outage loses nothing.

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
SPECVERSION = "scdc-wazuh/1"
SOURCE = "scdc-wazuh"
MAX_BODY = 32 * 1024
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
# Alert -> portal payload

def severity_for_level(level: int) -> str:
    if level >= 13:
        return "sev1"
    if level >= 10:
        return "sev2"
    if level >= 7:
        return "sev3"
    return "sev4"


# Fields copied from SCDC contract events (data.*). Product events are ids
# only by contract, so these are safe to forward whole.
SCDC_DATA_FIELDS = (
    "source", "product", "environment", "type", "time", "severity", "dedupe_key", "title",
    "refs", "counts", "reason", "key_id", "received_at", "id",
    # relay log fields
    "event", "srcip", "claimed_source", "key_source",
)
# Fields kept from host alerts (agents, the manager itself).
HOST_DATA_FIELDS = (
    "srcip", "srcport", "dstip", "dstport", "srcuser", "dstuser", "user", "protocol", "action",
    "status", "command", "url", "id", "system_name", "title", "file", "uid", "gid", "audit",
)
MAX_TEXT = 2048


def _clip(value, depth: int = 0):
    if isinstance(value, str):
        return value[:MAX_TEXT]
    if isinstance(value, dict) and depth < 3:
        return {str(k)[:64]: _clip(v, depth + 1) for k, v in list(value.items())[:40]}
    if isinstance(value, list) and depth < 3:
        return [_clip(v, depth + 1) for v in value[:40]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:MAX_TEXT]


def product_for(alert: dict) -> str:
    data = alert.get("data") or {}
    labels = (alert.get("agent") or {}).get("labels") or {}
    for candidate in (data.get("product"), labels.get("product")):
        if isinstance(candidate, str) and re.fullmatch(r"[a-z][a-z0-9-]{1,30}", candidate):
            return candidate
    return "unlabelled"


def build_payload(alert: dict, webhook_id: str) -> dict:
    rule = alert.get("rule") or {}
    level = int(rule.get("level") or 0)
    groups = [g for g in (rule.get("groups") or []) if isinstance(g, str)]
    data = alert.get("data") or {}
    is_scdc = "scdc" in groups
    fields = SCDC_DATA_FIELDS if is_scdc else HOST_DATA_FIELDS
    kept = {k: _clip(data[k]) for k in fields if k in data}
    agent = alert.get("agent") or {}
    payload = {
        "specversion": SPECVERSION,
        "id": webhook_id,
        "source": SOURCE,
        "product": product_for(alert),
        "severity": severity_for_level(level),
        "environment": data.get("environment") if data.get("environment") in ("production", "preview") else "production",
        "alert": {
            "id": str(alert.get("id", "")),
            "timestamp": alert.get("timestamp"),
            "rule": {
                "id": str(rule.get("id", "")),
                "level": level,
                "description": _clip(rule.get("description", "")),
                "groups": groups[:20],
                "firedtimes": rule.get("firedtimes"),
                "mitre": _clip(rule.get("mitre")) if rule.get("mitre") else None,
            },
            "agent": {
                "id": agent.get("id"),
                "name": agent.get("name"),
                "labels": _clip(agent.get("labels")) if agent.get("labels") else None,
            },
            "manager": (alert.get("manager") or {}).get("name"),
            "location": _clip(alert.get("location", "")),
            "decoder": (alert.get("decoder") or {}).get("name"),
            "data": kept,
        },
    }
    if is_scdc and isinstance(data.get("dedupe_key"), str):
        payload["dedupe_key"] = f"{payload['product']}:{data['dedupe_key']}"[:256]
    else:
        # Group host alerts by rule and agent so repeats land on one incident.
        payload["dedupe_key"] = f"wazuh:{rule.get('id', '')}:{agent.get('id', '')}"
    if not is_scdc and alert.get("full_log"):
        payload["alert"]["full_log"] = _clip(alert["full_log"])
    return payload


def webhook_id_for(alert: dict) -> str:
    raw = str(alert.get("id") or "")
    safe = re.sub(r"[^A-Za-z0-9_]", "_", raw)[:100]
    if not safe:
        safe = f"t{int(time.time() * 1000)}"
    return f"wza_{safe}"


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


def sign_headers(key, webhook_id: str, body: bytes, now: int | None = None) -> dict:
    ts = str(int(now if now is not None else time.time()))
    sig = key.sign(webhook_id.encode() + b"." + ts.encode() + b"." + body)
    return {
        "webhook-id": webhook_id,
        "webhook-timestamp": ts,
        "webhook-signature": "v1a," + base64.b64encode(sig).decode(),
        "content-type": "application/json",
        "user-agent": "omniaxis-scdc-wazuh/1",
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
        headers["x-scdc-key-id"] = self.key_id
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
    min_level = int(options.get("min_level", 7))
    if int((alert.get("rule") or {}).get("level") or 0) < min_level:
        debug("below min_level; skipped")
        return 0

    delivery.resend_spooled()
    webhook_id = webhook_id_for(alert)
    body = json.dumps(build_payload(alert, webhook_id), separators=(",", ":"), sort_keys=True).encode()
    if len(body) > MAX_BODY:
        # Drop the bulky parts rather than the alert.
        payload = json.loads(body)
        payload["alert"].pop("full_log", None)
        payload["alert"]["data"] = {}
        payload["truncated"] = True
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    if not delivery.deliver(webhook_id, body):
        delivery.spool(webhook_id, body)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:  # noqa: BLE001 - integratord only sees the exit code
        log(f"error: {type(exc).__name__}: {exc}")
        sys.exit(1)
