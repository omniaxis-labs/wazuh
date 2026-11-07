"""Tests for custom-scdc-portal.py.

Run with Wazuh's bundled Python (it has `cryptography`):
    /var/ossec/framework/python/bin/python3 -m unittest discover -s tests -v
or any Python 3.10+ with `cryptography` installed.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import pathlib
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE.parent / "custom-scdc-portal.py"
spec = importlib.util.spec_from_file_location("scdc_portal", SCRIPT)
portal = importlib.util.module_from_spec(spec)
os.environ["SCDC_ALLOW_HTTP_FOR_TESTS"] = "1"
spec.loader.exec_module(portal)


SCDC_ALERT = {
    "timestamp": "2026-11-07T05:12:50.000+0000",
    "id": "1794030528.12345",
    "rule": {"level": 13, "description": "Musterward SEV1: Audit chain broken", "id": "100111", "firedtimes": 1,
             "groups": ["omniaxis_labs", "scdc", "musterward", "scdc_sev1"]},
    "agent": {"id": "000", "name": "scdc-1"},
    "manager": {"name": "scdc-1"},
    "full_log": "omniaxis-scdc: {...}",
    "decoder": {"name": "omniaxis-scdc"},
    "data": {"specversion": "scdc/1", "id": "evt_1", "source": "musterward", "product": "musterward",
             "environment": "production", "type": "audit.chain_broken", "severity": "sev1",
             "dedupe_key": "audit.chain_broken", "title": "Audit chain broken",
             "refs": {"resource": "musterward-web"}, "key_id": "mw-prod-1", "unexpected": "dropped"},
    "location": "API-Webhook",
}

HOST_ALERT = {
    "timestamp": "2026-11-07T06:00:00.000+0000",
    "id": "1794031200.999",
    "rule": {"level": 10, "description": "sshd: brute force", "id": "5712", "groups": ["syslog", "sshd", "authentication_failures"]},
    "agent": {"id": "001", "name": "gate", "labels": {"product": "gate"}},
    "manager": {"name": "scdc-1"},
    "full_log": "Nov  7 06:00:00 gate sshd[1]: Failed password for invalid user admin from 203.0.113.9",
    "decoder": {"name": "sshd"},
    "data": {"srcip": "203.0.113.9", "srcuser": "admin", "weird": "dropped"},
    "location": "/var/log/auth.log",
}


class Portal(BaseHTTPRequestHandler):
    received: list = []
    statuses: list = []
    public_key = None

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["content-length"]))
        h = {k.lower(): v for k, v in self.headers.items()}
        signed = f"{h['webhook-id']}.{h['webhook-timestamp']}.".encode() + body
        scheme, sig = h["webhook-signature"].split(",", 1)
        Portal.public_key.verify(base64.b64decode(sig), signed)  # raises if bad
        assert scheme == "v1a"
        Portal.received.append((h, json.loads(body)))
        status = Portal.statuses.pop(0) if Portal.statuses else 202
        self.send_response(status)
        self.end_headers()

    def log_message(self, *a):
        pass


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = Ed25519PrivateKey.generate()
        Portal.public_key = cls.key.public_key()
        cls.server = HTTPServer(("127.0.0.1", 0), Portal)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/api/wazuh/alerts"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        Portal.received.clear()
        Portal.statuses.clear()
        self.tmp = tempfile.TemporaryDirectory()
        d = pathlib.Path(self.tmp.name)
        self.key_file = d / "portal-signing.key"
        self.key_file.write_bytes(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
        self.spool = d / "spool"
        self.options = d / "custom-scdc-portal-1-2.options"
        self.options.write_text(json.dumps({"key_file": str(self.key_file), "key_id": "scdc-wazuh-test", "spool_dir": str(self.spool)}))
        portal.LOG_FILE = str(d / "integrations.log")
        portal.time.sleep = lambda s: None  # no real backoff in tests

    def tearDown(self):
        self.tmp.cleanup()

    def run_with(self, alert: dict) -> int:
        f = pathlib.Path(self.tmp.name) / "alert.alert"
        f.write_text(json.dumps(alert))
        # Same shape integratord uses, with an empty api_key collapsed away.
        return portal.main(["custom-scdc-portal", str(f), self.url, str(self.options), "10", "3"])


class TestPayload(Base):
    def test_scdc_alert_is_signed_and_carries_product_and_severity(self):
        self.assertEqual(self.run_with(SCDC_ALERT), 0)
        self.assertEqual(len(Portal.received), 1)
        headers, body = Portal.received[0]
        self.assertEqual(headers["webhook-id"], "wza_1794030528_12345")
        self.assertEqual(headers["x-scdc-key-id"], "scdc-wazuh-test")
        self.assertEqual(body["product"], "musterward")
        self.assertEqual(body["severity"], "sev1")
        self.assertEqual(body["source"], "scdc-wazuh")
        self.assertEqual(body["dedupe_key"], "musterward:audit.chain_broken")
        self.assertEqual(body["alert"]["rule"]["id"], "100111")
        self.assertNotIn("unexpected", body["alert"]["data"])
        self.assertNotIn("full_log", body["alert"])

    def test_host_alert_takes_product_from_agent_label(self):
        self.run_with(HOST_ALERT)
        _, body = Portal.received[0]
        self.assertEqual(body["product"], "gate")
        self.assertEqual(body["severity"], "sev2")
        self.assertEqual(body["alert"]["data"], {"srcip": "203.0.113.9", "srcuser": "admin"})
        self.assertIn("full_log", body["alert"])
        self.assertEqual(body["dedupe_key"], "wazuh:5712:001")

    def test_level_bands(self):
        self.assertEqual([portal.severity_for_level(n) for n in (3, 6, 7, 9, 10, 12, 13, 15)],
                         ["sev4", "sev4", "sev3", "sev3", "sev2", "sev2", "sev1", "sev1"])

    def test_below_min_level_is_not_sent(self):
        alert = json.loads(json.dumps(HOST_ALERT))
        alert["rule"]["level"] = 5
        self.run_with(alert)
        self.assertEqual(Portal.received, [])

    def test_unlabelled_alert(self):
        alert = json.loads(json.dumps(HOST_ALERT))
        alert["agent"].pop("labels")
        self.run_with(alert)
        self.assertEqual(Portal.received[0][1]["product"], "unlabelled")


class TestDelivery(Base):
    def test_retries_then_succeeds(self):
        Portal.statuses[:] = [503, 502]
        self.run_with(SCDC_ALERT)
        self.assertEqual(len(Portal.received), 3)
        self.assertFalse(self.spool.exists() and any(self.spool.iterdir()))

    def test_outage_spools_then_resends_on_next_run_with_same_id(self):
        Portal.statuses[:] = [503, 503, 503]
        self.run_with(SCDC_ALERT)
        spooled = list(self.spool.iterdir())
        self.assertEqual(len(spooled), 1)
        Portal.received.clear()
        self.run_with(HOST_ALERT)
        ids = [h["webhook-id"] for h, _ in Portal.received]
        self.assertEqual(ids, ["wza_1794030528_12345", "wza_1794031200_999"])
        self.assertEqual(list(self.spool.iterdir()), [])

    def test_permanent_refusal_is_not_spooled(self):
        Portal.statuses[:] = [400]
        self.run_with(SCDC_ALERT)
        self.assertEqual(len(Portal.received), 1)
        self.assertFalse(self.spool.exists() and any(self.spool.iterdir()))

    def test_raw_seed_key_file(self):
        seed = self.key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        self.key_file.write_text(base64.b64encode(seed).decode())
        self.run_with(SCDC_ALERT)
        self.assertEqual(len(Portal.received), 1)

    def test_https_required_outside_tests(self):
        os.environ.pop("SCDC_ALLOW_HTTP_FOR_TESTS")
        try:
            with self.assertRaises(ValueError):
                portal.Delivery("http://example.com", self.key, "k", 5, 1, str(self.spool))
        finally:
            os.environ["SCDC_ALLOW_HTTP_FOR_TESTS"] = "1"


class TestArgs(unittest.TestCase):
    def test_full_integratord_argv(self):
        a = portal.parse_args(["x", "/tmp/a.alert", "", "https://h/api", "debug", "/tmp/x-1-2.options", "10", "3"])
        self.assertEqual((a["hook_url"], a["options_file"], a["debug"], a["timeout"], a["retries"]),
                         ("https://h/api", "/tmp/x-1-2.options", True, 10, 3))


if __name__ == "__main__":
    unittest.main()
