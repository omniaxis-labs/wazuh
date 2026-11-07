"""Tests for custom-scdc-portal.py.

Run with Wazuh's bundled Python (it has `cryptography`):
    /var/ossec/framework/python/bin/python3 -m unittest discover -s tests -v
or any Python 3.10+ with `cryptography` installed.
"""
from __future__ import annotations

import base64
import importlib.util
import re
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
             "environment": "preview", "type": "audit.chain_broken", "severity": "sev1",
             "dedupe_key": "audit.chain_broken", "title": "Audit chain broken",
             "refs": {"resource": "musterward-web", "bogus": "x"}, "counts": {"attempts": "3"},
             "reason": "hash_mismatch", "key_id": "mw-prod-1", "unexpected": "dropped"},
    "location": "API-Webhook",
}

HOST_ALERT = {
    "timestamp": "2026-11-07T06:00:00.000+0000",
    "id": "1794031200.999",
    "rule": {"level": 10, "description": "sshd: brute force", "id": "5712", "groups": ["syslog", "sshd", "authentication_failures"]},
    "agent": {"id": "001", "name": "gate", "labels": {"product": "company"}},
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


ALERT_KEYS = {"specversion", "id", "source", "environment", "time", "product", "product_environment", "type",
              "title", "dedupe_key", "severity", "rule", "agent", "event_id", "refs", "counts", "reason"}


class TestPayload(Base):
    def test_scdc_event_alert_becomes_the_scdc_alert_envelope(self):
        self.assertEqual(self.run_with(SCDC_ALERT), 0)
        self.assertEqual(len(Portal.received), 1)
        headers, body = Portal.received[0]
        self.assertEqual(headers["webhook-id"], "wz_1794030528.12345")
        self.assertEqual(body["id"], headers["webhook-id"])
        self.assertEqual(body["specversion"], "scdc-alert/1")
        self.assertEqual(body["source"], "wazuh")
        self.assertEqual(body["environment"], "production")
        self.assertEqual(body["time"], "2026-11-07T05:12:50.000Z")
        self.assertEqual(body["product"], "musterward")
        self.assertEqual(body["product_environment"], "preview")
        self.assertEqual(body["type"], "audit.chain_broken")
        self.assertEqual(body["title"], "Audit chain broken")
        self.assertEqual(body["dedupe_key"], "audit.chain_broken")
        self.assertEqual(body["severity"], "sev1")
        self.assertEqual(body["rule"], {"id": "100111", "level": 13, "groups": ["omniaxis_labs", "scdc", "musterward", "scdc_sev1"]})
        self.assertEqual(body["event_id"], "evt_1")
        self.assertEqual(body["refs"], {"resource": "musterward-web"})
        self.assertEqual(body["counts"], {"attempts": 3})
        self.assertEqual(body["reason"], "hash_mismatch")
        self.assertEqual(body["agent"], {"name": "scdc-1"})
        self.assertTrue(set(body) <= ALERT_KEYS, set(body) - ALERT_KEYS)

    def test_host_alert_takes_product_from_agent_label_and_sends_no_raw_log(self):
        self.run_with(HOST_ALERT)
        _, body = Portal.received[0]
        self.assertEqual(body["product"], "company")
        self.assertEqual(body["severity"], "sev2")
        self.assertEqual(body["type"], "wazuh.rule.5712")
        self.assertEqual(body["title"], "sshd: brute force")
        self.assertEqual(body["dedupe_key"], "wazuh.rule.5712:gate")
        self.assertTrue(set(body) <= ALERT_KEYS)
        self.assertNotIn("203.0.113.9", json.dumps(body))

    def test_unknown_product_label_is_company(self):
        alert = json.loads(json.dumps(HOST_ALERT))
        alert["agent"]["labels"]["product"] = "gate"
        self.run_with(alert)
        self.assertEqual(Portal.received[0][1]["product"], "company")

    def test_level_bands(self):
        self.assertEqual([portal.severity_for_level(n) for n in (2, 3, 6, 7, 9, 10, 12, 13, 15)],
                         [None, "sev4", "sev4", "sev3", "sev3", "sev2", "sev2", "sev1", "sev1"])

    def test_below_min_level_is_not_sent(self):
        alert = json.loads(json.dumps(HOST_ALERT))
        alert["rule"]["level"] = 5
        self.run_with(alert)
        self.assertEqual(Portal.received, [])

    def test_long_titles_and_odd_groups_are_made_to_fit(self):
        alert = json.loads(json.dumps(HOST_ALERT))
        alert["rule"]["description"] = "x\u200b " * 200
        alert["rule"]["groups"] = ["ok", "Has Space", "pci_dss_10.2.4"] + [f"g{i}" for i in range(30)]
        self.run_with(alert)
        body = Portal.received[0][1]
        self.assertLessEqual(len(body["title"]), 140)
        self.assertNotIn("\u200b", body["title"])
        self.assertEqual(body["rule"]["groups"][0], "ok")
        self.assertEqual(len(body["rule"]["groups"]), 16)


class TestVector(unittest.TestCase):
    """The portal's published vector, byte for byte (vendored test-vectors.ts)."""

    def test_signer_matches_the_published_test_vector(self):
        src = (HERE.parents[2] / "intake-relay" / "vendor" / "scdc-verifier" / "src" / "test-vectors.ts").read_text()
        seed = base64.b64decode(re.search(r'seed: "([^"]+)"', src).group(1))
        body = re.search(r"body: '(.*?)',\n", src).group(1).encode()
        vid = re.search(r'id: "([^"]+)"', src).group(1)
        ts = re.search(r'timestamp: "([^"]+)"', src).group(1)
        expected = re.search(r'signature:\s*"([^"]+)"', src).group(1)
        public = re.search(r'publicKey: "([^"]+)"', src).group(1)
        key = Ed25519PrivateKey.from_private_bytes(seed)
        headers = portal.sign_headers(key, vid, body, now=int(ts))
        self.assertEqual(headers["webhook-signature"], expected)
        self.assertEqual(portal.public_key_whpk(key), public)


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
        self.assertEqual(ids, ["wz_1794030528.12345", "wz_1794031200.999"])
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
    def test_full_integratord_argv(self):  # noqa: D102
        a = portal.parse_args(["x", "/tmp/a.alert", "", "https://h/api", "debug", "/tmp/x-1-2.options", "10", "3"])
        self.assertEqual((a["hook_url"], a["options_file"], a["debug"], a["timeout"], a["retries"]),
                         ("https://h/api", "/tmp/x-1-2.options", True, 10, 3))


if __name__ == "__main__":
    unittest.main()
