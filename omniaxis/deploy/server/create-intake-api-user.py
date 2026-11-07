#!/usr/bin/env python3
"""Create (or re-key) the least-privilege Wazuh API user the intake relay uses.

The user gets one role with one policy: action `event:ingest` on `*:*:*`.
It cannot read alerts, agents or configuration. Idempotent: existing user,
policy and role are reused; the password is only changed with --rotate or
when the password file is missing.

    create-intake-api-user.py --admin-user wazuh-wui --admin-password-file /root/.wazuh-api-admin \
        --password-file /etc/omniaxis-intake/api-password [--owner scdc-intake] [--rotate]

Talks to the API on loopback only. Passwords are read from and written to
files (mode 0400/0600); they are never printed or passed on a command line.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import pwd
import secrets
import ssl
import string
import sys
import urllib.error
import urllib.parse
import urllib.request

USER = "scdc-intake"
POLICY = "scdc_event_ingest"
ROLE = "scdc_intake"


def new_password() -> str:
    # Wazuh requires 8-64 chars with upper, lower, digit and symbol.
    alphabet = string.ascii_letters + string.digits + "._-+!"
    while True:
        p = "".join(secrets.choice(alphabet) for _ in range(40))
        if (any(c.isupper() for c in p) and any(c.islower() for c in p) and any(c.isdigit() for c in p)
                and any(c in "._-+!" for c in p)):
            return p


class Api:
    def __init__(self, base: str, ca: str | None):
        host = urllib.parse.urlparse(base).hostname
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise SystemExit("the Wazuh API must be reached on loopback")
        self.base = base.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=ca) if ca else ssl._create_unverified_context()  # noqa: S323 loopback only
        if ca:
            self.ctx.check_hostname = False
        self.token = None

    def call(self, method: str, path: str, body=None, basic: str | None = None):
        headers = {"Content-Type": "application/json"}
        if basic:
            headers["Authorization"] = "Basic " + base64.b64encode(basic.encode()).decode()
        elif self.token:
            headers["Authorization"] = "Bearer " + self.token
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=20) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            raise SystemExit(f"API {method} {path} -> HTTP {e.code}: {detail}")

    def login(self, user: str, password: str):
        self.token = self.call("POST", "/security/user/authenticate", basic=f"{user}:{password}")["data"]["token"]

    def create(self, path: str, body: dict) -> dict:
        # Use the create response: GET results are cached by the API for
        # about 0.75 s, so a lookup straight after a create can miss it.
        data = self.call("POST", path, body)["data"]
        if not data["affected_items"]:
            raise SystemExit(f"API POST {path} failed: {data.get('failed_items')}")
        return data["affected_items"][0]

    def find(self, path: str, field: str, value: str):
        items = self.call("GET", f"{path}?limit=500")["data"]["affected_items"]
        return next((i for i in items if i.get(field) == value), None)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="https://127.0.0.1:55000")
    ap.add_argument("--ca")
    ap.add_argument("--admin-user", required=True)
    ap.add_argument("--admin-password-file", required=True)
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--owner", help="system user (name or numeric uid) that must read the password file")
    ap.add_argument("--rotate", action="store_true")
    a = ap.parse_args()

    api = Api(a.api, a.ca)
    api.login(a.admin_user, open(a.admin_password_file).read().strip())

    user = api.find("/security/users", "username", USER)
    need_password = a.rotate or user is None or not os.path.exists(a.password_file)
    password = new_password() if need_password else None
    if user is None:
        user = api.create("/security/users", {"username": USER, "password": password})
        print(f"created API user {USER}")
    elif need_password:
        api.call("PUT", f"/security/users/{user['id']}", {"password": password})
        print(f"set a new password for API user {USER}")

    # Wazuh 4.14 ships "events_ingest_resourceless" with exactly this body and
    # refuses a second policy with the same body, so reuse whichever exists.
    body = {"actions": ["event:ingest"], "resources": ["*:*:*"], "effect": "allow"}
    policies = api.call("GET", "/security/policies?limit=500")["data"]["affected_items"]
    policy = next((p for p in policies if p.get("policy") == body), None)
    if policy is None:
        policy = api.create("/security/policies", {"name": POLICY, "policy": body})
        print(f"created policy {POLICY}")
    else:
        print(f"using policy {policy['name']} (event:ingest only)")
    role = api.find("/security/roles", "name", ROLE)
    if role is None:
        role = api.create("/security/roles", {"name": ROLE})
        print(f"created role {ROLE}")
    if policy["id"] not in role.get("policies", []):
        api.call("POST", f"/security/roles/{role['id']}/policies?policy_ids={policy['id']}")
    if role["id"] not in user.get("roles", []):
        api.call("POST", f"/security/users/{user['id']}/roles?role_ids={role['id']}")
    print(f"{USER} has role {ROLE} (event:ingest only)")

    if password is not None:
        os.makedirs(os.path.dirname(a.password_file), mode=0o750, exist_ok=True)
        tmp = a.password_file + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(password + "\n")
        if a.owner:
            if a.owner.isdigit():
                uid = gid = int(a.owner)
            else:
                pw = pwd.getpwnam(a.owner)
                uid, gid = pw.pw_uid, pw.pw_gid
            os.chown(tmp, uid, gid)
            os.chmod(tmp, 0o400)
        os.replace(tmp, a.password_file)
        print(f"password written to {a.password_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
