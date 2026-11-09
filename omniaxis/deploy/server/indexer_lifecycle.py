#!/usr/bin/env python3
"""Retention and snapshots for the Wazuh indexer (OpenSearch 2.19).

- Index State Management deletes alert indices after ALERT_INDEX_DAYS (90)
  and archive, monitoring and statistics indices after OTHER_INDEX_DAYS (30).
  The policies carry templates, so each new day's index is caught, and
  indices made before the policies existed are added to them.
- Snapshot Management takes a daily snapshot of the wazuh-* indices into the
  filesystem repository at SNAPSHOT_DIR and keeps SNAPSHOTS_KEPT (14). The
  off-host backup copies that folder (45-retention-backup.sh).

Re-runnable: each run brings the indexer to these settings and changes
nothing that already matches. Standard library only; run with the system
python3 on the server.

    indexer_lifecycle.py apply --url https://127.0.0.1:9200 \\
        --user admin --password-file /root/omniaxis-scdc/wazuh-indexer-admin \\
        --cacert /etc/wazuh-indexer/certs/root-ca.pem
"""

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

REPOSITORY = "omniaxis-fs"
SNAPSHOT_DIR = "/var/lib/wazuh-indexer-snapshots"
SM_POLICY = "omniaxis-daily"
ALERT_PATTERNS = ["wazuh-alerts-*"]
OTHER_PATTERNS = ["wazuh-archives-*", "wazuh-monitoring-*", "wazuh-statistics-*"]


@dataclass(frozen=True)
class Settings:
    alert_days: int
    other_days: int
    snapshots_kept: int


def _int(env, key, default, low, high):
    raw = env.get(key, "") or str(default)
    if not raw.isdigit() or not low <= int(raw) <= high:
        raise ValueError(f"{key} must be a whole number from {low} to {high}, not {raw!r}")
    return int(raw)


def settings(env):
    return Settings(
        alert_days=_int(env, "ALERT_INDEX_DAYS", 90, 1, 3650),
        other_days=_int(env, "OTHER_INDEX_DAYS", 30, 1, 3650),
        snapshots_kept=_int(env, "SNAPSHOTS_KEPT", 14, 1, 365),
    )


def _delete_after(description, days, patterns):
    return {
        "policy": {
            "description": description,
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [],
                    "transitions": [
                        {"state_name": "delete", "conditions": {"min_index_age": f"{days}d"}}
                    ],
                },
                {"name": "delete", "actions": [{"delete": {}}], "transitions": []},
            ],
            "ism_template": [{"index_patterns": patterns, "priority": 100}],
        }
    }


def ism_policies(s):
    return {
        "omniaxis-alerts": _delete_after(
            f"OmniAxis SCDC: alert indices are deleted {s.alert_days} days after creation",
            s.alert_days,
            ALERT_PATTERNS,
        ),
        "omniaxis-other": _delete_after(
            f"OmniAxis SCDC: archive, monitoring and statistics indices are deleted {s.other_days} days after creation",
            s.other_days,
            OTHER_PATTERNS,
        ),
    }


def repository_body():
    return {"type": "fs", "settings": {"location": SNAPSHOT_DIR, "compress": True}}


def sm_policy(s):
    return {
        "description": f"OmniAxis SCDC: daily snapshot of wazuh-* indices, {s.snapshots_kept} kept",
        "enabled": True,
        "creation": {"schedule": {"cron": {"expression": "30 3 * * *", "timezone": "UTC"}}},
        "deletion": {
            "schedule": {"cron": {"expression": "0 4 * * *", "timezone": "UTC"}},
            "condition": {"max_count": s.snapshots_kept, "min_count": 1},
        },
        "snapshot_config": {
            "repository": REPOSITORY,
            "indices": "wazuh-*",
            "ignore_unavailable": True,
            "include_global_state": False,
        },
    }


class Indexer:
    def __init__(self, url, user=None, password=None, cacert=None):
        self.url = url.rstrip("/")
        self.headers = {"content-type": "application/json"}
        if user:
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            self.headers["authorization"] = f"Basic {token}"
        self.ctx = ssl.create_default_context(cafile=cacert) if cacert else None

    def call(self, method, path, body=None, ok404=False):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=self.headers)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=30) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            if ok404 and e.code == 404:
                return None
            detail = e.read().decode("utf-8", "replace")[:500]
            raise SystemExit(f"indexer: {method} {path} answered {e.code}: {detail}") from None


def _same(want, have):
    """Whether every key we set has the value we want (the indexer adds its own)."""
    if isinstance(want, dict):
        return isinstance(have, dict) and all(_same(v, have.get(k)) for k, v in want.items())
    if isinstance(want, list):
        return isinstance(have, list) and len(want) == len(have) and all(map(_same, want, have))
    # Settings come back as strings ("compress": "true").
    return want == have or (isinstance(have, str) and json.dumps(want).strip('"') == have)


def say(msg):
    print(f"  indexer: {msg}", flush=True)


def apply(ix, s):
    for name, body in ism_policies(s).items():
        cur = ix.call("GET", f"/_plugins/_ism/policies/{name}", ok404=True)
        if cur is None:
            ix.call("PUT", f"/_plugins/_ism/policies/{name}", body)
            say(f"policy {name} created")
        elif _same(body["policy"], cur["policy"]):
            say(f"policy {name} already as wanted")
        else:
            q = f"?if_seq_no={cur['_seq_no']}&if_primary_term={cur['_primary_term']}"
            ix.call("PUT", f"/_plugins/_ism/policies/{name}{q}", body)
            say(f"policy {name} updated")
        # Indices from before the policy: templates only catch new ones.
        patterns = body["policy"]["ism_template"][0]["index_patterns"]
        explain = ix.call("GET", f"/_plugins/_ism/explain/{','.join(patterns)}")
        loose = [
            i
            for i, v in explain.items()
            if isinstance(v, dict)
            and not (v.get("index.plugins.index_state_management.policy_id") or v.get("policy_id"))
        ]
        if loose:
            r = ix.call("POST", f"/_plugins/_ism/add/{','.join(loose)}", {"policy_id": name})
            say(f"policy {name} added to {r.get('updated_indices', 0)} existing indices")

    cur = ix.call("GET", f"/_snapshot/{REPOSITORY}", ok404=True)
    if cur is None or not _same(repository_body(), cur.get(REPOSITORY)):
        ix.call("PUT", f"/_snapshot/{REPOSITORY}", repository_body())
        say(f"snapshot repository {REPOSITORY} at {SNAPSHOT_DIR}")
    else:
        say(f"snapshot repository {REPOSITORY} already as wanted")

    body = sm_policy(s)
    cur = ix.call("GET", f"/_plugins/_sm/policies/{SM_POLICY}", ok404=True)
    if cur is None:
        ix.call("POST", f"/_plugins/_sm/policies/{SM_POLICY}", body)
        say(f"snapshot policy {SM_POLICY} created")
    elif _same(body, cur["sm_policy"]):
        say(f"snapshot policy {SM_POLICY} already as wanted")
    else:
        q = f"?if_seq_no={cur['_seq_no']}&if_primary_term={cur['_primary_term']}"
        ix.call("PUT", f"/_plugins/_sm/policies/{SM_POLICY}{q}", body)
        say(f"snapshot policy {SM_POLICY} updated")


def main(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("command", choices=["apply", "show"])
    p.add_argument("--url", default="https://127.0.0.1:9200")
    p.add_argument("--user")
    p.add_argument("--password-file")
    p.add_argument("--cacert")
    a = p.parse_args(argv)
    s = settings(os.environ)
    if a.command == "show":
        json.dump({"ism": ism_policies(s), "repository": repository_body(), "sm": sm_policy(s)}, sys.stdout, indent=2)
        print()
        return
    password = None
    if a.user:
        with open(a.password_file, encoding="utf-8") as f:
            password = f.read().strip()
    apply(Indexer(a.url, a.user, password, a.cacert), s)


if __name__ == "__main__":
    main(sys.argv[1:])
