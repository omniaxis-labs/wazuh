#!/usr/bin/env python3
"""Run the SCDC ruleset fixtures through wazuh-logtest.

Runs inside a Wazuh manager (container or host) and talks to the logtest
socket directly, so each event can carry its real `location` (the CLI tool
always uses "stdin", which our location checks would reject).

Each case in fixtures/*.json:
    {
      "name": "...",
      "events": [{"location": "API-Webhook", "log": "omniaxis-scdc: {...}", "repeat": 1}],
      "expect": {                       # checked against the LAST event's output
        "rule_id": "100111",            # or "rule_id_not_prefix": "1001"
        "level": 13,
        "groups": ["musterward", "scdc_sev1"],
        "data": {"product": "musterward", "refs.tenant_ref": "t_..."}
      }
    }
Every case gets a fresh logtest session, so frequency rules start from zero.

Usage: run_logtest.py [fixtures_dir]   (exit 1 on any failure)
"""
from __future__ import annotations

import json
import pathlib
import socket
import struct
import sys

SOCKET = "/var/ossec/queue/sockets/logtest"


def call(command: str, parameters: dict) -> dict:
    msg = json.dumps({"version": 1, "origin": {"name": "omniaxis-tests", "module": "logtest"},
                      "command": command, "parameters": parameters}).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCKET)
        s.sendall(struct.pack("<I", len(msg)) + msg)
        size = struct.unpack("<I", s.recv(4, socket.MSG_WAITALL))[0]
        buf = b""
        while len(buf) < size:
            chunk = s.recv(size - len(buf))
            if not chunk:
                break
            buf += chunk
    reply = json.loads(buf)
    if reply.get("error"):
        raise RuntimeError(f"logtest error: {reply}")
    return reply["data"]


def dotted(obj: dict, path: str):
    # The JSON decoder keeps nested objects nested in the alert's data.
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def run_case(case: dict) -> list[str]:
    token = None
    output = None
    for ev in case["events"]:
        for _ in range(ev.get("repeat", 1)):
            params = {"event": ev["log"], "log_format": "syslog", "location": ev["location"]}
            if token:
                params["token"] = token
            data = call("log_processing", params)
            token = data.get("token", token)
            output = data["output"]
    if token:
        try:
            call("remove_session", {"token": token})
        except RuntimeError:
            pass

    errors = []
    exp = case["expect"]
    rule = output.get("rule", {})
    rid = str(rule.get("id", ""))
    if "rule_id" in exp and rid != exp["rule_id"]:
        errors.append(f"rule_id {rid!r} != {exp['rule_id']!r} ({rule.get('description')})")
    if "rule_id_not_prefix" in exp and rid.startswith(exp["rule_id_not_prefix"]):
        errors.append(f"rule_id {rid!r} must not start with {exp['rule_id_not_prefix']!r}")
    if "level" in exp and rule.get("level") != exp["level"]:
        errors.append(f"level {rule.get('level')!r} != {exp['level']!r}")
    for g in exp.get("groups", []):
        if g not in rule.get("groups", []):
            errors.append(f"group {g!r} missing from {rule.get('groups')}")
    for path, want in exp.get("data", {}).items():
        got = dotted(output.get("data", {}), path)
        if got != want:
            errors.append(f"data.{path} {got!r} != {want!r}")
    if exp.get("alert") is not None and bool(data_alert(output)) != exp["alert"]:
        errors.append(f"alert flag mismatch: rule level {rule.get('level')}")
    return errors


def data_alert(output: dict) -> bool:
    return output.get("rule", {}).get("level", 0) > 0


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).parent / "fixtures")
    cases = []
    for f in sorted(root.glob("*.json")):
        for case in json.loads(f.read_text()):
            case["_file"] = f.name
            cases.append(case)
    failed = 0
    for case in cases:
        try:
            errors = run_case(case)
        except Exception as exc:  # noqa: BLE001 - report and continue
            errors = [f"exception: {exc}"]
        status = "ok  " if not errors else "FAIL"
        print(f"{status} {case['_file']}: {case['name']}")
        for e in errors:
            print(f"       {e}")
        failed += bool(errors)
    print(f"\n{len(cases) - failed}/{len(cases)} passed")
    return 1 if failed or not cases else 0


if __name__ == "__main__":
    sys.exit(main())
