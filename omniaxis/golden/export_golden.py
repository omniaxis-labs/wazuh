#!/usr/bin/env python3
"""Export the planted scenarios as the SCDC agents' golden set.

Runs inside a Wazuh 4.14.9 manager (see test_export.sh) with the SCDC
decoder and rules loaded, and feeds each scenario's log lines through the
logtest socket, one fresh session per scenario so frequency rules start from
zero. Every event Wazuh raises an alert for (rule level above 0) goes into the
scenario's bundle in alert shape; the highest-level one (the last on a tie)
is the alert the agent is shown. A scenario that raises no alert at all is an
error: it would test nothing.

    export_golden.py <set_version> <out.json> [--report]

The output is what the admin portal imports with `pnpm golden:import`.
"""
from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "ruleset" / "tests"))

from run_logtest import call  # noqa: E402  (the existing fixtures' socket client)
from scenarios import SCENARIOS  # noqa: E402

BASE_EPOCH = 1794186000  # 2026-11-10T01:00:00Z, so ids and times are stable


def to_alert(output: dict, item_no: int, seq: int, location: str) -> dict:
    rule = output.get("rule", {})
    alert = {
        "id": f"{BASE_EPOCH + item_no}.{seq}",
        "timestamp": f"2026-11-10T01:00:{seq % 60:02d}.000+0000",
        "rule": {k: rule[k] for k in ("id", "level", "description", "groups", "mitre", "firedtimes") if k in rule},
        "agent": {"id": "000", "name": "scdc-wazuh"},
        "manager": {"name": "scdc-wazuh"},
        "decoder": output.get("decoder", {}),
        "location": location,
        "full_log": output.get("full_log", ""),
    }
    if output.get("data"):
        alert["data"] = output["data"]
    return alert


def run(scenario: dict, item_no: int) -> dict:
    token = None
    bundle = []
    for seq, (location, log) in enumerate(scenario["events"]):
        params = {"event": log, "log_format": "syslog", "location": location}
        if token:
            params["token"] = token
        data = call("log_processing", params)
        token = data.get("token", token)
        out = data["output"]
        if out.get("rule", {}).get("level", 0) > 0:
            bundle.append(to_alert(out, item_no, seq, location))
    if token:
        try:
            call("remove_session", {"token": token})
        except RuntimeError:
            pass
    if not bundle:
        return {"id": scenario["id"], "silent": True}
    shown = max(enumerate(bundle), key=lambda p: (p[1]["rule"].get("level", 0), p[0]))[1]
    return {
        "id": scenario["id"],
        "scenario": scenario["scenario"],
        "alert_class": scenario["alert_class"],
        "label": scenario["label"],
        "injection": scenario["injection"],
        "alert": shown,
        "bundle": bundle,
    }


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    set_version, out = argv[0], pathlib.Path(argv[1])
    results = [run(s, n) for n, s in enumerate(SCENARIOS)]
    silent = [r["id"] for r in results if r.get("silent")]
    if silent:
        # Wazuh raised nothing for these: they test nothing, and say where the sensor is blind.
        raise SystemExit("no alert raised for: " + ", ".join(silent))
    items = results
    ids = [i["id"] for i in items]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate scenario ids")
    out.write_text(json.dumps({
        "set_version": set_version,
        "generated_by": "omniaxis/golden/export_golden.py on wazuh-manager 4.14.9",
        "items": items,
    }, indent=1) + "\n")
    if "--report" in argv:
        for i in items:
            r = i["alert"]["rule"]
            print(f"{i['label']:9} {i['alert_class']:22} {i['id']:34} {r.get('id'):>6} L{r.get('level'):<2} {len(i['bundle']):>2} alerts  {r.get('description')}")
    print(f"{len(items)} items written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
