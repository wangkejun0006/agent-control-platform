"""Fixed offline worker. Reads only the adjacent fictional fixture; no model."""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path


def main() -> None:
    task_id, scenario = sys.argv[1:]
    if scenario not in {
        "success",
        "wrong_task",
        "duplicate_json",
        "bad_quality",
        "timeout",
        "cancel",
        "output_limit",
    }:
        raise ValueError("unknown_scenario")
    if scenario in {"timeout", "cancel"}:
        time.sleep(30)
    if scenario == "output_limit":
        print("x" * 20000)
        return
    raw = (Path(__file__).parent / "fixtures/catalog.json").read_bytes()
    fixture = json.loads(raw)
    rows = {item["id"]: item["records"] for item in fixture["collections"]}
    artifact = {
        "collections": len(rows),
        "records": sum(map(len, rows.values())),
        "out_of_stock": sorted(
            item["id"] for item in rows["catalog"] if item["stock"] == 0
        ),
        "open_support": sum(item["status"] == "open" for item in rows["support"]),
        "shipment_units": sum(item["units"] for item in rows["shipments"]),
        "revision": fixture["revision"],
    }
    if scenario == "bad_quality":
        artifact["records"] = 900
    doc = {
        "schema_version": "orbit.offline-receipt/1",
        "task_id": task_id,
        "fixture_sha256": hashlib.sha256(raw).hexdigest(),
        "artifact": artifact,
        "model_calls": 0,
        "cost_cny": "0",
        "external_side_effects": [],
    }
    if scenario == "wrong_task":
        doc["task_id"] = "task_synthetic_other"
    if scenario == "duplicate_json":
        print(json.dumps(doc)[:-1] + ',"task_id":"task_synthetic_other"}')
    else:
        print(json.dumps(doc, sort_keys=True))


if __name__ == "__main__":
    main()
