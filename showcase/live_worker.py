"""Credential-free, bounded fictional tools; no network or arbitrary paths."""

import json
import os
import sys
from pathlib import Path


def execute(name, arguments):
    fixture = json.loads((Path(__file__).parent / "fixtures/catalog.json").read_text())
    collections = {item["id"]: item["records"] for item in fixture["collections"]}
    if name == "query_fixture":
        return {"revision": fixture["revision"], "collections": collections}
    if name == "compute_metrics":
        return {
            "low_stock": [r["id"] for r in collections["catalog"] if r["stock"] == 0],
            "open_support": sum(r["status"] == "open" for r in collections["support"]),
            "shipment_units": sum(r["units"] for r in collections["shipments"]),
        }
    if name == "submit_candidate":
        return {
            "status": "awaiting_review",
            "candidate": arguments,
            "external_publication": False,
        }
    raise ValueError("operation_not_allowed")


if __name__ == "__main__":
    result = execute(sys.argv[1], json.loads(sys.argv[2]))
    print(
        json.dumps(
            {
                "result": result,
                "pid": os.getpid(),
                "credential_environment_present": any(
                    "KEY" in k or "TOKEN" in k for k in os.environ
                ),
            },
            ensure_ascii=False,
        )
    )
