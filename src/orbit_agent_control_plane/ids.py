"""Deterministic identifiers; no timestamps or random state."""

from __future__ import annotations

from hashlib import sha256


COMPANY_TASK_ROUTER_AGENT_ID = "agt_company_task_router_syn"
COMPANY_EVALUATOR_AGENT_ID = "agt_evaluator_syn"
LIFECYCLE_ASSURANCE_AGENT_ID = "agt_orbit_agent_lifecycle_assurance_syn"
SYNTHETIC_WORKER_ID = "worker_company_d0_echo_syn"


def deterministic_id(prefix: str, *parts: str) -> str:
    material = "\x1f".join(parts).encode("utf-8")
    return f"{prefix}_{sha256(material).hexdigest()[:20]}"

