"""Fixed D0 proposal constraints, never a claim of live adapter conformance."""

from copy import deepcopy

from ..qualification.automation import canonical_digest

# These are implementation candidate requirements. A live Runtime must still
# provide its independently qualified descriptor before any Task composition.
_PROFILES = {
    "langgraph": {
        "protocols": ["openai_chat_completions", "openai_responses"],
        "minimum_capabilities": ["text", "structured_output"],
        "allowed_capabilities": ["text", "structured_output", "reasoning", "streaming"],
    },
    "hermes": {
        "protocols": ["openai_chat_completions", "anthropic_messages"],
        "minimum_capabilities": ["text", "structured_output", "tool_calling"],
        "allowed_capabilities": [
            "text",
            "structured_output",
            "tool_calling",
            "reasoning",
            "streaming",
            "vision",
        ],
    },
    "codex": {
        "protocols": ["openai_responses"],
        "minimum_capabilities": ["text", "structured_output", "tool_calling"],
        "allowed_capabilities": [
            "text",
            "structured_output",
            "tool_calling",
            "reasoning",
            "streaming",
            "vision",
        ],
    },
}


def proposal_profile(department_id, agent_kind, runtime_kind):
    expected = (
        "langgraph"
        if agent_kind == "department_planning"
        else ("codex" if department_id == "technology_center" else "hermes")
    )
    if (
        agent_kind not in {"department_planning", "professional"}
        or runtime_kind != expected
    ):
        raise ValueError("agent_runtime_binding_not_allowed")
    descriptor = {
        "adapter_id": f"{runtime_kind}_proposal_adapter_d0",
        "version": "0.1.0-synthetic.1",
        "runtime_kind": runtime_kind,
        **deepcopy(_PROFILES[runtime_kind]),
        "evidence_status": "synthetic_d0",
        "live_runtime_verified": False,
    }
    policy = {
        "policy_id": f"{department_id}_proposal_policy_d0",
        "version": "0.1.0-synthetic.1",
        "allowed_data_classifications": ["synthetic", "public"],
        "max_input_tokens": 20000,
        "max_output_tokens": 4000,
        "max_cost_cny": "1.00",
        "execution_grant_required": True,
    }
    return {
        "adapter": descriptor,
        "adapter_digest": canonical_digest(descriptor),
        "policy": policy,
        "policy_digest": canonical_digest(policy),
        "candidate_compatibility_only": True,
    }

