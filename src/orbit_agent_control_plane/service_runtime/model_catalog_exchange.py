"""Explicit export to the locked Architecture v0.4 draft, not a new Schema.

Candidate object versions are recorded at submission. Legacy incomplete rows
remain readable but cannot be exported by inventing identity or version data.
"""

import re
from copy import deepcopy
from datetime import timezone

from ..qualification.automation import canonical_digest

_ACCOUNT = re.compile(r"^account://[a-z0-9][a-z0-9._/-]{2,190}$")


def exchange_context(
    *,
    proposer_account_ref,
    department_owner_ref,
    definition,
    binding,
    route_digest,
    entry_digest,
    profile,
):
    return {
        "proposer_account_ref": proposer_account_ref,
        "department_owner_ref": department_owner_ref,
        "versions": {
            "definition": definition["version"],
            "binding": "0.1.0-candidate." + canonical_digest(binding)[7:19],
            "route": "0.1.0-candidate." + route_digest[7:19],
            "entry": "0.4.0-candidate." + entry_digest[7:19],
            "adapter": profile["adapter"]["version"],
            "policy": profile["policy"]["version"],
        },
        "version_scope": "immutable_internal_candidate_export_only",
    }


def export_proposal(row, *, route, entry, predecessor_export=None):
    document = row.document
    context = document.get("exchange_context")
    if not context or any(
        not isinstance(context.get(key), str) or not _ACCOUNT.fullmatch(context[key])
        for key in ["proposer_account_ref", "department_owner_ref"]
    ):
        raise ValueError("proposal_exchange_account_mapping_missing")
    submitted_at = (
        row.submitted_at.replace(tzinfo=timezone.utc)
        if row.submitted_at.tzinfo is None
        else row.submitted_at.astimezone(timezone.utc)
    )
    submitted_at_text = submitted_at.isoformat().replace("+00:00", "Z")
    if (
        document["package"].get("exchange_context_digest") != canonical_digest(context)
        or document["package"].get("submitted_at") != submitted_at_text
    ):
        raise ValueError("proposal_exchange_context_drift")
    versions = context.get("versions", {})
    if set(versions) != {
        "definition",
        "binding",
        "route",
        "entry",
        "adapter",
        "policy",
    }:
        raise ValueError("proposal_exchange_version_mapping_missing")
    definition, binding = document["agent_definition"], document["agent_binding"]
    package, profile = document["package"], document["compatibility_profile"]
    entry_subject = {
        k: v
        for k, v in entry.document.items()
        if k
        not in {
            "entry_revision_digest",
            "request_digest",
            "provider_key",
            "provider_model_id",
            "endpoint",
        }
    }
    if (
        canonical_digest(package) != row.package_digest
        or canonical_digest(definition) != row.agent_definition_digest
        or canonical_digest(binding) != row.agent_binding_digest
        or canonical_digest(route) != row.model_route_revision_digest
        or canonical_digest(entry_subject) != row.selected_catalog_entry_revision_digest
    ):
        raise ValueError("proposal_exchange_source_digest_drift")
    if (
        entry.entry_id != row.selected_catalog_entry_id
        or route["route_id"] != row.model_route_id
        or binding["agent_definition_digest"] != row.agent_definition_digest
        or binding["model_route_refs"]
        != [
            {
                "route_id": row.model_route_id,
                "revision_digest": row.model_route_revision_digest,
            }
        ]
    ):
        raise ValueError("proposal_exchange_reference_drift")
    if (
        profile["adapter_digest"] != canonical_digest(profile["adapter"])
        or profile["policy_digest"] != canonical_digest(profile["policy"])
        or route["runtime_binding"]["digest"]
        != canonical_digest(
            {
                "adapter_digest": profile["adapter_digest"],
                "agent_definition_digest": row.agent_definition_digest,
            }
        )
        or route["policy_binding"]["digest"] != profile["policy_digest"]
    ):
        raise ValueError("proposal_exchange_profile_drift")
    if (row.supersedes_package_digest is None) != (predecessor_export is None):
        raise ValueError("proposal_exchange_predecessor_missing")
    if (
        not 4 <= len(definition["identity"]) <= 160
        or not 8 <= len(definition["task_scope"]) <= 500
        or not 8 <= len("；".join(definition["prohibited_actions"])) <= 500
    ):
        raise ValueError("proposal_exchange_scope_not_representable")

    def ref(key, identifier, digest):
        return {"id": identifier, "version": versions[key], "digest": digest}

    supersedes = (
        None
        if predecessor_export is None
        else {
            "id": predecessor_export["metadata"]["proposal_id"],
            "version": predecessor_export["metadata"]["version"],
            "digest": predecessor_export["spec"]["package_digest"],
        }
    )
    policy = profile["policy"]
    value = {
        "api_version": "company-ai-os/v1alpha4-draft",
        "kind": "DepartmentAgentProposalPackage",
        "metadata": {
            "proposal_id": row.proposal_id,
            "version": f"0.4.0-candidate.{row.revision}",
            "revision": row.revision,
            "department_id": row.department_id,
            "proposer_account_ref": context["proposer_account_ref"],
            "department_owner_ref": context["department_owner_ref"],
            "submitted_at": submitted_at_text,
            "evidence_status": "synthetic_d0",
            "synthetic_only": True,
        },
        "spec": {
            "agent_identity": definition["identity"],
            "task_scope_summary": definition["task_scope"],
            "prohibited_scope_summary": "；".join(definition["prohibited_actions"]),
            "agent_definition_ref": ref(
                "definition", definition["agent_id"], row.agent_definition_digest
            ),
            "model_requirements": {
                "required_capabilities": definition["model_requirements"][
                    "capabilities"
                ],
                "allowed_data_classifications": definition["model_requirements"][
                    "data_classifications"
                ],
                "max_input_tokens": policy["max_input_tokens"],
                "max_output_tokens": policy["max_output_tokens"],
                "budget_policy_ref": binding["policy_binding"]["ref"],
            },
            "selected_catalog_entry_ref": ref(
                "entry",
                row.selected_catalog_entry_id,
                row.selected_catalog_entry_revision_digest,
            ),
            "generated_model_route_ref": ref(
                "route", row.model_route_id, row.model_route_revision_digest
            ),
            "generated_agent_binding_ref": ref(
                "binding", binding["binding_id"], row.agent_binding_digest
            ),
            "runtime_adapter_ref": ref(
                "adapter", profile["adapter"]["adapter_id"], profile["adapter_digest"]
            ),
            "policy_binding_ref": ref(
                "policy", policy["policy_id"], profile["policy_digest"]
            ),
            "generation_inputs_digest": canonical_digest(
                {
                    "source_package_digest": row.package_digest,
                    "request_digest": row.request_digest,
                    "exchange_context": context,
                }
            ),
            "supersedes": supersedes,
            "review_requirements": {
                "model_route_approval_required": True,
                "agent_activation_required": True,
                "company_may_change_selected_model": False,
                "new_revision_required_for_model_change": True,
                "execution_grant_required_per_task": True,
            },
        },
        "authority_boundary": {
            key: False
            for key in [
                "formal_registration_applied",
                "model_route_approved",
                "agent_activated",
                "execution_grant_issued",
                "runtime_composition_created",
                "worker_lease_issued",
                "runtime_started",
                "model_called",
                "production_authorized",
                "release_authorization",
            ]
        },
    }
    value["spec"]["package_digest"] = canonical_digest(value)
    return deepcopy(value)

