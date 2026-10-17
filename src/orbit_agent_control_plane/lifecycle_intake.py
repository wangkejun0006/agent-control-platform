"""Generic lifecycle intake for verified external registration and evaluation.

The import is deliberately synthetic and local.  A verified registration
record, selected immutable Agent Release, and Company EvaluationReport remain
separate inputs with separate approval scopes.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .lifecycle import AgentCandidate, LifecycleError, LifecycleEvaluation
from .registration import (
    _COMMON_SCHEMA_ID,
    DEFAULT_APPROVAL_LOCK,
    DEFAULT_COMPANY_LOCK,
    DEFAULT_CONTRACT_BUNDLE,
    RegistrationError,
    SyntheticAgentRegistrationLedger,
    VerifiedRegistrationHandoff,
    _digest,
    _load_json_bytes,
    _load_strict_yaml_bytes,
    _load_verified_company_schemas,
    _read_safe_file,
    _safe_relative_path,
    _SchemaValidator,
    verify_registration_handoff,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_IMPORT_PROFILE = (
    _REPO_ROOT / "references" / "agent-lifecycle-import-profile.json"
)
_RELEASE_SCHEMA_ID = "urn:company-ai-os:schema:agent-release-manifest:0.1"
_EVALUATION_SCHEMA_ID = "urn:company-ai-os:schema:evaluation-report:0.1"


@dataclass(frozen=True)
class VerifiedAgentRelease:
    release_id: str
    agent_id: str
    version: str
    release_digest: str
    runtime_family: str
    runtime_realization_refs: tuple[str, ...]
    required_evidence_refs: tuple[str, ...]
    document: Mapping[str, Any]


@dataclass(frozen=True)
class ImportedLifecycleCandidate:
    registration: VerifiedRegistrationHandoff
    release: VerifiedAgentRelease
    candidate: AgentCandidate


def import_lifecycle_candidate(
    source_root: Path | str,
    handoff_manifest: Path | str,
    registration_ledger_path: Path | str,
    release_manifest: Path | str,
    *,
    release_root: Path | str | None = None,
    approval_lock_path: Path | str = DEFAULT_APPROVAL_LOCK,
    import_profile_path: Path | str = DEFAULT_IMPORT_PROFILE,
    company_lock_path: Path | str = DEFAULT_COMPANY_LOCK,
    contract_bundle_root: Path | str = DEFAULT_CONTRACT_BUNDLE,
) -> ImportedLifecycleCandidate:
    try:
        registration = verify_registration_handoff(
            source_root,
            handoff_manifest,
            approval_lock_path=approval_lock_path,
            company_lock_path=company_lock_path,
            contract_bundle_root=contract_bundle_root,
        )
        registration_replay = SyntheticAgentRegistrationLedger(
            registration_ledger_path
        ).replay()
    except RegistrationError as error:
        raise LifecycleError(error.reason_code, "registration import failed closed") from error
    matches = tuple(
        item
        for item in registration_replay.registrations
        if item["handoff_id"] == registration.handoff_id
        and item["handoff_digest"] == registration.handoff_digest
        and item["candidate_digest"] == registration.candidate_digest
    )
    if len(matches) != 1:
        raise LifecycleError(
            "registration_record_missing",
            "exact verified registration record is unavailable",
        )
    registration_record = matches[0]
    if (
        registration_record["registration_status"] != "draft"
        or registration_record["formal_registry_record_exists"] is not False
        or registration_record["activation_authorized"] is not False
        or registration_record["active"] is not False
    ):
        raise LifecycleError(
            "registration_scope_invalid",
            "registration record exceeds the draft synthetic boundary",
        )

    profile = _load_import_profile(Path(import_profile_path))
    mapping = _resolve_system_mapping(profile, registration.hierarchy_node_ref)
    release = load_verified_agent_release(
        source_root if release_root is None else release_root,
        release_manifest,
        registration,
        required_evidence_refs=tuple(mapping["required_release_evidence_refs"]),
        company_lock_path=company_lock_path,
        contract_bundle_root=contract_bundle_root,
    )
    change = profile["change_classification"]
    candidate = AgentCandidate(
        agent_id=registration.agent_id,
        release_digest=release.release_digest,
        definition_ref=registration.definition_ref,
        binding_ref=registration.binding_ref,
        owner_role_ref=registration.owner_role_ref,
        agent_system_ref=mapping["agent_system_ref"],
        change_fields=tuple(change["change_fields"]),
        structural_change=change["structural_change"],
    )
    return ImportedLifecycleCandidate(registration, release, candidate)


def load_verified_agent_release(
    source_root: Path | str,
    release_manifest: Path | str,
    registration: VerifiedRegistrationHandoff,
    *,
    required_evidence_refs: tuple[str, ...],
    company_lock_path: Path | str = DEFAULT_COMPANY_LOCK,
    contract_bundle_root: Path | str = DEFAULT_CONTRACT_BUNDLE,
) -> VerifiedAgentRelease:
    root = Path(source_root)
    relative = _safe_relative_path(release_manifest, "Agent Release Manifest")
    source = _read_safe_file(root, relative)
    release = _load_strict_yaml_bytes(source)
    schemas, _, _ = _load_verified_company_schemas(
        Path(company_lock_path),
        Path(contract_bundle_root),
        {_COMMON_SCHEMA_ID, _RELEASE_SCHEMA_ID},
    )
    _SchemaValidator(schemas).validate(release, _RELEASE_SCHEMA_ID)
    metadata = release["metadata"]
    spec = release["spec"]
    if (
        metadata["agent_id"] != registration.agent_id
        or metadata["version"] != registration.agent_version
        or metadata["status"] != "evaluation"
        or metadata["evidence_status"] != "synthetic"
        or metadata["synthetic_only"] is not True
    ):
        raise LifecycleError(
            "release_registration_mismatch",
            "Agent Release does not match the synthetic registration",
        )
    if spec["registry_ref"] != {
        "id": registration.registry_record_ref,
        "schema_version": "0.3",
        "digest": registration.registry_record_digest,
    }:
        raise LifecycleError(
            "release_registry_reference_mismatch",
            "Agent Release Registry reference differs from registration",
        )
    if spec["definition_ref"] != {
        "id": registration.definition_ref,
        "version": registration.agent_version,
        "digest": registration.definition_digest,
    } or spec["binding_refs"] != [
        {
            "id": registration.binding_ref,
            "version": registration.agent_version,
            "digest": registration.binding_digest,
        }
    ]:
        raise LifecycleError(
            "release_candidate_reference_mismatch",
            "Agent Release Definition or Binding differs from registration",
        )
    template_refs = spec["template_refs"]
    if {
        "id": registration.template_ref,
        "version": registration.agent_version,
        "digest": registration.template_digest,
    } not in template_refs:
        raise LifecycleError(
            "release_template_reference_mismatch",
            "Agent Release does not bind the reviewed template",
        )
    runtime = spec["runtime_selection"]
    if (
        runtime["status"] != "selected"
        or not runtime["selected_runtime_family"]
        or not runtime["selected_realization_refs"]
        or not runtime["decision_ref"]
        or spec["model_selection"]["status"] != "not_required"
        or spec["model_route_refs"]
        or spec["model_selection"]["selected_route_refs"]
        or spec["model_selection"]["decision_ref"] is not None
    ):
        raise LifecycleError(
            "release_runtime_gate_incomplete",
            "Agent Release lacks a selected no-model synthetic Runtime",
        )
    release_evidence = spec["release_gate"]["required_evidence_refs"]
    if not set(required_evidence_refs).issubset(release_evidence):
        raise LifecycleError(
            "release_evidence_missing",
            "Agent Release lacks required lifecycle evidence",
        )
    if spec["release_gate"]["approval_decision_refs"]:
        raise LifecycleError(
            "release_activation_approval_embedded",
            "pre-activation Agent Release must not embed activation approval",
        )
    return VerifiedAgentRelease(
        release_id=metadata["release_id"],
        agent_id=metadata["agent_id"],
        version=metadata["version"],
        release_digest=_digest(source),
        runtime_family=runtime["selected_runtime_family"],
        runtime_realization_refs=tuple(
            item["id"] for item in runtime["selected_realization_refs"]
        ),
        required_evidence_refs=tuple(release_evidence),
        document=release,
    )


def load_company_lifecycle_evaluation(
    source_root: Path | str,
    evaluation_report: Path | str,
    release_manifest: Path | str,
    candidate: AgentCandidate,
    *,
    release_root: Path | str | None = None,
    company_lock_path: Path | str = DEFAULT_COMPANY_LOCK,
    contract_bundle_root: Path | str = DEFAULT_CONTRACT_BUNDLE,
) -> LifecycleEvaluation:
    root = Path(source_root)
    release_source_root = root if release_root is None else Path(release_root)
    release_source = _read_safe_file(
        release_source_root,
        _safe_relative_path(release_manifest, "Agent Release Manifest"),
    )
    release = _load_strict_yaml_bytes(release_source)
    if _digest(release_source) != candidate.release_digest:
        raise LifecycleError(
            "evaluation_release_bytes_mismatch",
            "Evaluation release bytes differ from lifecycle candidate",
        )
    report_source = _read_safe_file(
        root, _safe_relative_path(evaluation_report, "Company EvaluationReport")
    )
    report = _load_strict_yaml_bytes(report_source)
    schemas, _, _ = _load_verified_company_schemas(
        Path(company_lock_path),
        Path(contract_bundle_root),
        {_COMMON_SCHEMA_ID, _EVALUATION_SCHEMA_ID},
    )
    _SchemaValidator(schemas).validate(report, _EVALUATION_SCHEMA_ID)
    metadata = report["metadata"]
    spec = report["spec"]
    if (
        metadata["status"] != "final"
        or metadata["evidence_status"] != "synthetic"
        or metadata["synthetic_only"] is not True
        or spec["subject"]
        != {
            "kind": "agent_release",
            "id": release["metadata"]["release_id"],
            "version": release["metadata"]["version"],
            "digest": candidate.release_digest,
        }
        or spec["release_authorization"] is not False
    ):
        raise LifecycleError(
            "evaluation_subject_mismatch",
            "EvaluationReport is not final synthetic evidence for the exact release",
        )
    evidence_refs = tuple(
        dict.fromkeys(
            [item["id"] for item in spec["suite_refs"]]
            + list(spec["case_refs"])
            + [item["evidence_ref"] for item in spec["metrics"]]
            + list(spec["audit_event_refs"])
        )
    )
    return LifecycleEvaluation(
        report_id=metadata["report_id"],
        subject_agent_id=candidate.agent_id,
        subject_release_digest=candidate.release_digest,
        evaluator_agent_id=spec["evaluator"]["agent_ref"]["id"],
        verdict=spec["verdict"],
        release_recommendation=spec["release_recommendation"],
        evidence_refs=evidence_refs,
        risk_flags=tuple(spec["risk_flags"]),
        release_authorization=False,
    )


def _load_import_profile(path: Path) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise LifecycleError("import_profile_invalid", "lifecycle import profile is invalid")
    try:
        profile = _load_json_bytes(path.read_bytes(), "lifecycle import profile")
    except RegistrationError as error:
        raise LifecycleError(error.reason_code, "lifecycle import profile failed closed") from error
    if (
        set(profile)
        != {
            "profile_version",
            "evidence_status",
            "company_authoritative",
            "system_mappings",
            "change_classification",
            "boundary",
        }
        or profile["profile_version"]
        != "orbit.synthetic-agent-lifecycle-import-profile/1"
        or profile["evidence_status"] != "synthetic"
        or profile["company_authoritative"] is not False
        or profile["change_classification"]
        != {
            "change_fields": ["new_stable_agent", "purpose", "runtime"],
            "structural_change": True,
        }
        or profile["boundary"]
        != {
            "registration_record_required": True,
            "selected_runtime_required": True,
            "synthetic_only": True,
            "activation_authorized": False,
        }
        or not isinstance(profile["system_mappings"], list)
    ):
        raise LifecycleError(
            "import_profile_invalid", "lifecycle import profile boundary differs"
        )
    return profile


def _resolve_system_mapping(
    profile: Mapping[str, Any], hierarchy_node_ref: str
) -> Mapping[str, Any]:
    matches = []
    for value in profile["system_mappings"]:
        if not isinstance(value, dict) or set(value) != {
            "hierarchy_node_ref",
            "agent_system_ref",
            "required_release_evidence_refs",
        }:
            raise LifecycleError(
                "import_profile_invalid", "lifecycle system mapping is invalid"
            )
        if (
            not isinstance(value["required_release_evidence_refs"], list)
            or not value["required_release_evidence_refs"]
            or not all(
                isinstance(item, str) and item
                for item in value["required_release_evidence_refs"]
            )
        ):
            raise LifecycleError(
                "import_profile_invalid", "required release evidence is invalid"
            )
        if value["hierarchy_node_ref"] == hierarchy_node_ref:
            matches.append(value)
    if len(matches) != 1:
        raise LifecycleError(
            "agent_system_mapping_missing",
            "registration hierarchy has no unique Agent System mapping",
        )
    return matches[0]

