"""Department cockpit planning service with a fail-closed runtime boundary.

The service owns D0 planning projections and synthetic acceptance fixtures.  It
does not treat LangGraph checkpoints or professional runtime state as Company Task authority, does not
resolve model/provider secrets for the browser, and never accepts host paths as
inputs.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import re
import sqlite3
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.constants import END, START
from langgraph.graph import StateGraph
from langgraph.types import Command, interrupt
from sqlalchemy import select

from .control_console_models import ModelRouteDecisionRow, ModelRouteRetirementRow
from .controlled_artifacts import ControlledArtifactError, ControlledArtifactStore
from .database import Database
from .model_catalog import ModelCatalogError, ModelCatalogService
from .model_catalog_models import DepartmentAgentProposalRow
from .models import (
    AuditEventRow,
    DepartmentCockpitObjectRow,
    GrantRevocationRow,
    ModelRouteRevisionRow,
    ModelRouteSnapshotRow,
    PlanningCommandRow,
    PlanningInvocationEvidenceRow,
    PlanningSessionAuthorityRow,
    PlanningTurnRow,
    ReceiptRow,
)
from .runtime_artifact_models import (
    DepartmentTaskDecisionRow,
    RuntimeArtifactImportReceiptRow,
    RuntimeArtifactRevisionRow,
    RuntimeArtifactRevocationRow,
    RuntimeNodeCapabilityReportRow,
)
from .runtime_artifacts import (
    runtime_artifact_qualification_receipt_matches,
    runtime_artifact_subject_ref,
)


class DepartmentCockpitError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


_DEPARTMENT = re.compile(r"^(product|technology|market)_center$")
_SAFE_ID = re.compile(r"^[a-z][a-z0-9_-]{2,127}$")
_RUN_ID = re.compile(r"^run_[A-Za-z0-9_:-]{3,120}$")
_SESSION_ID = re.compile(r"^session_[A-Za-z0-9_:-]{3,120}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9._:-]{8,192}$")
_LOGICAL_ARTIFACT = re.compile(r"^artifact://[a-zA-Z0-9._:/-]{3,220}$")
_CONTEXT_TAG = re.compile(r"^[\w\u4e00-\u9fff -]{1,24}$")
_MAX_TEXT = 4000
_MAX_PLANNING_ROUNDS = 3
_MAX_PLANNING_MODEL_CALLS = 4
_MAX_PLANNING_COST_CNY_MICROS = 10_000_000
_FAIL_CLOSED_PLANNING_REASONS = frozenset(
    {
        "planning_route_revision_unavailable",
        "planning_route_revision_not_eligible",
        "planning_route_agent_incompatible",
        "planning_model_call_limit_exceeded",
        "planning_budget_exceeded",
        "planning_model_structure_invalid",
        "planning_live_model_not_enabled",
        "planning_model_route_mismatch",
        "planning_returned_model_missing",
        "planning_returned_model_mismatch",
        "planning_model_usage_invalid",
        "planning_question_structure_invalid",
        "planning_package_structure_invalid",
        "planning_package_required_section_missing",
        "planning_package_validation_failed",
    }
)
_PROMPT_INJECTION = re.compile(
    r"(?:ignore\s+(?:all\s+)?previous|system\s+prompt|developer\s+message|"
    r"忽略(?:以上|前述|系统)|系统提示词|泄露(?:密钥|凭据))",
    re.IGNORECASE,
)
_SENSITIVE_EVIDENCE = re.compile(
    r"(?:BEGIN .*PRIVATE KEY|\bsk-[A-Za-z0-9_-]{8,}|\bBearer\s+[A-Za-z0-9._~-]{8,})",
    re.IGNORECASE,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _stable_id(prefix: str, value: Mapping[str, Any]) -> str:
    return f"{prefix}_{hashlib.sha256(_canonical(value)).hexdigest()[:20]}"


def _clean_text(value: Any, *, reason_code: str) -> str:
    if not isinstance(value, str):
        raise DepartmentCockpitError(reason_code)
    cleaned = " ".join(value.split())
    if not cleaned or len(cleaned) > _MAX_TEXT or "\x00" in value:
        raise DepartmentCockpitError(reason_code)
    return cleaned


@dataclass(frozen=True)
class PlanningRuntimeBinding:
    department_id: str
    planning_agent_ref: str
    agent_definition_ref: str
    graph_ref: str
    checkpoint_namespace: str
    route_alias: str
    runtime_revision: str
    adapter_revision: str
    evidence_status: str = "architecture_reference"
    synthetic_only: bool = True
    production_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            not _DEPARTMENT.fullmatch(self.department_id)
            or not all(
                isinstance(value, str) and value
                for value in (
                    self.planning_agent_ref,
                    self.agent_definition_ref,
                    self.graph_ref,
                    self.checkpoint_namespace,
                    self.route_alias,
                    self.runtime_revision,
                    self.adapter_revision,
                )
            )
            or self.evidence_status
            not in {"architecture_reference", "synthetic", "verified_runtime"}
            or type(self.synthetic_only) is not bool
            or self.production_authorized is not False
        ):
            raise DepartmentCockpitError("planning_runtime_binding_invalid")
        if not _SAFE_ID.fullmatch(self.checkpoint_namespace.replace("/", "_")):
            raise DepartmentCockpitError("planning_checkpoint_namespace_invalid")

    def public_summary(self) -> dict[str, Any]:
        return {
            "planning_agent_ref": self.planning_agent_ref,
            "agent_definition_ref": self.agent_definition_ref,
            "runtime_kind": "langgraph",
            "graph_ref": self.graph_ref,
            "checkpoint_namespace": self.checkpoint_namespace,
            "route_alias": self.route_alias,
            "runtime_revision": self.runtime_revision,
            "adapter_revision": self.adapter_revision,
            "evidence_status": self.evidence_status,
            "synthetic_only": self.synthetic_only,
            "production_authorized": False,
        }


@dataclass(frozen=True)
class ProfessionalRuntimeBinding:
    department_id: str
    professional_agent_ref: str
    agent_definition_ref: str
    runtime_kind: str
    runtime_revision: str
    adapter_revision: str
    qualification_status: str
    availability: str

    def __post_init__(self) -> None:
        if (
            not _DEPARTMENT.fullmatch(self.department_id)
            or self.runtime_kind not in {"hermes", "codex"}
            or self.qualification_status != "unverified_runtime"
            or self.availability != "d0_synthetic_fixture_available"
            or not all(
                isinstance(value, str) and value
                for value in (
                    self.professional_agent_ref,
                    self.agent_definition_ref,
                    self.runtime_revision,
                    self.adapter_revision,
                )
            )
        ):
            raise DepartmentCockpitError("professional_runtime_binding_invalid")

    def public_summary(self) -> dict[str, Any]:
        return {
            "professional_agent_ref": self.professional_agent_ref,
            "agent_definition_ref": self.agent_definition_ref,
            "runtime_kind": self.runtime_kind,
            "runtime_revision": self.runtime_revision,
            "adapter_revision": self.adapter_revision,
            "qualification_status": self.qualification_status,
            "availability": self.availability,
            "live_execution_enabled": False,
            "production_authorized": False,
        }


class PlanningRuntimeTransport(Protocol):
    def health(self, *, binding: PlanningRuntimeBinding) -> Mapping[str, Any]: ...

    def start(
        self,
        *,
        binding: PlanningRuntimeBinding,
        session_id: str,
        message: str,
        artifact_refs: Sequence[str],
        idempotency_key: str,
    ) -> Mapping[str, Any]: ...

    def resume(
        self,
        *,
        binding: PlanningRuntimeBinding,
        run_id: str,
        answers: Mapping[str, str],
        supplement: str | None,
        continue_clarification: bool = False,
    ) -> Mapping[str, Any]: ...

    def status(
        self, *, binding: PlanningRuntimeBinding, run_id: str
    ) -> Mapping[str, Any]: ...

    def events(
        self,
        *,
        binding: PlanningRuntimeBinding,
        run_id: str,
        after_sequence: int,
    ) -> Sequence[Mapping[str, Any]]: ...

    def stop(self, *, binding: PlanningRuntimeBinding, run_id: str) -> None: ...


class CompanyModelRouteCatalog(Protocol):
    """Sanitized company Registry view consumed by the department cockpit."""

    def routes(self, *, department_id: str) -> Sequence[Mapping[str, Any]]: ...


class PlanningModelTransportError(RuntimeError):
    """Retryable transport failure before a valid structured response exists."""


class PlanningModelPort(Protocol):
    """Strict, non-streaming planning-model boundary."""

    def invoke(
        self,
        *,
        stage: str,
        route_id: str,
        route_revision_digest: str,
        grant_id: str,
        payload: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...


class DeterministicPlanningModelPort:
    """Deterministic fake Provider used by default in D0 and automated tests."""

    def invoke(
        self,
        *,
        stage: str,
        route_id: str,
        route_revision_digest: str,
        grant_id: str,
        payload: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        del route_id, grant_id
        round_number = int(payload.get("round_number", 1))
        department_id = str(payload["department_id"])
        strict_workflow = bool(payload.get("strict_workflow", False))
        if stage == "generate_questions":
            output: dict[str, Any] = {
                "result_kind": "questions",
                "questions": _workflow_questions(
                    department_id, round_number, strict=strict_workflow
                ),
            }
        elif stage == "generate_task_package":
            supplement = str(payload.get("supplement") or "")
            if supplement.startswith("继续澄清：") and round_number < 3:
                output = {
                    "result_kind": "questions",
                    "questions": _workflow_questions(
                        department_id,
                        round_number + 1,
                        strict=strict_workflow,
                    ),
                }
            else:
                output = {
                    "result_kind": "task_package_candidate",
                    "candidate": _workflow_package_candidate(department_id),
                }
        else:
            raise DepartmentCockpitError("planning_model_stage_invalid")
        response_digest = canonical_digest(output)
        return {
            "output": output,
            "route_revision_digest": route_revision_digest,
            "provider_request_id": _stable_id(
                "provider_request_fake",
                {
                    "stage": stage,
                    "round_number": round_number,
                    "response_digest": response_digest,
                },
            ),
            "returned_model_id": "deterministic-fake-provider/structured-v1",
            "expected_model_id": "deterministic-fake-provider/structured-v1",
            "input_tokens": 96,
            "output_tokens": 128,
            "cost_cny_micros": 0,
            "schema_valid": True,
            "synthetic_only": True,
        }


class SqlCompanyModelRouteCatalog:
    """Project immutable ModelRoute revisions, decisions and health without secrets."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def routes(self, *, department_id: str) -> Sequence[Mapping[str, Any]]:
        _departments()[department_id]
        with self.database.session() as session:
            revisions = tuple(
                session.scalars(
                    select(ModelRouteRevisionRow).order_by(ModelRouteRevisionRow.id)
                )
            )
            decisions = tuple(
                session.scalars(
                    select(ModelRouteDecisionRow).order_by(ModelRouteDecisionRow.id)
                )
            )
            snapshots = tuple(
                session.scalars(
                    select(ModelRouteSnapshotRow).order_by(ModelRouteSnapshotRow.id)
                )
            )
            retirements = tuple(session.scalars(select(ModelRouteRetirementRow)))
            proposals = tuple(session.scalars(select(DepartmentAgentProposalRow)))
        latest: dict[str, ModelRouteRevisionRow] = {}
        for row in revisions:
            latest[row.route_id] = row
        proposed_routes = {item.model_route_id for item in proposals}
        result = []
        for row in latest.values():
            exact = [item for item in proposals
                     if item.model_route_id == row.route_id
                     and item.model_route_revision_digest == row.revision_digest]
            # A department candidate has one exact accepted owner. Global legacy
            # routes keep their existing projection; ambiguous candidates do not.
            if row.route_id in proposed_routes and (
                len(exact) != 1 or exact[0].department_id != department_id
            ):
                continue
            projected = _registered_model_route(
                row=row, decisions=decisions, snapshots=snapshots,
                retirements=retirements, observed_at=datetime.now(timezone.utc),
            )
            if exact:
                public = exact[0].document["model_route_public"]
                if (public["route_id"] != row.route_id
                        or public["revision_digest"] != row.revision_digest):
                    raise DepartmentCockpitError("agent_proposal_projection_binding_drift")
                # These display labels were already disclosed in this department's
                # immutable proposal; never copy raw provider IDs or credentials.
                projected.update(
                    model_display_name=public["model_display_name"],
                    model_version_label=public["model_version_label"],
                    display_name="申报模型路线 · " + public["model_display_name"],
                )
            result.append(projected)
        return result


class DisabledPlanningRuntimeTransport:
    """Fail-closed boundary until a planning Runtime is explicitly configured."""

    def health(self, *, binding: PlanningRuntimeBinding) -> Mapping[str, Any]:
        del binding
        return {
            "status": "unavailable",
            "reason_code": "planning_runtime_not_configured",
            "verified_runtime": False,
        }

    def start(
        self,
        *,
        binding: PlanningRuntimeBinding,
        session_id: str,
        message: str,
        artifact_refs: Sequence[str],
        idempotency_key: str,
    ) -> Mapping[str, Any]:
        del binding, session_id, message, artifact_refs, idempotency_key
        raise DepartmentCockpitError("planning_runtime_not_configured")

    def resume(
        self,
        *,
        binding: PlanningRuntimeBinding,
        run_id: str,
        answers: Mapping[str, str],
        supplement: str | None,
        continue_clarification: bool = False,
    ) -> Mapping[str, Any]:
        del binding, run_id, answers, supplement, continue_clarification
        raise DepartmentCockpitError("planning_runtime_not_configured")

    def status(
        self, *, binding: PlanningRuntimeBinding, run_id: str
    ) -> Mapping[str, Any]:
        del binding, run_id
        raise DepartmentCockpitError("planning_runtime_not_configured")

    def events(
        self,
        *,
        binding: PlanningRuntimeBinding,
        run_id: str,
        after_sequence: int,
    ) -> Sequence[Mapping[str, Any]]:
        del binding, run_id, after_sequence
        raise DepartmentCockpitError("planning_runtime_not_configured")

    def stop(self, *, binding: PlanningRuntimeBinding, run_id: str) -> None:
        del binding, run_id
        raise DepartmentCockpitError("planning_runtime_not_configured")


class LangGraphPlanningTransport:
    """Persistent D0 planning graph; it never owns Company Task authority."""

    def __init__(self, *, checkpoint_path: Path) -> None:
        if not checkpoint_path.is_absolute() or checkpoint_path.suffix != ".sqlite3":
            raise DepartmentCockpitError("planning_checkpoint_path_invalid")
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._connection = sqlite3.connect(checkpoint_path, check_same_thread=False)
        self._checkpointer = SqliteSaver(self._connection)
        builder = StateGraph(dict)
        builder.add_node("capture_input", self._capture_input)
        builder.add_node("assess_gaps", self._assess_gaps)
        builder.add_node("generate_questions", self._generate_questions)
        builder.add_node("validate_questions", self._validate_questions)
        builder.add_node("ask_clarification", self._ask_clarification)
        builder.add_node("generate_package_candidate", self._draft_package)
        builder.add_node("validate_package", self._validate_package)
        builder.add_node("normalize_package", self._normalize_package)
        builder.add_edge(START, "capture_input")
        builder.add_edge("capture_input", "assess_gaps")
        builder.add_edge("assess_gaps", "generate_questions")
        builder.add_edge("generate_questions", "validate_questions")
        builder.add_edge("validate_questions", "ask_clarification")
        builder.add_conditional_edges(
            "ask_clarification",
            self._after_clarification,
            {
                "more_questions": "generate_questions",
                "package": "generate_package_candidate",
            },
        )
        builder.add_edge("generate_package_candidate", "validate_package")
        builder.add_edge("validate_package", "normalize_package")
        builder.add_edge("normalize_package", END)
        self._graph = builder.compile(
            checkpointer=self._checkpointer,
            name="orbit_department_planning_d0",
        )
        self._lock = threading.RLock()

    @staticmethod
    def _capture_input(state: Mapping[str, Any]) -> dict[str, Any]:
        return {
            **state,
            "stage": "checking_input",
            "status": "running",
            "round_count": 0,
        }

    @staticmethod
    def _assess_gaps(state: Mapping[str, Any]) -> dict[str, Any]:
        return {**state, "stage": "assessing_gaps"}

    @staticmethod
    def _generate_questions(state: Mapping[str, Any]) -> dict[str, Any]:
        return {**state, "stage": "generating_questions", "status": "running"}

    @staticmethod
    def _validate_questions(state: Mapping[str, Any]) -> dict[str, Any]:
        return {**state, "stage": "validating_questions"}

    @staticmethod
    def _ask_clarification(state: Mapping[str, Any]) -> dict[str, Any]:
        response = interrupt(
            {
                "kind": "TaskClarificationRequest",
                "question_count": state.get("question_count", 2),
                "round_number": int(state.get("round_count", 0)) + 1,
                "task_authority_changed": False,
            }
        )
        if not isinstance(response, dict) or not isinstance(
            response.get("answers"), dict
        ):
            raise DepartmentCockpitError("planning_resume_payload_invalid")
        return {
            **state,
            "answers": dict(response["answers"]),
            "supplement": response.get("supplement"),
            "continue_clarification": bool(
                response.get("continue_clarification", False)
            ),
            "round_count": int(state.get("round_count", 0)) + 1,
            "stage": "checking_gaps",
            "status": "running",
        }

    @staticmethod
    def _after_clarification(state: Mapping[str, Any]) -> str:
        if (
            state.get("continue_clarification")
            and int(state.get("round_count", 0)) < _MAX_PLANNING_ROUNDS
        ):
            return "more_questions"
        return "package"

    @staticmethod
    def _draft_package(state: Mapping[str, Any]) -> dict[str, Any]:
        return {
            **state,
            "stage": "generating_task_package",
            "status": "running",
        }

    @staticmethod
    def _validate_package(state: Mapping[str, Any]) -> dict[str, Any]:
        return {**state, "stage": "validating_task_package"}

    @staticmethod
    def _normalize_package(state: Mapping[str, Any]) -> dict[str, Any]:
        return {**state, "stage": "awaiting_confirmation", "status": "ready"}

    def health(self, *, binding: PlanningRuntimeBinding) -> Mapping[str, Any]:
        del binding
        return {
            "status": "d0_ready",
            "runtime_kind": "langgraph",
            "runtime_revision": importlib.metadata.version("langgraph"),
            "checkpoint_store": "sqlite_d0",
            "verified_runtime": False,
            "production_authorized": False,
        }

    def start(
        self,
        *,
        binding: PlanningRuntimeBinding,
        session_id: str,
        message: str,
        artifact_refs: Sequence[str],
        idempotency_key: str,
    ) -> Mapping[str, Any]:
        seed = {
            "department_id": binding.department_id,
            "session_id": session_id,
            "message": message,
            "artifact_refs": list(artifact_refs),
            "idempotency_key": idempotency_key,
        }
        run_id = _stable_id("run_lg", seed)
        config = self._config(binding, run_id)
        with self._lock:
            existing = self._graph.get_state(config)
            if not existing.values:
                output = self._graph.invoke(
                    {
                        **seed,
                        "run_id": run_id,
                        "stage": "received",
                        "status": "running",
                    },
                    config=config,
                )
                if "__interrupt__" not in output:
                    raise DepartmentCockpitError("planning_interrupt_not_reached")
        return {
            "run_id": run_id,
            "status": "needs_input",
            "response_id": _stable_id("response_lg", seed),
        }

    def resume(
        self,
        *,
        binding: PlanningRuntimeBinding,
        run_id: str,
        answers: Mapping[str, str],
        supplement: str | None,
        continue_clarification: bool = False,
    ) -> Mapping[str, Any]:
        _validate_run_id(run_id)
        config = self._config(binding, run_id)
        with self._lock:
            snapshot = self._graph.get_state(config)
            if not snapshot.values:
                raise DepartmentCockpitError("planning_run_not_found")
            if snapshot.values.get("status") == "ready":
                return self.status(binding=binding, run_id=run_id)
            if snapshot.values.get("status") == "cancelled":
                raise DepartmentCockpitError("planning_run_cancelled")
            output = self._graph.invoke(
                Command(
                    resume={
                        "answers": dict(answers),
                        "supplement": supplement,
                        "continue_clarification": continue_clarification,
                    }
                ),
                config=config,
            )
        current = self._graph.get_state(config)
        if current.values.get("status") == "ready":
            return {
                "run_id": run_id,
                "status": "ready",
                "stage": "awaiting_confirmation",
            }
        if current.next:
            return {
                "run_id": run_id,
                "status": "needs_input",
                "stage": "awaiting_clarification",
            }
        if output.get("status") != "ready":
            raise DepartmentCockpitError("planning_runtime_resume_incomplete")
        return {
            "run_id": run_id,
            "status": "ready",
            "stage": "awaiting_confirmation",
        }

    def status(
        self, *, binding: PlanningRuntimeBinding, run_id: str
    ) -> Mapping[str, Any]:
        _validate_run_id(run_id)
        snapshot = self._graph.get_state(self._config(binding, run_id))
        if not snapshot.values:
            raise DepartmentCockpitError("planning_run_not_found")
        status = snapshot.values.get("status", "needs_input")
        if snapshot.next and status == "running":
            status = "needs_input"
        return {
            "run_id": run_id,
            "status": status,
            "stage": snapshot.values.get("stage", "unknown"),
        }

    def events(
        self,
        *,
        binding: PlanningRuntimeBinding,
        run_id: str,
        after_sequence: int,
    ) -> Sequence[Mapping[str, Any]]:
        if after_sequence < -1:
            raise DepartmentCockpitError("runtime_event_cursor_invalid")
        value = self.status(binding=binding, run_id=run_id)
        events: list[dict[str, Any]] = [
            {
                "sequence": 0,
                "event_type": "planning.question_requested",
                "status": "needs_input",
            }
        ]
        if value["status"] == "ready":
            events.append(
                {
                    "sequence": 1,
                    "event_type": "planning.package_ready",
                    "status": "awaiting_confirmation",
                }
            )
        elif value["status"] == "cancelled":
            events.append(
                {
                    "sequence": 1,
                    "event_type": "planning.stop_recorded",
                    "status": "cancelled",
                }
            )
        return tuple(event for event in events if event["sequence"] > after_sequence)

    def stop(self, *, binding: PlanningRuntimeBinding, run_id: str) -> None:
        _validate_run_id(run_id)
        config = self._config(binding, run_id)
        with self._lock:
            snapshot = self._graph.get_state(config)
            if not snapshot.values:
                raise DepartmentCockpitError("planning_run_not_found")
            self._graph.update_state(
                config,
                {**snapshot.values, "status": "cancelled", "stage": "stopped"},
            )

    def close(self) -> None:
        self._connection.close()

    @staticmethod
    def _config(
        binding: PlanningRuntimeBinding, run_id: str
    ) -> dict[str, dict[str, str]]:
        return {
            "configurable": {
                "thread_id": (
                    f"{binding.checkpoint_namespace}:{binding.department_id}:{run_id}"
                ),
            }
        }


class DepartmentCockpitService:
    def __init__(
        self,
        *,
        database: Database,
        transport: PlanningRuntimeTransport | None = None,
        model_port: PlanningModelPort | None = None,
        artifact_store: ControlledArtifactStore | None = None,
        model_route_catalog: CompanyModelRouteCatalog | None = None,
        agent_proposals: ModelCatalogService | None = None,
    ) -> None:
        self.database = database
        self.transport = transport or DisabledPlanningRuntimeTransport()
        self.model_port = model_port or DeterministicPlanningModelPort()
        self.artifact_store = artifact_store or ControlledArtifactStore(database)
        # The fixture catalog is retained for isolated legacy tests only.  The LAN
        # entrypoint injects SqlCompanyModelRouteCatalog so department pages read
        # the company Registry, decisions and health snapshots as one source.
        self.model_route_catalog = model_route_catalog
        # Legacy/catalog-backed entrypoints retain their original rollout scope.
        # The explicitly authorized delivery integration opts in the third
        # department after installing its route and contract adapters.
        self.planning_workflow_departments = frozenset({"product_center", "technology_center"})
        self.agent_proposals = agent_proposals
        self.bindings = _bindings()
        self.departments = _departments()
        self.tasks: dict[str, dict[str, Any]] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.packages: dict[str, dict[str, Any]] = {}
        self.synthetic_acceptance_runs: dict[str, dict[str, Any]] = {}
        self.model_route_selections: dict[str, dict[str, Any]] = {}
        self.agent_model_route_selections: dict[str, dict[str, Any]] = {}
        self.runtime_artifact_selections: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._restore_or_seed()

    def agent_proposal_model_catalog(
        self, *, department_id: str, model_requirements: Mapping[str, Any] | None = None, agent_kind: str = "professional", runtime_kind: str | None = None
    ) -> dict[str, Any]:
        self._binding(department_id)
        if self.agent_proposals is None:
            raise DepartmentCockpitError("agent_proposal_catalog_unavailable")
        try:
            return self.agent_proposals.proposal_catalog(
                department_id=department_id,
                model_requirements=model_requirements, agent_kind=agent_kind, runtime_kind=runtime_kind,
            )
        except ModelCatalogError as error:
            raise DepartmentCockpitError(error.reason_code) from error

    def agent_proposal_history(self, *, department_id: str):
        self._binding(department_id)
        if self.agent_proposals is None:
            raise DepartmentCockpitError('agent_proposal_catalog_unavailable')
        return self.agent_proposals.list_agent_route_reviews(department_id=department_id)

    def export_agent_proposal(self, *, department_id: str, package_digest: str):
        self._binding(department_id)
        if self.agent_proposals is None:
            raise DepartmentCockpitError('agent_proposal_catalog_unavailable')
        try:
            return self.agent_proposals.export_agent_proposal(department_id=department_id, package_digest=package_digest)
        except ModelCatalogError as error:
            raise DepartmentCockpitError(error.reason_code) from error

    def submit_agent_proposal(self, **values: Any) -> dict[str, Any]:
        department_id = str(values.get("department_id", ""))
        self._binding(department_id)
        if self.agent_proposals is None:
            raise DepartmentCockpitError("agent_proposal_catalog_unavailable")
        try:
            return self.agent_proposals.submit_agent_proposal(**values)
        except ModelCatalogError as error:
            raise DepartmentCockpitError(error.reason_code) from error

    def department_agents(self, department_id: str) -> list[dict[str, Any]]:
        """One read-only identity projection; approvals do not register a Runtime."""
        self._binding(department_id)
        agents = [{**item, "source_kind": "builtin"} for item in _agents(department_id)]
        if self.agent_proposals is not None:
            proposals = self.agent_proposals.list_agent_route_reviews(
                department_id=department_id
            )["items"]
            agents.extend(
                _proposal_agent(item, department_id=department_id)
                for item in proposals if item["is_latest"]
            )
        return agents

    def _department_agent_by_binding(
        self, department_id: str, agent_binding_ref: str
    ) -> dict[str, Any] | None:
        # Existing configured Agents do not depend on the proposal review feed.
        builtin = next((item for item in _agents(department_id)
                        if item["agent_binding_ref"] == agent_binding_ref), None)
        if builtin is not None:
            return builtin
        return next((item for item in self.department_agents(department_id)
                     if item["agent_binding_ref"] == agent_binding_ref), None)

    def bootstrap(self, *, department_id: str) -> dict[str, Any]:
        binding = self._binding(department_id)
        selection = self._agent_model_route_selection(
            department_id, _planning_agent_binding_ref(department_id)
        )
        health = dict(self.transport.health(binding=binding))
        return {
            "department": dict(self.departments[department_id]),
            "authority": {
                "task_source": "d0_company_task_store",
                "runtime_projection_authoritative": False,
                "release_authorization": False,
            },
            "service_mode": "d0_synthetic_only",
            "tasks": [
                dict(value)
                for value in self.tasks.values()
                if value["department_id"] == department_id
            ],
            "agents": self.department_agents(department_id),
            "model_routes": _legacy_routes(
                department_id,
                selected_alias=selection["route_alias"],
                routes=self._model_routes(department_id),
            ),
            "runtime": {
                **binding.public_summary(),
                "route_alias": selection["route_alias"],
                "model_route_selection_revision": selection["revision"],
                "health": health,
                "live_model_enabled": bool(getattr(self.model_port, "live_model_enabled", False)),
                "blocker_codes": [
                    "provider_key_rotation_required",
                    "budget_policy_not_configured",
                    "langgraph_runtime_not_verified",
                    "professional_runtime_not_verified",
                ],
            },
            "runtime_environment": self._runtime_environment(department_id),
            "audit_events": self._audit_events(department_id),
            "feishu_mirror": {
                "status": "not_configured",
                "affects_company_task_state": False,
            },
        }

    def create_session(
        self,
        *,
        department_id: str,
        actor_ref: str,
        message: str,
        artifact_refs: Sequence[str],
        idempotency_key: str,
        actor_name: str | None = None,
        predecessor_session_id: str | None = None,
        context_tags: Sequence[str] = (),
    ) -> dict[str, Any]:
        binding = self._binding(department_id)
        clean_message = _clean_text(message, reason_code="planning_message_invalid")
        _reject_prompt_injection(clean_message)
        refs = _artifact_refs(artifact_refs)
        tags = _context_tags(context_tags)
        try:
            artifacts = self.artifact_store.require_department_refs(
                department_id=department_id,
                artifact_refs=refs,
            )
        except ControlledArtifactError as error:
            raise DepartmentCockpitError(error.reason_code) from error
        if not _IDEMPOTENCY.fullmatch(idempotency_key):
            raise DepartmentCockpitError("planning_idempotency_key_invalid")
        if (
            self.model_route_catalog is not None
            and department_id not in self.planning_workflow_departments
        ):
            raise DepartmentCockpitError("department_planning_workflow_not_enabled")
        if (
            self.model_route_catalog is not None
            and any(item["data_classification"] != "public" for item in artifacts)
        ):
            raise DepartmentCockpitError("planning_data_classification_not_allowed")
        session_seed = {
            "department_id": department_id,
            "actor_ref": actor_ref,
            "message": clean_message,
            "idempotency_key": idempotency_key,
            "predecessor_session_id": predecessor_session_id,
            "context_tags": tags,
        }
        session_id = _stable_id("session", session_seed)
        task_id = _stable_id("task_plan", session_seed)
        planning_selection = self._agent_model_route_selection(
            department_id, _planning_agent_binding_ref(department_id)
        )
        self._planning_route(department_id, planning_selection)
        model_route_alias = planning_selection["route_alias"]
        with self._lock:
            previous = self.sessions.get(session_id)
            if previous is not None:
                return self._session_response(previous)
            run_id = _stable_id("run_pending", session_seed)
            task = _planning_task(
                department_id=department_id,
                task_id=task_id,
                title=clean_message[:42],
                actor_ref=actor_ref,
                actor_name=actor_name,
                run_id=run_id,
                model_route_alias=model_route_alias,
            )
            grant = _planning_execution_grant(
                task_id=task_id,
                department_id=department_id,
                binding=binding,
                planning_selection=planning_selection,
            )
            grant_digest = canonical_digest(grant)
            run = dict(
                self.transport.start(
                    binding=binding,
                    session_id=session_id,
                    message=clean_message,
                    artifact_refs=refs,
                    idempotency_key=idempotency_key,
                )
            )
            run_id = str(run.get("run_id", ""))
            _validate_run_id(run_id)
            task["runtime_run_ref"] = run_id
            task["task_kind"] = "planning_parent"
            task["planning_ready"] = True
            task["professional_execution_ready"] = False
            task["professional_task_ref"] = None
            task["execution_grant_ref"] = grant["metadata"]["grant_id"]
            task["agent_binding_ref"] = planning_selection["agent_binding_ref"]
            task["model_route_id"] = planning_selection["route_id"]
            task["model_route_revision_digest"] = planning_selection[
                "route_revision_digest"
            ]
            task["model_route_selection_digest"] = planning_selection[
                "selection_digest"
            ]
            task["context_tags"] = list(tags)
            if artifacts:
                task["data_classification"] = (
                    "internal_standard"
                    if any(
                        item["data_classification"] == "internal_standard"
                        for item in artifacts
                    )
                    else "public"
                )
            self.tasks[task_id] = task
            session = {
                "session_id": session_id,
                "department_id": department_id,
                "task_id": task_id,
                "run_id": run_id,
                "response_id": run.get("response_id"),
                "status": "running",
                "stage": "checking_input",
                "revision": 1,
                "round_count": 0,
                "actor_ref": actor_ref,
                "message": clean_message,
                "predecessor_session_id": predecessor_session_id,
                "model_route_alias": model_route_alias,
                "model_route_id": planning_selection["route_id"],
                "agent_binding_ref": planning_selection["agent_binding_ref"],
                "model_route_revision_digest": planning_selection[
                    "route_revision_digest"
                ],
                "model_route_selection_digest": planning_selection["selection_digest"],
                "grant": grant,
                "grant_digest": grant_digest,
                "planning_constraints": {
                    "max_model_calls": _MAX_PLANNING_MODEL_CALLS,
                    "max_cost_cny_micros": _MAX_PLANNING_COST_CNY_MICROS,
                    "max_clarification_rounds": _MAX_PLANNING_ROUNDS,
                    "transport_retry_limit": 1,
                    "fallback_allowed": False,
                },
                "artifact_refs": list(refs),
                "context_tags": list(tags),
                "question_card": None,
                "package_id": None,
                "professional_task_id": None,
                "model_call_count": 0,
                "live_model_enabled": bool(getattr(self.model_port, "live_model_enabled", False)),
                "cost_cny_micros": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "transport_retry_count": 0,
                "events": [
                    _planning_event(0, "planning.input_checking", "checking_input", 1)
                ],
                "last_event_sequence": 0,
            }
            self.sessions[session_id] = session
            self._persist("task", task_id, department_id, task)
            self._persist("session", session_id, department_id, session)
            self._persist_planning_authority(session)
            self._record_planning_command(
                session=session,
                command_kind="create",
                idempotency_key=idempotency_key,
                request={
                    "department_id": department_id,
                    "message_digest": canonical_digest({"message": clean_message}),
                    "artifact_refs": list(refs),
                    "context_tags": list(tags),
                    "route_revision_digest": planning_selection[
                        "route_revision_digest"
                    ],
                    "predecessor_session_id": predecessor_session_id,
                },
            )
            try:
                result = self._invoke_planning_model(
                    session=session,
                    stage="generate_questions",
                    payload={
                        "department_id": department_id,
                        "goal": clean_message,
                        "artifact_refs": list(refs),
                        "context_tags": list(tags),
                        "round_number": 1,
                        "strict_workflow": self.model_route_catalog is not None,
                    },
                )
                questions = _validate_question_projection(result["output"])
                session["question_card"] = _question_card(
                    task_id=task_id,
                    revision=1,
                    round_number=1,
                    questions=questions,
                )
                session["question_request"] = _formal_question_request(
                    session["question_card"], binding.planning_agent_ref
                )
                session["status"] = "needs_input"
                session["stage"] = "awaiting_clarification"
                self._append_planning_events(
                    session,
                    (
                        ("planning.questions_generating", "generating_questions"),
                        ("planning.questions_validating", "validating_questions"),
                        ("planning.question_requested", "awaiting_clarification"),
                    ),
                )
            except PlanningModelTransportError:
                session["status"] = "failed_recoverable"
                session["stage"] = "provider_failed"
                self._append_planning_events(
                    session,
                    (("planning.provider_failed", "provider_failed"),),
                )
            except DepartmentCockpitError as error:
                if error.reason_code not in _FAIL_CLOSED_PLANNING_REASONS:
                    raise
                self._fail_planning_session(session, error.reason_code)
            self._persist("session", session_id, department_id, session)
            self._persist_planning_authority(session)
            with self.database.session() as database_session:
                database_session.add(
                    AuditEventRow(
                        audit_id=_stable_id(
                            "audit",
                            {
                                "task_id": task_id,
                                "event_type": "planning_model_route_bound",
                                "route_alias": model_route_alias,
                            },
                        ),
                        correlation_id=task_id,
                        event_type="planning_model_route_bound",
                        actor_ref=actor_ref,
                        payload={
                            "department_id": department_id,
                            "route_alias": model_route_alias,
                            "route_revision_digest": planning_selection[
                                "route_revision_digest"
                            ],
                            "execution_grant_id": grant["metadata"]["grant_id"],
                            "execution_grant_digest": grant_digest,
                            "company_allowlist_projection": True,
                            "provider_details_included": False,
                            "release_authorization": False,
                        },
                        recorded_at=datetime.now(timezone.utc),
                    )
                )
            return self._session_response(session)

    def model_resources(
        self, *, department_id: str, window: str = "month_to_date"
    ) -> dict[str, Any]:
        self._binding(department_id)
        if window not in {"month_to_date", "last_7_days", "last_30_days"}:
            raise DepartmentCockpitError("model_usage_window_invalid")
        observed_at = datetime.now(timezone.utc)
        usage = self._model_usage(
            department_id=department_id,
            window=window,
            observed_at=observed_at,
        )
        routes = self._model_routes(department_id)
        agent_items: list[dict[str, Any]] = []
        for agent in self.department_agents(department_id):
            binding_ref = str(agent["agent_binding_ref"])
            candidate = agent.get("source_kind") == "department_proposal"
            selection = (
                _proposal_model_route_selection(agent)
                if candidate else self._agent_model_route_selection(department_id, binding_ref)
            )
            current = next(
                (
                    item
                    for item in routes
                    if item["route_id"] == selection["route_id"]
                    and item["route_revision_digest"]
                    == selection["route_revision_digest"]
                ),
                _unavailable_selected_route(selection),
            )
            projected_routes = [
                _public_agent_route(
                    item,
                    agent=agent,
                    selected=(not candidate and
                        item["route_id"] == current["route_id"]
                        and item["route_revision_digest"]
                        == current["route_revision_digest"]
                    ),
                )
                for item in routes
            ]
            agent_usage = next(
                (
                    item
                    for item in usage["by_agent"]
                    if item["agent_ref"] == agent["agent_id"]
                ),
                _empty_usage_bucket(agent_ref=agent["agent_id"]),
            )
            if agent_usage["receipt_count"] == 0:
                agent_usage = dict(agent_usage)
                for key in ("input_tokens", "output_tokens", "model_calls"):
                    agent_usage[key] = None
            agent_items.append(
                {
                    "agent_ref": agent["agent_id"],
                    **_agent_source_metadata(agent),
                    "agent_binding_ref": binding_ref,
                    "display_name": agent["name"],
                    "kind": agent["kind"],
                    "model_requirements": dict(agent["model_requirements"]),
                    "selection_digest": selection["selection_digest"],
                    "selected_at": selection["selected_at"],
                    "current_route": _public_agent_route(
                        current, agent=agent, selected=not candidate
                    ),
                    "available_routes": projected_routes,
                    "usage": agent_usage,
                }
            )
        return {
            "department_id": department_id,
            "window": window,
            "window_started_at": usage["window_started_at"],
            "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
            "data_status": usage["data_status"],
            "evidence_completeness": usage["evidence_completeness"],
            "totals": usage["totals"],
            "by_route": usage["by_route"],
            "agents": agent_items,
            "provider_details_visible": False,
            "synthetic_only": True,
            "production_authorized": False,
            "release_authorization": False,
        }

    def select_agent_model_route(
        self,
        *,
        department_id: str,
        agent_binding_ref: str,
        route_id: str,
        route_revision_digest: str,
        expected_selection_digest: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        self._binding(department_id)
        agent = self._department_agent_by_binding(department_id, agent_binding_ref)
        if agent is None:
            raise DepartmentCockpitError("agent_binding_not_found")
        if agent.get("source_kind") == "department_proposal":
            # A candidate approval is not a Registry activation receipt.  Do not
            # silently map a new candidate onto an unrelated built-in identity.
            raise DepartmentCockpitError("agent_registry_activation_missing")
        if (
            not isinstance(route_id, str)
            or not isinstance(route_revision_digest, str)
            or not _DIGEST.fullmatch(route_revision_digest)
            or not isinstance(expected_selection_digest, str)
            or not _DIGEST.fullmatch(expected_selection_digest)
            or not _IDEMPOTENCY.fullmatch(idempotency_key)
        ):
            raise DepartmentCockpitError("agent_model_route_selection_invalid")
        route = next(
            (
                item
                for item in self._model_routes(department_id)
                if item["route_id"] == route_id
                and item["route_revision_digest"] == route_revision_digest
            ),
            None,
        )
        if route is None:
            raise DepartmentCockpitError("model_route_revision_not_found")
        if (
            route["company_approval_status"] not in {"d0_approved", "approved"}
            or route["revoked"]
            or not route["selectable"]
        ):
            raise DepartmentCockpitError("model_route_not_company_approved")
        compatibility = _route_compatibility(agent, route)
        if not compatibility["compatible"]:
            raise DepartmentCockpitError("model_route_agent_incompatible")

        request_document = {
            "department_id": department_id,
            "agent_binding_ref": agent_binding_ref,
            "route_id": route_id,
            "route_revision_digest": route_revision_digest,
            "expected_selection_digest": expected_selection_digest,
            "actor_ref": actor_ref,
        }
        request_digest = canonical_digest(request_document)
        receipt_id = _stable_id(
            "receipt_model_route_selection", {"idempotency_key": idempotency_key}
        )
        with self.database.session() as database_session:
            previous_receipt = database_session.scalar(
                select(ReceiptRow).where(ReceiptRow.receipt_id == receipt_id)
            )
        if previous_receipt is not None:
            previous_document = previous_receipt.document
            if previous_document.get("request_digest") != request_digest:
                raise DepartmentCockpitError(
                    "agent_model_route_selection_idempotency_conflict"
                )
            return {
                **dict(previous_document["response"]),
                "receipt_digest": previous_receipt.receipt_digest,
                "idempotent_replay": True,
            }

        with self._lock:
            with self.database.session() as database_session:
                locked_previous = database_session.scalar(
                    select(ReceiptRow).where(ReceiptRow.receipt_id == receipt_id)
                )
            if locked_previous is not None:
                locked_document = locked_previous.document
                if locked_document.get("request_digest") != request_digest:
                    raise DepartmentCockpitError(
                        "agent_model_route_selection_idempotency_conflict"
                    )
                return {
                    **dict(locked_document["response"]),
                    "receipt_digest": locked_previous.receipt_digest,
                    "idempotent_replay": True,
                }
            current = self._agent_model_route_selection(
                department_id, agent_binding_ref
            )
            if current["selection_digest"] != expected_selection_digest:
                raise DepartmentCockpitError("agent_model_route_selection_drift")
            selected_at = _now()
            selection = {
                "department_id": department_id,
                "agent_ref": agent["agent_id"],
                "agent_binding_ref": agent_binding_ref,
                "route_id": route_id,
                "route_alias": route["route_alias"],
                "route_revision_digest": route_revision_digest,
                "revision": current["revision"] + 1,
                "selected_by_ref": actor_ref,
                "selected_at": selected_at,
                "receipt_id": receipt_id,
                "company_approval_status": "d0_approved",
                "provider_details_visible": False,
                "production_authorized": False,
                "release_authorization": False,
            }
            selection["selection_digest"] = _model_selection_digest(selection)
            response = {
                "changed": True,
                "selection": dict(selection),
                "receipt_id": receipt_id,
                "selection_digest": selection["selection_digest"],
                "effective_for": "future_tasks_only",
                "execution_grant_issued": False,
                "release_authorization": False,
            }
            receipt_document = {
                "kind": "DepartmentModelRouteSelectionReceipt",
                "request_digest": request_digest,
                "metadata": {
                    "receipt_id": receipt_id,
                    "department_id": department_id,
                    "recorded_at": selected_at,
                    "evidence_status": "synthetic",
                },
                "spec": {
                    "agent_ref": agent["agent_id"],
                    "agent_binding_ref": agent_binding_ref,
                    "route_id": route_id,
                    "route_alias": route["route_alias"],
                    "route_revision_digest": route_revision_digest,
                    "previous_selection_digest": current["selection_digest"],
                    "selection_digest": selection["selection_digest"],
                    "selected_by_human_ref": actor_ref,
                    "company_approval_status": "d0_approved",
                    "provider_details_included": False,
                    "execution_grant": False,
                    "effective_for": "future_tasks_only",
                    "release_authorization": False,
                    "production_authorization": False,
                },
                "response": response,
            }
            receipt_digest = canonical_digest(receipt_document)
            with self.database.session() as database_session:
                database_session.add(
                    ReceiptRow(
                        receipt_id=receipt_id,
                        receipt_type="department_model_route_selection",
                        receipt_digest=receipt_digest,
                        subject_ref=agent_binding_ref,
                        document=receipt_document,
                        recorded_at=datetime.now(timezone.utc),
                    )
                )
                database_session.add(
                    AuditEventRow(
                        audit_id=_stable_id("audit", {"receipt_id": receipt_id}),
                        correlation_id=agent_binding_ref,
                        event_type="department_model_route_selected",
                        actor_ref=actor_ref,
                        payload={
                            "department_id": department_id,
                            "agent_ref": agent["agent_id"],
                            "agent_binding_ref": agent_binding_ref,
                            "route_alias": route["route_alias"],
                            "route_revision_digest": route_revision_digest,
                            "selection_digest": selection["selection_digest"],
                            "receipt_id": receipt_id,
                            "effective_for": "future_tasks_only",
                            "provider_details_included": False,
                            "execution_grant_issued": False,
                            "release_authorization": False,
                        },
                        recorded_at=datetime.now(timezone.utc),
                    )
                )
                self._persist_in_session(
                    database_session,
                    "agent_model_route_selection",
                    agent_binding_ref,
                    department_id,
                    selection,
                )
                if agent_binding_ref == _planning_agent_binding_ref(department_id):
                    self._persist_in_session(
                        database_session,
                        "model_route_selection",
                        department_id,
                        department_id,
                        selection,
                    )
            self.agent_model_route_selections[agent_binding_ref] = selection
            if agent_binding_ref == _planning_agent_binding_ref(department_id):
                self.model_route_selections[department_id] = dict(selection)
            return {**response, "receipt_digest": receipt_digest}

    def select_model_route(
        self, *, department_id: str, route_alias: str, actor_ref: str
    ) -> dict[str, Any]:
        """Compatibility endpoint: select the planning Agent's route only."""
        route = next(
            (
                item
                for item in self._model_routes(department_id)
                if item["route_alias"] == route_alias
            ),
            None,
        )
        if route is None:
            raise DepartmentCockpitError("model_route_not_company_approved")
        binding_ref = _planning_agent_binding_ref(department_id)
        current = self._agent_model_route_selection(department_id, binding_ref)
        return self.select_agent_model_route(
            department_id=department_id,
            agent_binding_ref=binding_ref,
            route_id=route["route_id"],
            route_revision_digest=route["route_revision_digest"],
            expected_selection_digest=current["selection_digest"],
            idempotency_key=_stable_id(
                "legacy_model_route",
                {
                    "department_id": department_id,
                    "route_alias": route_alias,
                    "expected_selection_digest": current["selection_digest"],
                    "actor_ref": actor_ref,
                },
            ),
            actor_ref=actor_ref,
        )

    def select_runtime_artifact(
        self,
        *,
        department_id: str,
        artifact_id: str,
        artifact_revision: str,
        runtime_image_digest: str,
        expected_current_image_digest: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        self._binding(department_id)
        if (
            not _SAFE_ID.fullmatch(artifact_id)
            or not _DIGEST.fullmatch(artifact_revision)
            or not _DIGEST.fullmatch(runtime_image_digest)
            or expected_current_image_digest != "none"
            and not _DIGEST.fullmatch(expected_current_image_digest)
            or not _IDEMPOTENCY.fullmatch(idempotency_key)
        ):
            raise DepartmentCockpitError("runtime_artifact_selection_invalid")
        request = {
            "department_id": department_id,
            "artifact_id": artifact_id,
            "artifact_revision": artifact_revision,
            "runtime_image_digest": runtime_image_digest,
            "expected_current_image_digest": expected_current_image_digest,
            "actor_ref": actor_ref,
        }
        request_digest = canonical_digest(request)
        receipt_id = _stable_id(
            "receipt_runtime_artifact_selection",
            {"idempotency_key": idempotency_key},
        )
        with self.database.session() as session:
            replay = session.scalar(
                select(ReceiptRow).where(ReceiptRow.receipt_id == receipt_id)
            )
            if replay is not None:
                if replay.document.get("request_digest") != request_digest:
                    raise DepartmentCockpitError(
                        "runtime_artifact_selection_idempotency_conflict"
                    )
                return {
                    **replay.document["response"],
                    "idempotent_replay": True,
                }
            artifact = session.scalar(
                select(RuntimeArtifactRevisionRow).where(
                    RuntimeArtifactRevisionRow.artifact_id == artifact_id,
                    RuntimeArtifactRevisionRow.revision_digest == artifact_revision,
                )
            )
            revoked = session.scalar(
                select(RuntimeArtifactRevocationRow).where(
                    RuntimeArtifactRevocationRow.artifact_id == artifact_id,
                    RuntimeArtifactRevocationRow.revision_digest == artifact_revision,
                )
            )
            qualification = session.scalar(
                select(ReceiptRow).where(
                    ReceiptRow.receipt_type == "runtime_artifact_qualification_d0",
                    ReceiptRow.subject_ref
                    == runtime_artifact_subject_ref(artifact_id, artifact_revision),
                )
            )
        expected_family = {
            "product_center": "hermes",
            "technology_center": "codex",
            "market_center": "hermes",
        }[department_id]
        if (
            artifact is None
            or revoked is not None
            or not runtime_artifact_qualification_receipt_matches(
                artifact, qualification
            )
            or artifact.runtime_image_digest != runtime_image_digest
            or artifact.runtime_family != expected_family
        ):
            raise DepartmentCockpitError(
                "runtime_artifact_not_company_approved_or_compatible"
            )
        current = self.runtime_artifact_selections.get(department_id)
        actual_current = "none" if current is None else current["runtime_image_digest"]
        if actual_current != expected_current_image_digest:
            raise DepartmentCockpitError("runtime_artifact_selection_drift")
        changed = current is None or (
            current["artifact_revision"] != artifact_revision
            or current["runtime_image_digest"] != runtime_image_digest
        )
        selected_at = _now()
        selection = {
            "department_id": department_id,
            "artifact_id": artifact_id,
            "artifact_revision": artifact_revision,
            "runtime_source_digest": artifact.runtime_source_digest,
            "runtime_image_digest": runtime_image_digest,
            "isolation_profile_digest": artifact.isolation_profile_digest,
            "runtime_family": artifact.runtime_family,
            "selection_revision": 1
            if current is None
            else current["selection_revision"] + (1 if changed else 0),
            "selected_by_ref": actor_ref,
            "selected_at": selected_at,
            "production_authorized": False,
            "release_authorization": False,
        }
        response = {
            "changed": changed,
            "receipt_id": receipt_id,
            "selection": selection,
            "execution_grant_issued": False,
            "release_authorization": False,
        }
        receipt_document = {
            "kind": "DepartmentRuntimeArtifactSelectionReceipt",
            "receipt_id": receipt_id,
            "request_digest": request_digest,
            "response": response,
            "recorded_at": selected_at,
            "production_authorization": False,
            "release_authorization": False,
        }
        with self.database.session() as session:
            session.add(
                ReceiptRow(
                    receipt_id=receipt_id,
                    receipt_type="department_runtime_artifact_selection",
                    receipt_digest=canonical_digest(receipt_document),
                    subject_ref=f"department_{department_id}_syn",
                    document=receipt_document,
                    recorded_at=datetime.now(timezone.utc),
                )
            )
            session.add(
                AuditEventRow(
                    audit_id=_stable_id("audit", {"receipt_id": receipt_id}),
                    correlation_id=f"department_{department_id}_syn",
                    event_type="department_runtime_artifact_selected",
                    actor_ref=actor_ref,
                    payload={
                        "department_id": department_id,
                        "artifact_id": artifact_id,
                        "artifact_revision": artifact_revision,
                        "runtime_image_digest": runtime_image_digest,
                        "receipt_id": receipt_id,
                        "release_authorization": False,
                    },
                    recorded_at=datetime.now(timezone.utc),
                )
            )
        self.runtime_artifact_selections[department_id] = selection
        self._persist(
            "runtime_artifact_selection", department_id, department_id, selection
        )
        return response

    def continue_session(
        self,
        *,
        department_id: str,
        session_id: str,
        actor_ref: str,
        answers: Mapping[str, str],
        supplement: str | None,
        question_request_id: str | None = None,
        question_revision: int | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        session = self._session(department_id, session_id)
        if session["actor_ref"] != actor_ref:
            raise DepartmentCockpitError("planning_session_actor_mismatch")
        if session["status"] == "stop_requested":
            raise DepartmentCockpitError("planning_run_cancelled")
        if session["package_id"] is not None:
            return self._session_response(session)
        if session["status"] != "needs_input":
            raise DepartmentCockpitError("planning_session_not_awaiting_answer")
        card = session["question_card"]
        if not isinstance(card, dict):
            raise DepartmentCockpitError("planning_question_request_missing")
        effective_request_id = question_request_id or str(card["request_id"])
        effective_revision = question_revision or int(card["revision"])
        if (
            effective_request_id != card["request_id"]
            or effective_revision != card["revision"]
        ):
            raise DepartmentCockpitError("planning_question_revision_drift")
        expected = {question["question_id"]: question for question in card["questions"]}
        if set(answers) != set(expected):
            raise DepartmentCockpitError("clarification_answers_incomplete")
        for question_id, option_id in answers.items():
            allowed = {
                option["option_id"] for option in expected[question_id]["options"]
            }
            if option_id not in allowed:
                raise DepartmentCockpitError("clarification_option_invalid")
        clean_supplement = (
            None
            if supplement is None or not supplement.strip()
            else _clean_text(supplement, reason_code="clarification_supplement_invalid")
        )
        if clean_supplement is not None:
            _reject_prompt_injection(clean_supplement)
        effective_idempotency = idempotency_key or _stable_id(
            "planning_turn_legacy",
            {
                "session_id": session_id,
                "question_request_id": effective_request_id,
                "question_revision": effective_revision,
                "answers": dict(answers),
                "supplement": clean_supplement,
            },
        )
        if not _IDEMPOTENCY.fullmatch(effective_idempotency):
            raise DepartmentCockpitError("planning_idempotency_key_invalid")
        answer_request = {
            "session_id": session_id,
            "question_request_id": effective_request_id,
            "question_revision": effective_revision,
            "answers": dict(answers),
            "supplement": clean_supplement,
            "actor_ref": actor_ref,
        }
        answer_digest = canonical_digest(answer_request)
        with self.database.session() as database_session:
            replay = database_session.scalar(
                select(PlanningTurnRow).where(
                    PlanningTurnRow.idempotency_key == effective_idempotency
                )
            )
        if replay is not None:
            if replay.request_digest != answer_digest:
                raise DepartmentCockpitError("planning_turn_idempotency_conflict")
            return self._session_response(session)
        with self._lock:
            round_number = int(session["round_count"]) + 1
            self._record_planning_turn(
                session=session,
                card=card,
                answers=dict(answers),
                supplement=clean_supplement,
                idempotency_key=effective_idempotency,
                request_digest=answer_digest,
                round_number=round_number,
            )
            session["last_answer"] = {
                "answers": dict(answers),
                "supplement": clean_supplement,
            }
            try:
                result = self._invoke_planning_model(
                    session=session,
                    stage="generate_task_package",
                    payload={
                        "department_id": department_id,
                        "goal": session["message"],
                        "context_tags": session.get("context_tags", []),
                        "round_number": round_number,
                        "answers": dict(answers),
                        "supplement": clean_supplement,
                        "required_sections": _workflow_required_sections(
                            department_id
                        ),
                        "strict_workflow": self.model_route_catalog is not None,
                    },
                )
            except PlanningModelTransportError:
                session["status"] = "failed_recoverable"
                session["stage"] = "provider_failed"
                session["round_count"] = round_number
                session["revision"] += 1
                self._append_planning_events(
                    session,
                    (("planning.provider_failed", "provider_failed"),),
                )
                self._persist("session", session_id, department_id, session)
                self._persist_planning_authority(session)
                return self._session_response(session)
            except DepartmentCockpitError as error:
                if error.reason_code not in _FAIL_CLOSED_PLANNING_REASONS:
                    raise
                self._fail_planning_session(session, error.reason_code)
                self._persist("session", session_id, department_id, session)
                self._persist_planning_authority(session)
                return self._session_response(session)
            output = result["output"]
            if output.get("result_kind") == "questions":
                if round_number >= _MAX_PLANNING_ROUNDS:
                    session["status"] = "blocked_recoverable"
                    session["stage"] = "clarification_limit_reached"
                    session["round_count"] = round_number
                    session["revision"] += 1
                    self._append_planning_events(
                        session,
                        (("planning.clarification_blocked", session["stage"]),),
                    )
                    self._persist("session", session_id, department_id, session)
                    self._persist_planning_authority(session)
                    return self._session_response(session)
                try:
                    next_questions = _validate_question_projection(output)
                except DepartmentCockpitError as error:
                    self._fail_planning_session(session, error.reason_code)
                    self._persist("session", session_id, department_id, session)
                    self._persist_planning_authority(session)
                    return self._session_response(session)
                runtime_result = self.transport.resume(
                    binding=self._binding(department_id),
                    run_id=session["run_id"],
                    answers=answers,
                    supplement=clean_supplement,
                    continue_clarification=True,
                )
                if runtime_result.get("status") != "needs_input":
                    raise DepartmentCockpitError("planning_runtime_resume_incomplete")
                session["round_count"] = round_number
                session["revision"] += 1
                session["question_card"] = _question_card(
                    task_id=session["task_id"],
                    revision=session["revision"],
                    round_number=round_number + 1,
                    questions=next_questions,
                )
                session["question_request"] = _formal_question_request(
                    session["question_card"],
                    self._binding(department_id).planning_agent_ref,
                )
                session["status"] = "needs_input"
                session["stage"] = "awaiting_clarification"
                self._append_planning_events(
                    session,
                    (
                        ("planning.gaps_checking", "checking_gaps"),
                        ("planning.question_requested", "awaiting_clarification"),
                    ),
                )
                self._persist("session", session_id, department_id, session)
                self._persist_planning_authority(session)
                return self._session_response(session)
            try:
                candidate = _validate_package_candidate(output, department_id)
            except DepartmentCockpitError as error:
                self._fail_planning_session(session, error.reason_code)
                self._persist("session", session_id, department_id, session)
                self._persist_planning_authority(session)
                return self._session_response(session)
            session["round_count"] = round_number
            return self._materialize_professional_task(
                session=session,
                answers=dict(answers),
                supplement=clean_supplement,
                candidate=candidate,
                resume_runtime=True,
            )

    def _materialize_professional_task(
        self,
        *,
        session: dict[str, Any],
        answers: Mapping[str, str],
        supplement: str | None,
        candidate: Mapping[str, Any],
        resume_runtime: bool,
    ) -> dict[str, Any]:
        department_id = session["department_id"]
        round_number = int(session["round_count"])
        if resume_runtime:
            runtime_result = self.transport.resume(
                binding=self._binding(department_id),
                run_id=session["run_id"],
                answers=answers,
                supplement=supplement,
                continue_clarification=False,
            )
            if runtime_result.get("status") != "ready":
                raise DepartmentCockpitError("planning_runtime_resume_incomplete")
        parent_task = self.tasks[session["task_id"]]
        professional_task_id = _stable_id(
            "task_professional",
            {
                "parent_task_id": parent_task["task_id"],
                "session_id": session["session_id"],
                "round_number": round_number,
            },
        )
        package = _professional_task_package(
            session=session,
            task=parent_task,
            answers=answers,
            supplement=supplement,
            professional_task_id=professional_task_id,
            candidate=candidate,
        )
        package_id = package["metadata"]["package_id"]
        self.packages[package_id] = package
        session["package_id"] = package_id
        session["professional_task_id"] = professional_task_id
        session["status"] = "awaiting_approval"
        session["stage"] = "awaiting_confirmation"
        session["revision"] += 1
        task = _professional_child_task(
            parent_task=parent_task,
            professional_task_id=professional_task_id,
            package=package,
        )
        self.tasks[professional_task_id] = task
        parent_task["authority_state"] = "pending_approval"
        parent_task["department_approval_status"] = "not_reviewed"
        parent_task["ui_column"] = "awaiting_confirmation"
        parent_task["professional_task_ref"] = professional_task_id
        parent_task["professional_agent_ref"] = task["professional_agent_ref"]
        parent_task["professional_agent_name"] = task["professional_agent_name"]
        budget = package["spec"]["budget"]
        parent_task["budget_summary"] = (
            f"{round(budget['max_runtime_seconds'] / 60)} 分钟 · "
            f"{budget['max_model_tokens']:,} tokens · "
            f"{budget['max_tool_calls']} 次工具调用"
        )
        parent_task["deadline_summary"] = (
            f"截止 {package['spec']['deadline_at'][:10]}"
        )
        parent_task["last_event_at"] = _now()
        self._append_planning_events(
            session,
            (
                ("planning.package_generating", "generating_task_package"),
                ("planning.package_validating", "validating_task_package"),
                ("planning.package_ready", "awaiting_confirmation"),
            ),
        )
        self._persist("package", package_id, department_id, package)
        self._persist("session", session["session_id"], department_id, session)
        self._persist("task", professional_task_id, department_id, task)
        self._persist("task", parent_task["task_id"], department_id, parent_task)
        self._persist_planning_authority(session)
        return self._session_response(session)

    def planning_session(
        self, *, department_id: str, session_id: str
    ) -> dict[str, Any]:
        return self._session_response(self._session(department_id, session_id))

    def retry_session(
        self,
        *,
        department_id: str,
        session_id: str,
        actor_ref: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        session = self._session(department_id, session_id)
        if session["actor_ref"] != actor_ref:
            raise DepartmentCockpitError("planning_session_actor_mismatch")
        if not _IDEMPOTENCY.fullmatch(idempotency_key):
            raise DepartmentCockpitError("planning_idempotency_key_invalid")
        with self.database.session() as database_session:
            replay = database_session.scalar(
                select(PlanningCommandRow).where(
                    PlanningCommandRow.idempotency_key == idempotency_key
                )
            )
        if replay is not None:
            if (
                replay.session_id != session_id
                or replay.command_kind != "retry_same_route"
            ):
                raise DepartmentCockpitError("planning_command_idempotency_conflict")
            return self._session_response(session)
        if session["status"] != "failed_recoverable":
            raise DepartmentCockpitError("planning_session_not_retryable")
        self._record_planning_command(
            session=session,
            command_kind="retry_same_route",
            idempotency_key=idempotency_key,
            request={
                "session_id": session_id,
                "route_revision_digest": session["model_route_revision_digest"],
                "expected_revision": session["revision"],
            },
        )
        session["revision"] += 1
        self._append_planning_events(
            session, (("planning.explicit_retry_started", "retrying_provider"),)
        )
        last_answer = session.get("last_answer")
        try:
            if not isinstance(last_answer, dict):
                result = self._invoke_planning_model(
                    session=session,
                    stage="generate_questions",
                    payload={
                        "department_id": department_id,
                        "goal": session["message"],
                        "artifact_refs": session["artifact_refs"],
                        "context_tags": session.get("context_tags", []),
                        "round_number": 1,
                        "strict_workflow": self.model_route_catalog is not None,
                    },
                )
                questions = _validate_question_projection(result["output"])
                session["question_card"] = _question_card(
                    task_id=session["task_id"],
                    revision=session["revision"],
                    round_number=1,
                    questions=questions,
                )
                session["question_request"] = _formal_question_request(
                    session["question_card"],
                    self._binding(department_id).planning_agent_ref,
                )
                session["status"] = "needs_input"
                session["stage"] = "awaiting_clarification"
                self._append_planning_events(
                    session,
                    (("planning.question_requested", "awaiting_clarification"),),
                )
                self._persist("session", session_id, department_id, session)
                self._persist_planning_authority(session)
                return self._session_response(session)
            result = self._invoke_planning_model(
                session=session,
                stage="generate_task_package",
                payload={
                    "department_id": department_id,
                    "goal": session["message"],
                    "context_tags": session.get("context_tags", []),
                    "round_number": session["round_count"],
                    "answers": dict(last_answer["answers"]),
                    "supplement": last_answer.get("supplement"),
                    "required_sections": _workflow_required_sections(department_id),
                    "strict_workflow": self.model_route_catalog is not None,
                },
            )
            candidate = _validate_package_candidate(result["output"], department_id)
            return self._materialize_professional_task(
                session=session,
                answers=dict(last_answer["answers"]),
                supplement=last_answer.get("supplement"),
                candidate=candidate,
                resume_runtime=True,
            )
        except PlanningModelTransportError:
            session["stage"] = "provider_failed"
            self._append_planning_events(
                session, (("planning.provider_failed", "provider_failed"),)
            )
            self._persist("session", session_id, department_id, session)
            self._persist_planning_authority(session)
            return self._session_response(session)
        except DepartmentCockpitError as error:
            if error.reason_code not in _FAIL_CLOSED_PLANNING_REASONS:
                raise
            self._fail_planning_session(session, error.reason_code)
            self._persist("session", session_id, department_id, session)
            self._persist_planning_authority(session)
            return self._session_response(session)

    def create_successor_session(
        self,
        *,
        department_id: str,
        session_id: str,
        actor_ref: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        predecessor = self._session(department_id, session_id)
        if predecessor["actor_ref"] != actor_ref:
            raise DepartmentCockpitError("planning_session_actor_mismatch")
        if not _IDEMPOTENCY.fullmatch(idempotency_key):
            raise DepartmentCockpitError("planning_idempotency_key_invalid")
        if predecessor.get("successor_idempotency_key") == idempotency_key:
            successor_session_id = predecessor.get("successor_session_id")
            if not isinstance(successor_session_id, str):
                raise DepartmentCockpitError("planning_successor_state_invalid")
            return self._session_response(
                self._session(department_id, successor_session_id)
            )
        if predecessor["status"] not in {
            "failed_recoverable",
            "blocked_recoverable",
            "failed_closed",
        }:
            raise DepartmentCockpitError("planning_successor_not_allowed")
        current = self._agent_model_route_selection(
            department_id, _planning_agent_binding_ref(department_id)
        )
        if (
            current["route_revision_digest"]
            == predecessor["model_route_revision_digest"]
        ):
            raise DepartmentCockpitError("planning_successor_route_unchanged")
        successor = self.create_session(
            department_id=department_id,
            actor_ref=actor_ref,
            actor_name=self.tasks[predecessor["task_id"]].get("responsible_name"),
            message=predecessor["message"],
            artifact_refs=predecessor["artifact_refs"],
            idempotency_key=idempotency_key,
            predecessor_session_id=session_id,
            context_tags=predecessor.get("context_tags", ()),
        )
        predecessor["status"] = "superseded"
        predecessor["stage"] = "successor_created"
        predecessor["successor_session_id"] = successor["session_id"]
        predecessor["successor_idempotency_key"] = idempotency_key
        predecessor["revision"] += 1
        self._append_planning_events(
            predecessor,
            (("planning.successor_created", "successor_created"),),
        )
        self._persist("session", session_id, department_id, predecessor)
        self._persist_planning_authority(predecessor)
        return successor

    def confirm_package(
        self,
        *,
        department_id: str,
        package_id: str,
        task_revision: int,
        task_scope_digest: str,
        package_digest: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        """Compatibility wrapper; the authoritative record is ApprovalDecision."""
        task_id = self._task_id_for_package(department_id, package_id)
        return self.decide_task(
            department_id=department_id,
            task_id=task_id,
            package_id=package_id,
            task_revision=task_revision,
            task_scope_digest=task_scope_digest,
            package_digest=package_digest,
            decision="approved",
            reason="兼容端点确认精确任务包并形成部门任务审批",
            idempotency_key=_stable_id(
                "task_approval_compat",
                {
                    "department_id": department_id,
                    "package_id": package_id,
                    "task_revision": task_revision,
                    "task_scope_digest": task_scope_digest,
                    "package_digest": package_digest,
                    "actor_ref": actor_ref,
                },
            ),
            actor_ref=actor_ref,
            actor_role_ref="role_department_owner",
            compatibility_endpoint=True,
        )

    def decide_task(
        self,
        *,
        department_id: str,
        task_id: str,
        package_id: str,
        task_revision: int,
        task_scope_digest: str,
        package_digest: str,
        decision: str,
        reason: str,
        idempotency_key: str,
        actor_ref: str,
        actor_role_ref: str,
        compatibility_endpoint: bool = False,
    ) -> dict[str, Any]:
        self._binding(department_id)
        requested_task_id = task_id
        if actor_role_ref != "role_department_owner":
            raise DepartmentCockpitError("task_approval_role_not_allowed")
        if decision not in {"approved", "rejected"}:
            raise DepartmentCockpitError("task_approval_decision_invalid")
        clean_reason = _clean_text(reason, reason_code="task_approval_reason_invalid")
        if len(clean_reason) < 8:
            raise DepartmentCockpitError("task_approval_reason_invalid")
        if not _IDEMPOTENCY.fullmatch(idempotency_key):
            raise DepartmentCockpitError("task_approval_idempotency_key_invalid")
        if not _DIGEST.fullmatch(package_digest) or not _DIGEST.fullmatch(
            task_scope_digest
        ):
            raise DepartmentCockpitError("task_package_digest_invalid")
        request_digest = canonical_digest(
            {
                "department_id": department_id,
                "task_id": task_id,
                "package_id": package_id,
                "task_revision": task_revision,
                "task_scope_digest": task_scope_digest,
                "package_digest": package_digest,
                "decision": decision,
                "reason": clean_reason,
                "actor_ref": actor_ref,
            }
        )
        with self.database.session() as database_session:
            replay = database_session.scalar(
                select(DepartmentTaskDecisionRow).where(
                    DepartmentTaskDecisionRow.idempotency_key == idempotency_key
                )
            )
            if replay is not None:
                if (
                    canonical_digest(replay.document["request_binding"])
                    != request_digest
                ):
                    raise DepartmentCockpitError("task_approval_idempotency_conflict")
                return self._decision_response(replay, compatibility_endpoint)
        try:
            package = self.packages[package_id]
        except KeyError as error:
            raise DepartmentCockpitError("task_package_not_found") from error
        metadata = package["metadata"]
        if metadata["department_ref"]["id"] != f"department_{department_id}_syn":
            raise DepartmentCockpitError("department_scope_mismatch")
        if metadata["task_id"] != task_id:
            candidate = self.tasks.get(metadata["task_id"])
            if candidate is None or candidate.get("parent_task_ref") != task_id:
                raise DepartmentCockpitError("task_package_task_binding_drift")
            task_id = metadata["task_id"]
        task = self.tasks[task_id]
        if (
            task_revision != task["revision"]
            or task_scope_digest != _task_scope_digest(task)
            or package_digest != package["spec"]["package_digest"]
        ):
            raise DepartmentCockpitError("task_package_revision_drift")
        if task["authority_state"] != "pending_approval":
            raise DepartmentCockpitError("task_not_pending_approval")
        with self.database.session() as database_session:
            existing = database_session.scalar(
                select(DepartmentTaskDecisionRow)
                .where(
                    DepartmentTaskDecisionRow.task_id == task_id,
                    DepartmentTaskDecisionRow.task_revision == task_revision,
                )
                .order_by(DepartmentTaskDecisionRow.id.desc())
                .limit(1)
            )
        if existing is not None:
            raise DepartmentCockpitError("task_approval_already_decided")
        decision_seed = {
            "package_id": package_id,
            "package_digest": package_digest,
            "task_revision": task_revision,
            "task_scope_digest": task_scope_digest,
            "actor_ref": actor_ref,
            "task_id": task_id,
            "decision": decision,
            "idempotency_key": idempotency_key,
        }
        decision_id = _stable_id("approval_task", decision_seed)
        now = _now()
        decision_document = {
            "apiVersion": "company-ai-os/v1alpha1",
            "kind": "ApprovalDecision",
            "metadata": {
                "approval_id": decision_id,
                "created_at": now,
                "decided_by_human_ref": actor_ref,
                "decided_by_role_ref": actor_role_ref,
                "correlation_id": task_id,
                "task_id": task_id,
            },
            "spec": {
                "decision": decision,
                "reason": clean_reason,
                "scope_ref": f"task-execution-approval://{task_id}/{task_revision}",
                "scope_digest": task_scope_digest,
                "expires_at": None,
                "conditions": [
                    "decision_scope:task_execution_approval",
                    f"package_digest:{package_digest}",
                    "receipt_is_not_execution_grant",
                ],
            },
            "request_binding": {
                "department_id": department_id,
                "task_id": requested_task_id,
                "package_id": package_id,
                "task_revision": task_revision,
                "task_scope_digest": task_scope_digest,
                "package_digest": package_digest,
                "decision": decision,
                "reason": clean_reason,
                "actor_ref": actor_ref,
            },
        }
        decision_digest = canonical_digest(decision_document)
        receipt_id = _stable_id("receipt_task_approval", decision_seed)
        with self._lock:
            receipt_document = {
                "kind": "DepartmentTaskApprovalReceipt",
                "metadata": {
                    "receipt_id": receipt_id,
                    "department_id": department_id,
                    "recorded_at": now,
                    "evidence_status": "synthetic",
                },
                "spec": {
                    "decision_scope": "task_execution_approval",
                    "decision": decision,
                    "decision_id": decision_id,
                    "decision_digest": decision_digest,
                    "task_id": task_id,
                    "task_revision": task_revision,
                    "task_scope_digest": task_scope_digest,
                    "professional_task_package_ref": {
                        "package_id": package_id,
                        "package_digest": package_digest,
                    },
                    "decided_by_human_ref": actor_ref,
                    "next_authority_state": (
                        "pending_approval" if decision == "approved" else "rejected"
                    ),
                    "execution_grant_issued": False,
                    "runtime_projection_authoritative": False,
                    "release_authorization": False,
                    "production_authorization": False,
                },
            }
            receipt_digest = canonical_digest(receipt_document)
            audit_id = _stable_id("audit", decision_seed)
            with self.database.session() as database_session:
                database_session.add(
                    DepartmentTaskDecisionRow(
                        decision_id=decision_id,
                        decision_digest=decision_digest,
                        idempotency_key=idempotency_key,
                        department_id=department_id,
                        task_id=task_id,
                        task_revision=task_revision,
                        task_scope_digest=task_scope_digest,
                        package_id=package_id,
                        package_digest=package_digest,
                        action=decision,
                        actor_ref=actor_ref,
                        actor_role_ref=actor_role_ref,
                        reason=clean_reason,
                        document=decision_document,
                        receipt_id=receipt_id,
                        receipt_digest=receipt_digest,
                        created_at=datetime.now(timezone.utc),
                    )
                )
                database_session.add(
                    ReceiptRow(
                        receipt_id=receipt_id,
                        receipt_type="department_task_approval_receipt",
                        receipt_digest=receipt_digest,
                        subject_ref=task_id,
                        document=receipt_document,
                        recorded_at=datetime.now(timezone.utc),
                    )
                )
                database_session.add(
                    AuditEventRow(
                        audit_id=audit_id,
                        correlation_id=task_id,
                        event_type="task_execution_approval_recorded",
                        actor_ref=actor_ref,
                        payload={
                            "department_id": department_id,
                            "package_id": package_id,
                            "package_digest": package_digest,
                            "decision_id": decision_id,
                            "decision_digest": decision_digest,
                            "decision": decision,
                            "receipt_id": receipt_id,
                            "release_authorization": False,
                        },
                        recorded_at=datetime.now(timezone.utc),
                    )
                )
            task["authority_state"] = (
                "pending_approval" if decision == "approved" else "rejected"
            )
            task["department_approval_status"] = decision
            task["department_approval_decision_id"] = decision_id
            task["department_approval_decision_digest"] = decision_digest
            task["execution_grant_id"] = None
            task["ui_column"] = (
                "pending_execution" if decision == "approved" else "closed"
            )
            task["last_event_at"] = now
            self._persist("task", task_id, department_id, task)
            return {
                "decision_id": decision_id,
                "decision_digest": decision_digest,
                "receipt_id": receipt_id,
                "receipt_digest": receipt_digest,
                "company_task_ref": task_id,
                "authority_state": task["authority_state"],
                "decision_scope": "task_execution_approval",
                "decision": decision,
                "execution_grant_issued": False,
                "compatibility_endpoint": compatibility_endpoint,
                "runtime_projection_authoritative": False,
                "release_authorization": False,
            }

    def run_synthetic_acceptance(
        self, *, department_id: str, task_id: str, actor_ref: str
    ) -> dict[str, Any]:
        self._binding(department_id)
        if department_id == "product_center":
            # The product-center Hermes D0 slice intentionally stops after the
            # exact package approval receipt.  Import qualification is not a
            # professional ExecutionGrant and must not open the legacy
            # synthetic acceptance shortcut.
            raise DepartmentCockpitError("professional_execution_not_authorized")
        if not isinstance(self.transport, LangGraphPlanningTransport):
            raise DepartmentCockpitError("synthetic_acceptance_not_available")
        requested_task = self._task(department_id, task_id)
        task = requested_task
        if requested_task.get("task_kind") == "planning_parent":
            professional_task_ref = requested_task.get("professional_task_ref")
            if isinstance(professional_task_ref, str):
                task = self._task(department_id, professional_task_ref)
                task_id = professional_task_ref
        if task["authority_state"] != "pending_approval":
            previous = self.synthetic_acceptance_runs.get(requested_task["task_id"])
            if previous is not None:
                return dict(previous)
            raise DepartmentCockpitError("task_not_ready_for_synthetic_acceptance")
        package = next(
            (
                value
                for value in self.packages.values()
                if value["metadata"]["task_id"] == task_id
            ),
            None,
        )
        if package is None:
            raise DepartmentCockpitError("task_package_not_found")
        with self.database.session() as database_session:
            approval = database_session.scalar(
                select(DepartmentTaskDecisionRow).where(
                    DepartmentTaskDecisionRow.task_id == task_id,
                    DepartmentTaskDecisionRow.action == "approved",
                )
            )
        if approval is None:
            raise DepartmentCockpitError("task_execution_approval_missing")
        professional_selection = self._agent_model_route_selection(
            department_id, _professional_agent_binding_ref(department_id)
        )
        task["professional_agent_binding_ref"] = professional_selection[
            "agent_binding_ref"
        ]
        task["professional_model_route_id"] = professional_selection["route_id"]
        task["professional_model_route_alias"] = professional_selection["route_alias"]
        task["professional_model_route_revision_digest"] = professional_selection[
            "route_revision_digest"
        ]
        task["professional_model_route_selection_digest"] = professional_selection[
            "selection_digest"
        ]

        seed = {
            "task_id": task_id,
            "task_revision": task["revision"],
            "package_digest": package["spec"]["package_digest"],
            "professional_agent_ref": task["professional_agent_ref"],
            "professional_model_route_revision_digest": professional_selection[
                "route_revision_digest"
            ],
        }
        invocation_id = _stable_id("invocation_syn", seed)
        result_id = _stable_id("result_syn", seed)
        evaluation_id = _stable_id("evaluation_syn", seed)
        receipt_id = _stable_id("receipt_d0_acceptance", seed)
        recorded_at = _now()
        result = {
            "result_id": result_id,
            "status": "succeeded",
            "output_summary": "D0 固定专业 Agent 已生成结构化合成产物。",
            "artifact_refs": [f"artifact://department-cockpit/{result_id}"],
            "synthetic_only": True,
        }
        evaluation = {
            "evaluation_id": evaluation_id,
            "decision": "pass",
            "rule_summary": "任务包摘要、禁止动作和无副作用边界全部通过。",
            "evaluator": "deterministic_rule_fixture",
            "synthetic_only": True,
        }
        receipt_document = {
            "kind": "SyntheticDepartmentAcceptanceReceipt",
            "metadata": {
                "receipt_id": receipt_id,
                "department_id": department_id,
                "recorded_at": recorded_at,
                "evidence_status": "synthetic",
            },
            "spec": {
                "company_task_ref": task_id,
                "invocation_id": invocation_id,
                "professional_agent_ref": task["professional_agent_ref"],
                "professional_agent_binding_ref": professional_selection[
                    "agent_binding_ref"
                ],
                "model_route_ref": professional_selection["route_id"],
                "model_route_revision_digest": professional_selection[
                    "route_revision_digest"
                ],
                "model_route_selection_digest": professional_selection[
                    "selection_digest"
                ],
                "result_id": result_id,
                "evaluation_id": evaluation_id,
                "authority_state": "succeeded",
                "runtime_projection_authoritative": False,
                "release_authorization": False,
                "production_authorization": False,
            },
        }
        receipt_digest = canonical_digest(receipt_document)
        events = (
            (
                "professional_agent_invocation_recorded",
                task["professional_agent_ref"],
                {
                    "invocation_id": invocation_id,
                    "runtime": "synthetic_fixture",
                    "model_route_ref": professional_selection["route_id"],
                    "model_route_revision_digest": professional_selection[
                        "route_revision_digest"
                    ],
                },
            ),
            (
                "result_package_recorded",
                task["professional_agent_ref"],
                {"result_id": result_id, "status": "succeeded"},
            ),
            (
                "evaluation_completed",
                "evaluator_deterministic_rule_syn",
                {"evaluation_id": evaluation_id, "decision": "pass"},
            ),
            (
                "company_task_succeeded",
                actor_ref,
                {"receipt_id": receipt_id, "evaluation_id": evaluation_id},
            ),
        )
        with self._lock:
            with self.database.session() as database_session:
                database_session.add(
                    ReceiptRow(
                        receipt_id=receipt_id,
                        receipt_type="synthetic_department_acceptance",
                        receipt_digest=receipt_digest,
                        subject_ref=task_id,
                        document=receipt_document,
                        recorded_at=datetime.now(timezone.utc),
                    )
                )
                for index, (event_type, event_actor, payload) in enumerate(events):
                    database_session.add(
                        AuditEventRow(
                            audit_id=_stable_id(
                                "audit",
                                {**seed, "event_type": event_type, "index": index},
                            ),
                            correlation_id=task_id,
                            event_type=event_type,
                            actor_ref=event_actor,
                            payload={
                                "department_id": department_id,
                                **payload,
                                "synthetic_only": True,
                                "release_authorization": False,
                            },
                            recorded_at=datetime.now(timezone.utc),
                        )
                    )
            task["authority_state"] = "succeeded"
            task["runtime_projection_state"] = "done"
            task["projection_drift"] = False
            task["ui_column"] = "closed"
            task["last_event_at"] = recorded_at
            if requested_task is not task:
                for key in (
                    "authority_state",
                    "runtime_projection_state",
                    "projection_drift",
                    "ui_column",
                    "last_event_at",
                    "professional_agent_binding_ref",
                    "professional_model_route_id",
                    "professional_model_route_alias",
                    "professional_model_route_revision_digest",
                    "professional_model_route_selection_digest",
                ):
                    requested_task[key] = task.get(key)
            response = {
                "receipt_id": receipt_id,
                "receipt_digest": receipt_digest,
                "task": dict(requested_task),
                "invocation": {
                    "invocation_id": invocation_id,
                    "professional_agent_ref": task["professional_agent_ref"],
                    "runtime": "deterministic_synthetic_fixture",
                    "synthetic_only": True,
                },
                "result": result,
                "evaluation": evaluation,
                "audit_events": self._audit_events(
                    department_id, correlation_id=task_id
                ),
                "runtime_projection_authoritative": False,
                "release_authorization": False,
            }
            self.synthetic_acceptance_runs[requested_task["task_id"]] = response
            self._persist("task", task_id, department_id, task)
            if requested_task is not task:
                self._persist(
                    "task", requested_task["task_id"], department_id, requested_task
                )
            self._persist(
                "synthetic_acceptance",
                requested_task["task_id"],
                department_id,
                response,
            )
            return dict(response)

    def task_detail(self, *, department_id: str, task_id: str) -> dict[str, Any]:
        task = self._task(department_id, task_id)
        package = next(
            (
                value
                for value in self.packages.values()
                if value["metadata"]["task_id"] == task_id
                or self.tasks.get(value["metadata"]["task_id"], {}).get(
                    "parent_task_ref"
                )
                == task_id
            ),
            None,
        )
        approval_task = (
            task
            if package is None
            else self.tasks.get(package["metadata"]["task_id"], task)
        )
        return {
            "task": dict(task),
            "task_package": None if package is None else dict(package),
            "task_approval_subject": (
                None
                if package is None
                else {
                    "decision_scope": "task_execution_approval",
                    "task_id": approval_task["task_id"],
                    "task_revision": approval_task["revision"],
                    "task_scope_digest": _task_scope_digest(approval_task),
                    "package_digest": package["spec"]["package_digest"],
                }
            ),
            "audit_events": self._audit_events(department_id, correlation_id=task_id),
            "runtime_projection_authoritative": False,
            "release_authorization": False,
        }

    def _task(self, department_id: str, task_id: str) -> dict[str, Any]:
        self._binding(department_id)
        try:
            task = self.tasks[task_id]
        except KeyError as error:
            raise DepartmentCockpitError("company_task_not_found") from error
        if task["department_id"] != department_id:
            raise DepartmentCockpitError("department_scope_mismatch")
        return task

    def _task_id_for_package(self, department_id: str, package_id: str) -> str:
        self._binding(department_id)
        try:
            package = self.packages[package_id]
        except KeyError as error:
            raise DepartmentCockpitError("task_package_not_found") from error
        if (
            package["metadata"]["department_ref"]["id"]
            != f"department_{department_id}_syn"
        ):
            raise DepartmentCockpitError("department_scope_mismatch")
        return package["metadata"]["task_id"]

    @staticmethod
    def _decision_response(
        row: DepartmentTaskDecisionRow, compatibility_endpoint: bool
    ) -> dict[str, Any]:
        return {
            "decision_id": row.decision_id,
            "decision_digest": row.decision_digest,
            "receipt_id": row.receipt_id,
            "receipt_digest": row.receipt_digest,
            "company_task_ref": row.task_id,
            "authority_state": (
                "pending_approval" if row.action == "approved" else "rejected"
            ),
            "decision_scope": "task_execution_approval",
            "decision": row.action,
            "execution_grant_issued": False,
            "compatibility_endpoint": compatibility_endpoint,
            "idempotent_replay": True,
            "runtime_projection_authoritative": False,
            "release_authorization": False,
        }

    def events(
        self,
        *,
        department_id: str,
        session_id: str,
        after_sequence: int,
    ) -> dict[str, Any]:
        session = self._session(department_id, session_id)
        if after_sequence < -1:
            raise DepartmentCockpitError("runtime_event_cursor_invalid")
        events = tuple(
            event
            for event in session.get("events", [])
            if event["sequence"] > after_sequence
        )
        deduplicated: dict[int, Mapping[str, Any]] = {}
        for event in events:
            sequence = event.get("sequence")
            if type(sequence) is not int or sequence < 0:
                raise DepartmentCockpitError("planning_runtime_event_invalid")
            deduplicated.setdefault(sequence, event)
        ordered = [dict(deduplicated[key]) for key in sorted(deduplicated)]
        return {
            "session_id": session_id,
            "run_id": session["run_id"],
            "events": ordered,
            "resource_revision": session["revision"],
            "terminal": session["status"]
            in {
                "awaiting_approval",
                "blocked_recoverable",
                "failed_closed",
                "cancelled",
            },
            "runtime_projection_authoritative": False,
            "release_authorization": False,
        }

    def stop_session(
        self, *, department_id: str, session_id: str, actor_ref: str
    ) -> dict[str, Any]:
        session = self._session(department_id, session_id)
        if session["actor_ref"] != actor_ref:
            raise DepartmentCockpitError("planning_session_actor_mismatch")
        self.transport.stop(
            binding=self._binding(department_id), run_id=session["run_id"]
        )
        session["status"] = "stop_requested"
        session["stage"] = "stopped"
        session["revision"] += 1
        self._append_planning_events(
            session, (("planning.stop_recorded", "stopped"),)
        )
        self._persist("session", session_id, department_id, session)
        self._persist_planning_authority(session)
        return {
            "session_id": session_id,
            "run_id": session["run_id"],
            "status": "stop_requested",
            "company_task_state_changed": False,
            "release_authorization": False,
        }

    def _binding(self, department_id: str) -> PlanningRuntimeBinding:
        if not _DEPARTMENT.fullmatch(department_id):
            raise DepartmentCockpitError("department_id_invalid")
        try:
            return self.bindings[department_id]
        except KeyError as error:
            raise DepartmentCockpitError("department_not_found") from error

    def _restore_or_seed(self) -> None:
        with self.database.session() as session:
            rows = tuple(
                session.scalars(
                    select(DepartmentCockpitObjectRow).order_by(
                        DepartmentCockpitObjectRow.id
                    )
                )
            )
        stores = {
            "task": self.tasks,
            "session": self.sessions,
            "package": self.packages,
            "synthetic_acceptance": self.synthetic_acceptance_runs,
            "model_route_selection": self.model_route_selections,
            "agent_model_route_selection": self.agent_model_route_selections,
            "runtime_artifact_selection": self.runtime_artifact_selections,
        }
        for row in rows:
            target = stores.get(row.object_type)
            if target is None:
                raise DepartmentCockpitError("cockpit_state_object_type_invalid")
            target[row.object_id] = json.loads(json.dumps(row.document))
        if not self.tasks:
            self.tasks.update(_seed_tasks())
            for task_id, task in self.tasks.items():
                self._persist("task", task_id, task["department_id"], task)
        for department_id in self.departments:
            if department_id not in self.model_route_selections:
                selection = _seed_model_route_selection(department_id)
                self.model_route_selections[department_id] = selection
                self._persist(
                    "model_route_selection",
                    department_id,
                    department_id,
                    selection,
                )
            for agent in _agents(department_id):
                binding_ref = str(agent["agent_binding_ref"])
                if binding_ref in self.agent_model_route_selections:
                    continue
                legacy = (
                    self.model_route_selections.get(department_id)
                    if binding_ref == _planning_agent_binding_ref(department_id)
                    else None
                )
                selection = _seed_agent_model_route_selection(
                    department_id=department_id,
                    agent=agent,
                    legacy=legacy,
                )
                self.agent_model_route_selections[binding_ref] = selection
                self._persist(
                    "agent_model_route_selection",
                    binding_ref,
                    department_id,
                    selection,
                )

    def _model_route_selection(self, department_id: str) -> dict[str, Any]:
        return self._agent_model_route_selection(
            department_id, _planning_agent_binding_ref(department_id)
        )

    def _agent_model_route_selection(
        self, department_id: str, agent_binding_ref: str
    ) -> dict[str, Any]:
        self._binding(department_id)
        agent = self._department_agent_by_binding(department_id, agent_binding_ref)
        if agent is None:
            raise DepartmentCockpitError("agent_binding_not_found")
        if agent.get("source_kind") == "department_proposal":
            return _proposal_model_route_selection(agent)
        try:
            selection = self.agent_model_route_selections[agent_binding_ref]
        except KeyError as error:
            raise DepartmentCockpitError("model_route_selection_not_found") from error
        if selection.get("department_id") != department_id:
            raise DepartmentCockpitError("department_scope_mismatch")
        return selection

    def _model_routes(self, department_id: str) -> list[dict[str, Any]]:
        if self.model_route_catalog is None:
            return _model_route_catalog(department_id)
        return [
            dict(item)
            for item in self.model_route_catalog.routes(department_id=department_id)
        ]

    def _model_usage(
        self, *, department_id: str, window: str, observed_at: datetime
    ) -> dict[str, Any]:
        if window == "month_to_date":
            started_at = observed_at.replace(
                day=1, hour=0, minute=0, second=0, microsecond=0
            )
        elif window == "last_7_days":
            started_at = observed_at - timedelta(days=7)
        else:
            started_at = observed_at - timedelta(days=30)
        with self.database.session() as session:
            rows = tuple(
                session.scalars(
                    select(ReceiptRow)
                    .where(
                        ReceiptRow.receipt_type == "execution_closure",
                        ReceiptRow.recorded_at >= started_at,
                        ReceiptRow.recorded_at <= observed_at,
                    )
                    .order_by(ReceiptRow.id)
                )
            )
        by_agent: dict[str, dict[str, Any]] = {}
        by_route: dict[str, dict[str, Any]] = {}
        seen: set[str] = set()
        invalid_count = 0
        for row in rows:
            if row.receipt_id in seen:
                continue
            task = self.tasks.get(row.subject_ref)
            if task is None or task.get("department_id") != department_id:
                continue
            seen.add(row.receipt_id)
            document = row.document
            usage = document.get("spec", {}).get("usage")
            agent_ref = task.get("professional_agent_ref") or task.get(
                "planning_agent_ref"
            )
            route_alias = task.get("professional_model_route_alias") or task.get(
                "model_route_alias"
            )
            if (
                document.get("kind") != "ExecutionClosureReceipt"
                or not isinstance(usage, dict)
                or not isinstance(agent_ref, str)
                or not isinstance(route_alias, str)
                or any(
                    type(usage.get(key)) is not int or usage[key] < 0
                    for key in ("input_tokens", "output_tokens", "model_calls")
                )
            ):
                invalid_count += 1
                continue
            agent_bucket = by_agent.setdefault(
                agent_ref, _empty_usage_bucket(agent_ref=agent_ref)
            )
            route_bucket = by_route.setdefault(
                route_alias, _empty_usage_bucket(route_alias=route_alias)
            )
            for bucket in (agent_bucket, route_bucket):
                bucket["input_tokens"] += usage["input_tokens"]
                bucket["output_tokens"] += usage["output_tokens"]
                bucket["model_calls"] += usage["model_calls"]
                bucket["receipt_count"] += 1
        valid_count = sum(item["receipt_count"] for item in by_agent.values())
        if valid_count == 0:
            data_status = "partial" if invalid_count else "not_enabled"
            completeness = (
                "some_receipts_rejected"
                if invalid_count
                else "no_verified_execution_closure_receipts"
            )
            totals = _empty_usage_bucket()
            for key in ("input_tokens", "output_tokens", "model_calls"):
                totals[key] = None
        else:
            data_status = "partial" if invalid_count else "complete"
            completeness = (
                "some_receipts_rejected" if invalid_count else "verified_receipts_only"
            )
            totals = _empty_usage_bucket()
            for item in by_agent.values():
                for key in (
                    "input_tokens",
                    "output_tokens",
                    "model_calls",
                    "receipt_count",
                ):
                    totals[key] += item[key]
        return {
            "window_started_at": started_at.isoformat().replace("+00:00", "Z"),
            "data_status": data_status,
            "evidence_completeness": completeness,
            "totals": totals,
            "by_agent": list(by_agent.values()),
            "by_route": list(by_route.values()),
        }

    def _runtime_environment(self, department_id: str) -> dict[str, Any]:
        selection = self.runtime_artifact_selections.get(department_id)
        node_id = {
            "product_center": "node_product_001",
            "technology_center": "node_technology_001",
            "market_center": "node_market_001",
        }[department_id]
        with self.database.session() as session:
            artifacts = tuple(
                session.scalars(
                    select(RuntimeArtifactRevisionRow).order_by(
                        RuntimeArtifactRevisionRow.id
                    )
                )
            )
            revocations = {
                (row.artifact_id, row.revision_digest)
                for row in session.scalars(select(RuntimeArtifactRevocationRow))
            }
            qualification_receipts = {
                row.subject_ref: row
                for row in session.scalars(
                    select(ReceiptRow).where(
                        ReceiptRow.receipt_type == "runtime_artifact_qualification_d0"
                    )
                )
            }
            capability = session.scalar(
                select(RuntimeNodeCapabilityReportRow)
                .where(RuntimeNodeCapabilityReportRow.node_id == node_id)
                .order_by(RuntimeNodeCapabilityReportRow.id.desc())
                .limit(1)
            )
            imported = None
            if selection is not None:
                imported = session.scalar(
                    select(RuntimeArtifactImportReceiptRow)
                    .where(
                        RuntimeArtifactImportReceiptRow.node_id == node_id,
                        RuntimeArtifactImportReceiptRow.revision_digest
                        == selection["artifact_revision"],
                        RuntimeArtifactImportReceiptRow.outcome == "imported",
                    )
                    .order_by(RuntimeArtifactImportReceiptRow.id.desc())
                    .limit(1)
                )
        capability_verified = (
            capability is not None and capability.status == "eligible_d0"
        )
        capability_time = (
            None
            if capability is None
            else capability.recorded_at.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
        imported_time = (
            None
            if imported is None
            else imported.recorded_at.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
        expected_family = {
            "product_center": "hermes",
            "technology_center": "codex",
            "market_center": "hermes",
        }[department_id]
        compatible_departments = {
            "hermes": ["product_center", "market_center"],
            "codex": ["technology_center"],
        }
        runtime_artifacts = []
        current_artifact = (
            None
            if selection is None
            else next(
                (
                    item
                    for item in artifacts
                    if item.artifact_id == selection["artifact_id"]
                    and item.revision_digest == selection["artifact_revision"]
                ),
                None,
            )
        )
        for artifact in artifacts:
            if (
                artifact.runtime_family != expected_family
                or artifact.target_platform != "linux/amd64"
            ):
                continue
            revoked = (artifact.artifact_id, artifact.revision_digest) in revocations
            qualified = runtime_artifact_qualification_receipt_matches(
                artifact,
                qualification_receipts.get(
                    runtime_artifact_subject_ref(
                        artifact.artifact_id, artifact.revision_digest
                    )
                ),
            )
            current = (
                selection is not None
                and selection["artifact_id"] == artifact.artifact_id
                and selection["artifact_revision"] == artifact.revision_digest
            )
            rollback = (
                not current
                and not revoked
                and qualified
                and current_artifact is not None
                and artifact.artifact_id == current_artifact.artifact_id
                and (
                    artifact.document["metadata"]["revision"]
                    < current_artifact.document["metadata"]["revision"]
                    or artifact.document["metadata"]["revision"]
                    == current_artifact.document["metadata"]["revision"]
                    and artifact.recorded_at < current_artifact.recorded_at
                )
            )
            runtime_artifacts.append(
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_revision": artifact.revision_digest,
                    "display_name": f"{artifact.runtime_family.title()} Runtime Artifact",
                    "runtime_family": artifact.runtime_family,
                    "runtime_source_revision": artifact.document["spec"][
                        "upstream_revision"
                    ],
                    "runtime_source_digest": artifact.runtime_source_digest,
                    "runtime_image_digest": artifact.runtime_image_digest,
                    "artifact_set_digest": artifact.bundle_digest,
                    "target_platform": "linux/amd64",
                    "qualification_status": (
                        "revoked"
                        if revoked
                        else "d0_verified"
                        if qualified
                        else "candidate"
                    ),
                    "lifecycle_slot": (
                        "current"
                        if current
                        else "rollback"
                        if rollback
                        else "candidate"
                    ),
                    "compatible_department_refs": compatible_departments[
                        artifact.runtime_family
                    ],
                    "synthetic_only": True,
                    "production_authorized": False,
                }
            )
        stages = []
        for stage, summary in (
            ("install", "等待专用 WSL2 与 Rootless Docker 安装回执"),
            ("download", "等待签名 OCI 离线包下载回执"),
            ("verify", "等待签名、Artifact Set 与摘要校验回执"),
            ("import", "等待精确镜像摘要导入回执"),
            ("probe", "等待 Rootless 与隔离探针回执"),
            ("ready", "等待节点 CapabilityReport 完成可调度判定"),
        ):
            passed = imported is not None and stage in {
                "download",
                "verify",
                "import",
                "probe",
                "ready",
            }
            if stage == "install":
                passed = capability_verified
            stages.append(
                {
                    "stage": stage,
                    "status": "passed" if passed else "not_started",
                    "summary": summary if not passed else f"{summary}：已记录 D0 证据",
                    "receipt_status": (
                        "recorded"
                        if passed
                        else "waiting"
                        if selection is not None
                        else "not_expected"
                    ),
                    "recorded_at": (
                        capability_time if stage == "install" else imported_time
                    )
                    if passed
                    else None,
                }
            )
        checked_at = _now()
        return {
            "node": {
                "node_id": node_id,
                "display_name": f"{self.departments[department_id]['name']} WSL Runtime Node",
                "department_ref": department_id,
                "environment": "wsl2",
                "distribution": "OrbitRuntime-Ubuntu-22.04",
                "systemd_status": "verified" if capability_verified else "unverified",
                "container_engine": "rootless-docker",
                "rootless_status": "verified" if capability_verified else "unverified",
                "uidmap_status": "verified" if capability_verified else "unverified",
                "windows_automount_status": "disabled"
                if capability_verified
                else "unverified",
                "seccomp_status": "verified" if capability_verified else "unverified",
                "cgroup_status": "verified" if capability_verified else "unverified",
                "verified_artifact_digests": (
                    []
                    if capability is None
                    else capability.document["verified_runtime_artifact_digests"]
                ),
                "last_reported_at": capability_time,
                "evidence_status": (
                    "capability_report" if capability is not None else "synthetic"
                ),
                "production_authorized": False,
            },
            "deployment_stages": stages,
            "runtime_artifacts": runtime_artifacts,
            "service_health": [
                {
                    "service": "control_plane",
                    "status": "ready",
                    "summary": "Control Plane D0 投影可读",
                    "checked_at": checked_at,
                },
                *[
                    {
                        "service": service,
                        "status": (
                            "degraded"
                            if service == "runner" and capability is not None
                            else "not_installed"
                        ),
                        "summary": "尚未在真实部门电脑安装或启动",
                        "checked_at": checked_at,
                    }
                    for service in ("hermes", "codex", "runner", "gateway_relay")
                ],
            ],
            "selection_mode": "department_owner_from_company_allowlist",
            "release_authorization": False,
        }

    def _planning_route(
        self, department_id: str, selection: Mapping[str, Any]
    ) -> dict[str, Any]:
        route = next(
            (
                dict(item)
                for item in self._model_routes(department_id)
                if item["route_id"] == selection["route_id"]
                and item["route_revision_digest"]
                == selection["route_revision_digest"]
            ),
            None,
        )
        if route is None:
            raise DepartmentCockpitError("planning_route_revision_unavailable")
        if self.model_route_catalog is None:
            return route
        if (
            route.get("company_approval_status") not in {"approved", "d0_approved"}
            or route.get("revoked")
            or not route.get("selectable")
        ):
            raise DepartmentCockpitError("planning_route_revision_not_eligible")
        compatibility = _route_compatibility(
            _agents(department_id)[0], route
        )
        if not compatibility["compatible"]:
            raise DepartmentCockpitError("planning_route_agent_incompatible")
        return route

    def _fail_planning_session(
        self, session: dict[str, Any], reason_code: str
    ) -> None:
        if reason_code not in _FAIL_CLOSED_PLANNING_REASONS:
            raise DepartmentCockpitError("planning_failure_reason_invalid")
        session["status"] = "failed_closed"
        session["stage"] = "validation_failed"
        session["failure_reason_code"] = reason_code
        session["revision"] += 1
        self._append_planning_events(
            session, (("planning.failed_closed", "validation_failed"),)
        )

    def _assert_planning_execution_ready(
        self, session: Mapping[str, Any]
    ) -> None:
        grant = session.get("grant")
        if not isinstance(grant, dict):
            raise DepartmentCockpitError("planning_execution_grant_missing")
        metadata = grant.get("metadata", {})
        if (
            metadata.get("status") != "active"
            or metadata.get("task_id") != session["task_id"]
            or _parse_datetime(str(metadata.get("expires_at", "")))
            <= datetime.now(timezone.utc)
        ):
            raise DepartmentCockpitError("planning_execution_grant_inactive")
        with self.database.session() as database_session:
            revoked = database_session.scalar(
                select(GrantRevocationRow).where(
                    GrantRevocationRow.grant_id == metadata["grant_id"]
                )
            )
        if revoked is not None:
            raise DepartmentCockpitError("planning_execution_grant_revoked")
        self._planning_route(
            session["department_id"],
            {
                "route_id": session["model_route_id"],
                "route_revision_digest": session["model_route_revision_digest"],
            },
        )
        if session["model_call_count"] >= _MAX_PLANNING_MODEL_CALLS:
            raise DepartmentCockpitError("planning_model_call_limit_exceeded")
        if session["cost_cny_micros"] >= _MAX_PLANNING_COST_CNY_MICROS:
            raise DepartmentCockpitError("planning_budget_exceeded")

    def _invoke_planning_model(
        self,
        *,
        session: dict[str, Any],
        stage: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        request_digest = canonical_digest(dict(payload))
        attempts = (
            1 if getattr(self.model_port, "live_model_enabled", False)
            or session["transport_retry_count"] >= 1 else 2
        )
        for retry_count in range(attempts):
            self._assert_planning_execution_ready(session)
            call_number = int(session["model_call_count"]) + 1
            session["model_call_count"] = call_number
            try:
                value = self.model_port.invoke(
                    stage=stage,
                    route_id=session["model_route_id"],
                    route_revision_digest=session["model_route_revision_digest"],
                    grant_id=session["grant"]["metadata"]["grant_id"],
                    payload=payload,
                )
            except PlanningModelTransportError:
                session["transport_retry_count"] += 1
                self._record_invocation_evidence(
                    session=session,
                    stage=stage,
                    call_number=call_number,
                    retry_count=session["transport_retry_count"],
                    request_digest=request_digest,
                    response_digest=canonical_digest(
                        {"status": "transport_failed", "retry": retry_count}
                    ),
                    value={},
                    schema_valid=False,
                    status="transport_failed",
                )
                if retry_count == 0 and attempts == 2:
                    continue
                raise
            if not isinstance(value, Mapping) or not isinstance(
                value.get("output"), Mapping
            ):
                raise DepartmentCockpitError("planning_model_structure_invalid")
            if value.get("synthetic_only") is not True:
                raise DepartmentCockpitError("planning_live_model_not_enabled")
            if (
                value.get("route_revision_digest")
                != session["model_route_revision_digest"]
            ):
                raise DepartmentCockpitError("planning_model_route_mismatch")
            returned_model_id = value.get("returned_model_id")
            if not isinstance(returned_model_id, str) or not returned_model_id:
                raise DepartmentCockpitError("planning_returned_model_missing")
            expected_model_id = value.get("expected_model_id")
            if (
                isinstance(expected_model_id, str)
                and expected_model_id != returned_model_id
            ):
                raise DepartmentCockpitError("planning_returned_model_mismatch")
            metrics = {
                "input_tokens": value.get("input_tokens"),
                "output_tokens": value.get("output_tokens"),
                "cost_cny_micros": value.get("cost_cny_micros"),
            }
            if any(type(item) is not int or item < 0 for item in metrics.values()):
                raise DepartmentCockpitError("planning_model_usage_invalid")
            next_cost = session["cost_cny_micros"] + metrics["cost_cny_micros"]
            if next_cost > _MAX_PLANNING_COST_CNY_MICROS:
                raise DepartmentCockpitError("planning_budget_exceeded")
            session["input_tokens"] += metrics["input_tokens"]
            session["output_tokens"] += metrics["output_tokens"]
            session["cost_cny_micros"] = next_cost
            response_digest = canonical_digest(dict(value["output"]))
            schema_valid = value.get("schema_valid") is True
            self._record_invocation_evidence(
                session=session,
                stage=stage,
                call_number=call_number,
                retry_count=session["transport_retry_count"],
                request_digest=request_digest,
                response_digest=response_digest,
                value=value,
                schema_valid=schema_valid,
                status="succeeded" if schema_valid else "schema_rejected",
            )
            if not schema_valid:
                raise DepartmentCockpitError("planning_model_structure_invalid")
            return dict(value)
        raise PlanningModelTransportError("planning_transport_retry_exhausted")

    def _record_invocation_evidence(
        self,
        *,
        session: Mapping[str, Any],
        stage: str,
        call_number: int,
        retry_count: int,
        request_digest: str,
        response_digest: str,
        value: Mapping[str, Any],
        schema_valid: bool,
        status: str,
    ) -> None:
        invocation_id = _stable_id(
            "planning_invocation",
            {
                "session_id": session["session_id"],
                "call_number": call_number,
                "request_digest": request_digest,
            },
        )
        with self.database.session() as database_session:
            database_session.add(
                PlanningInvocationEvidenceRow(
                    invocation_id=invocation_id,
                    session_id=session["session_id"],
                    round_number=int(session["round_count"]) + 1,
                    stage=stage,
                    route_id=session["model_route_id"],
                    route_revision_digest=session["model_route_revision_digest"],
                    grant_id=session["grant"]["metadata"]["grant_id"],
                    provider_request_id=_optional_safe_text(
                        value.get("provider_request_id")
                    ),
                    returned_model_id=_optional_safe_text(
                        value.get("returned_model_id")
                    ),
                    retry_count=retry_count,
                    input_tokens=_nonnegative_int(value.get("input_tokens")),
                    output_tokens=_nonnegative_int(value.get("output_tokens")),
                    cost_cny_micros=_nonnegative_int(
                        value.get("cost_cny_micros")
                    ),
                    request_digest=request_digest,
                    response_digest=response_digest,
                    schema_valid=schema_valid,
                    status=status,
                    recorded_at=datetime.now(timezone.utc),
                )
            )

    def _record_planning_turn(
        self,
        *,
        session: Mapping[str, Any],
        card: Mapping[str, Any],
        answers: Mapping[str, str],
        supplement: str | None,
        idempotency_key: str,
        request_digest: str,
        round_number: int,
    ) -> None:
        with self.database.session() as database_session:
            database_session.add(
                PlanningTurnRow(
                    turn_id=_stable_id(
                        "planning_turn",
                        {
                            "session_id": session["session_id"],
                            "round_number": round_number,
                        },
                    ),
                    session_id=session["session_id"],
                    round_number=round_number,
                    question_request_id=card["request_id"],
                    question_revision=card["revision"],
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    question_document=dict(
                        session.get("question_request") or card
                    ),
                    answer_document={
                        "answers": dict(answers),
                        "supplement": supplement,
                    },
                    recorded_at=datetime.now(timezone.utc),
                )
            )

    def _record_planning_command(
        self,
        *,
        session: Mapping[str, Any],
        command_kind: str,
        idempotency_key: str,
        request: Mapping[str, Any],
    ) -> None:
        request_digest = canonical_digest(dict(request))
        with self.database.session() as database_session:
            replay = database_session.scalar(
                select(PlanningCommandRow).where(
                    PlanningCommandRow.idempotency_key == idempotency_key
                )
            )
            if replay is not None:
                if replay.request_digest != request_digest:
                    raise DepartmentCockpitError(
                        "planning_command_idempotency_conflict"
                    )
                return
            database_session.add(
                PlanningCommandRow(
                    command_id=_stable_id(
                        "planning_command",
                        {
                            "session_id": session["session_id"],
                            "command_kind": command_kind,
                            "idempotency_key": idempotency_key,
                        },
                    ),
                    session_id=session["session_id"],
                    command_kind=command_kind,
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    result_revision=session["revision"],
                    recorded_at=datetime.now(timezone.utc),
                )
            )

    def _persist_planning_authority(self, document: Mapping[str, Any]) -> None:
        normalized = json.loads(json.dumps(document, ensure_ascii=False))
        now = datetime.now(timezone.utc)
        with self.database.session() as database_session:
            row = database_session.scalar(
                select(PlanningSessionAuthorityRow).where(
                    PlanningSessionAuthorityRow.session_id
                    == document["session_id"]
                )
            )
            if row is None:
                database_session.add(
                    PlanningSessionAuthorityRow(
                        session_id=document["session_id"],
                        department_id=document["department_id"],
                        parent_task_id=document["task_id"],
                        professional_task_id=document.get("professional_task_id"),
                        predecessor_session_id=document.get(
                            "predecessor_session_id"
                        ),
                        actor_ref=document["actor_ref"],
                        status=document["status"],
                        stage=document["stage"],
                        revision=document["revision"],
                        round_count=document["round_count"],
                        route_id=document["model_route_id"],
                        route_revision_digest=document[
                            "model_route_revision_digest"
                        ],
                        route_selection_digest=document[
                            "model_route_selection_digest"
                        ],
                        grant_id=document["grant"]["metadata"]["grant_id"],
                        grant_digest=document["grant_digest"],
                        document=normalized,
                        created_at=now,
                        updated_at=now,
                    )
                )
                return
            row.professional_task_id = document.get("professional_task_id")
            row.status = document["status"]
            row.stage = document["stage"]
            row.revision = document["revision"]
            row.round_count = document["round_count"]
            row.document = normalized
            row.updated_at = now

    @staticmethod
    def _append_planning_events(
        session: dict[str, Any], events: Sequence[tuple[str, str]]
    ) -> None:
        for event_type, stage in events:
            sequence = int(session["last_event_sequence"]) + 1
            session["events"].append(
                _planning_event(
                    sequence, event_type, stage, int(session["revision"])
                )
            )
            session["last_event_sequence"] = sequence

    def _persist(
        self,
        object_type: str,
        object_id: str,
        department_id: str,
        document: Mapping[str, Any],
    ) -> None:
        with self.database.session() as session:
            self._persist_in_session(
                session, object_type, object_id, department_id, document
            )

    def _persist_in_session(
        self,
        session: Any,
        object_type: str,
        object_id: str,
        department_id: str,
        document: Mapping[str, Any],
    ) -> None:
        normalized = json.loads(json.dumps(document, ensure_ascii=False))
        revision = normalized.get("revision", 1)
        if type(revision) is not int or revision < 1:
            revision = 1
        row = session.scalar(
            select(DepartmentCockpitObjectRow).where(
                DepartmentCockpitObjectRow.object_type == object_type,
                DepartmentCockpitObjectRow.object_id == object_id,
            )
        )
        if row is None:
            session.add(
                DepartmentCockpitObjectRow(
                    object_type=object_type,
                    object_id=object_id,
                    department_id=department_id,
                    revision=revision,
                    document=normalized,
                    updated_at=datetime.now(timezone.utc),
                )
            )
            return
        if row.department_id != department_id:
            raise DepartmentCockpitError("cockpit_state_department_drift")
        row.revision = revision
        row.document = normalized
        row.updated_at = datetime.now(timezone.utc)

    def _session(self, department_id: str, session_id: str) -> dict[str, Any]:
        self._binding(department_id)
        if not _SESSION_ID.fullmatch(session_id):
            raise DepartmentCockpitError("planning_session_id_invalid")
        try:
            session = self.sessions[session_id]
        except KeyError as error:
            raise DepartmentCockpitError("planning_session_not_found") from error
        if session["department_id"] != department_id:
            raise DepartmentCockpitError("department_scope_mismatch")
        return session

    def _session_response(self, session: Mapping[str, Any]) -> dict[str, Any]:
        package_id = session.get("package_id")
        package = (
            None
            if package_id is None
            else self.packages[str(package_id)]
        )
        professional_task = (
            None
            if session.get("professional_task_id") is None
            else self.tasks[session["professional_task_id"]]
        )
        grant = session.get("grant")
        grant_metadata = (
            grant.get("metadata", {}) if isinstance(grant, Mapping) else {}
        )
        grant_projection = (
            {
                "grant_id": grant_metadata["grant_id"],
                "grant_digest": session.get("grant_digest"),
                "status": grant_metadata["status"],
                "expires_at": grant_metadata["expires_at"],
            }
            if all(
                isinstance(grant_metadata.get(key), str)
                for key in ("grant_id", "status", "expires_at")
            )
            else None
        )
        planning_ready = bool(
            grant_projection is not None
            and grant_projection["status"] == "active"
            and session.get("status")
            not in {
                "failed_closed",
                "failed_recoverable",
                "blocked_recoverable",
                "stop_requested",
                "superseded",
            }
        )
        with self.database.session() as database_session:
            invocation_rows = tuple(
                database_session.scalars(
                    select(PlanningInvocationEvidenceRow)
                    .where(
                        PlanningInvocationEvidenceRow.session_id
                        == session["session_id"]
                    )
                    .order_by(PlanningInvocationEvidenceRow.id)
                )
            )
        return {
            "session_id": session["session_id"],
            "company_task_ref": session["task_id"],
            "planning_parent_task_ref": session["task_id"],
            "professional_task_ref": session.get("professional_task_id"),
            "run_id": session["run_id"],
            "response_id": session["response_id"],
            "status": session["status"],
            "stage": session.get("stage", "unknown"),
            "failure_reason_code": session.get("failure_reason_code"),
            "revision": session["revision"],
            "round_number": session.get("round_count", 0),
            "max_rounds": _MAX_PLANNING_ROUNDS,
            "event_cursor": session.get("last_event_sequence", -1),
            "locked_model_route": {
                "route_id": session.get("model_route_id"),
                "route_alias": session.get("model_route_alias"),
                "route_revision_digest": session.get(
                    "model_route_revision_digest"
                ),
                "selection_digest": session.get("model_route_selection_digest"),
                "fallback_allowed": False,
            },
            "execution_grant_ref": grant_projection,
            "question_card": (session.get("question_card") if package is None else None),
            "task_package": None if package is None else dict(package),
            "validation_result": (
                None
                if package is None
                else {
                    "schema_valid": True,
                    "required_sections_complete": True,
                    "policy_valid": True,
                    "normalized": True,
                }
            ),
            "task_approval_subject": (
                None
                if package is None or professional_task is None
                else {
                    "decision_scope": "task_execution_approval",
                    "task_id": professional_task["task_id"],
                    "task_revision": professional_task["revision"],
                    "task_scope_digest": _task_scope_digest(professional_task),
                    "package_digest": package["spec"]["package_digest"],
                }
            ),
            "task_chain": {
                "planning_parent": dict(self.tasks[session["task_id"]]),
                "professional_child": (
                    None if professional_task is None else dict(professional_task)
                ),
                "planning_ready": planning_ready,
                "professional_execution_ready": False,
            },
            "model_invocation_evidence": [
                {
                    "invocation_id": row.invocation_id,
                    "stage": row.stage,
                    "round_number": row.round_number,
                    "provider_request_id": row.provider_request_id,
                    "returned_model_observed": row.returned_model_id is not None,
                    "model_identity_digest": (
                        None
                        if row.returned_model_id is None
                        else canonical_digest(
                            {"returned_model_id": row.returned_model_id}
                        )
                    ),
                    "retry_count": row.retry_count,
                    "input_tokens": row.input_tokens,
                    "output_tokens": row.output_tokens,
                    "cost_cny": row.cost_cny_micros / 1_000_000,
                    "schema_valid": row.schema_valid,
                    "status": row.status,
                    "request_digest": row.request_digest,
                    "response_digest": row.response_digest,
                    "synthetic_only": True,
                    "live_model_enabled": bool(session.get("live_model_enabled", False)),
                }
                for row in invocation_rows
            ],
            "synthetic_only": True,
            "live_model_enabled": bool(session.get("live_model_enabled", False)),
            "runtime_projection_authoritative": False,
            "release_authorization": False,
        }

    def _audit_events(
        self, department_id: str, *, correlation_id: str | None = None
    ) -> list[dict[str, Any]]:
        with self.database.session() as session:
            scoped = select(AuditEventRow).where(
                AuditEventRow.payload["department_id"].as_string() == department_id
            )
            statement = scoped.order_by(AuditEventRow.id.desc()).limit(50)
            if correlation_id is not None:
                statement = (
                    scoped
                    .where(AuditEventRow.correlation_id == correlation_id)
                    .order_by(AuditEventRow.id)
                )
            rows = tuple(session.scalars(statement))
        return [
            {
                "audit_id": row.audit_id,
                "correlation_id": row.correlation_id,
                "event_type": row.event_type,
                "actor_ref": row.actor_ref,
                "actor_name": _audit_actor_name(row.actor_ref),
                "summary": _audit_summary(row.event_type),
                "payload": row.payload,
                "recorded_at": row.recorded_at.isoformat(),
                "status": "recorded",
                "category": _audit_category(row.event_type),
            }
            for row in rows
            if row.payload.get("department_id") == department_id
        ]


def _validate_run_id(run_id: str) -> None:
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise DepartmentCockpitError("planning_run_id_invalid")


def _audit_actor_name(actor_ref: str) -> str:
    if actor_ref.startswith("agent_"):
        return "专业 Agent（D0）"
    if actor_ref.startswith("evaluator_"):
        return "规则评价器（D0）"
    return "部门负责人"


def _audit_summary(event_type: str) -> str:
    return {
        "task_execution_approval_recorded": (
            "负责人已记录唯一任务执行审批，等待后续 Approval 与 Grant。"
        ),
        "professional_agent_invocation_recorded": (
            "D0 固定专业 Agent 已接收精确任务包并记录调用投影。"
        ),
        "result_package_recorded": "D0 合成结果包已记录。",
        "evaluation_completed": "确定性规则评价已通过。",
        "company_task_succeeded": "Company Task 已依据评价与回执进入成功终态。",
        "planning_model_route_bound": ("规划任务已绑定当时生效的公司批准模型路线。"),
        "department_model_route_selected": (
            "部门负责人已为指定 Agent 选择公司批准模型，并收到审计回执。"
        ),
        "cockpit_local_account_registered": "本地阶段 1 账号已提交注册。",
        "cockpit_local_account_approved": "本地阶段 1 账号已获授权角色批准。",
        "lan_invite_consumed": "部门邀请已用于账号注册。",
        "lan_account_approved": "公司管理员已批准部门账号及角色。",
        "department_agent_proposal_submitted": "Agent 申报已提交，等待独立审核 Agent 与模型路线。",
        "agent_activation_decided": "Agent 激活审核决定已记录；任务执行仍需独立授权。",
        "model_route_candidate_recorded": "模型路线候选已记录，等待精确修订审核。",
        "provider_observation_recorded": "模型路线的供应商观察证据已记录。",
        "model_route_snapshot_recorded": "模型路线健康与资格快照已记录。",
        "model_route_reconcile_requested": "模型路线已按当前证据重新核验。",
        "model_route_approval_approved": "模型路线的精确修订已批准；任务执行仍需独立授权。",
        "model_route_approval_rejected": "模型路线的精确修订已拒绝。",
        "model_route_approval_revoked": "模型路线的精确修订批准已撤销。",
    }.get(event_type, "驾驶舱事件已记录。")


def _audit_category(event_type: str) -> str:
    if event_type in {
        "task_execution_approval_recorded",
        "department_agent_proposal_submitted",
        "agent_activation_decided",
        "model_route_approval_approved",
        "model_route_approval_rejected",
        "model_route_approval_revoked",
    }:
        return "approval"
    if event_type == "professional_agent_invocation_recorded":
        return "runtime"
    if event_type == "result_package_recorded":
        return "runtime"
    if event_type == "evaluation_completed":
        return "evaluation"
    if event_type in {
        "planning_model_route_bound",
        "department_model_route_selected",
        "model_route_candidate_recorded",
        "provider_observation_recorded",
        "model_route_snapshot_recorded",
        "model_route_reconcile_requested",
    }:
        return "route"
    if event_type in {
        "cockpit_local_account_registered",
        "cockpit_local_account_approved",
        "lan_invite_consumed",
        "lan_account_approved",
    }:
        return "identity"
    return "task"


def _artifact_refs(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or len(values) > 8:
        raise DepartmentCockpitError("artifact_refs_invalid")
    result = []
    for value in values:
        if not isinstance(value, str) or not _LOGICAL_ARTIFACT.fullmatch(value):
            raise DepartmentCockpitError("artifact_ref_invalid")
        result.append(value)
    if len(set(result)) != len(result):
        raise DepartmentCockpitError("artifact_refs_invalid")
    return tuple(result)


def _context_tags(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or len(values) > 5:
        raise DepartmentCockpitError("planning_context_tags_invalid")
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise DepartmentCockpitError("planning_context_tags_invalid")
        normalized = " ".join(value.split())
        if not _CONTEXT_TAG.fullmatch(normalized):
            raise DepartmentCockpitError("planning_context_tags_invalid")
        result.append(normalized)
    if len(set(result)) != len(result):
        raise DepartmentCockpitError("planning_context_tags_invalid")
    return tuple(result)


def _bindings() -> dict[str, PlanningRuntimeBinding]:
    path = (
        Path(__file__).resolve().parents[3]
        / "references/company-department-planning-bindings.json"
    )
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: _reject_json_constant(),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DepartmentCockpitError("planning_binding_registry_invalid") from error
    if (
        not isinstance(document, dict)
        or document.get("registry_version") != "orbit.department-planning-bindings/1"
        or document.get("status") != "fixed_control_plane_candidate"
        or document.get("planning_runtime_kind") != "langgraph"
        or not isinstance(document.get("bindings"), list)
    ):
        raise DepartmentCockpitError("planning_binding_registry_invalid")
    result: dict[str, PlanningRuntimeBinding] = {}
    for item in document["bindings"]:
        if not isinstance(item, dict):
            raise DepartmentCockpitError("planning_binding_registry_invalid")
        try:
            binding = PlanningRuntimeBinding(**item)
        except TypeError as error:
            raise DepartmentCockpitError("planning_binding_registry_invalid") from error
        if binding.department_id in result:
            raise DepartmentCockpitError("planning_binding_registry_invalid")
        result[binding.department_id] = binding
    if set(result) != {"product_center", "technology_center", "market_center"}:
        raise DepartmentCockpitError("planning_binding_registry_invalid")
    return result


def _professional_runtime_bindings() -> dict[str, ProfessionalRuntimeBinding]:
    path = (
        Path(__file__).resolve().parents[3]
        / "references/company-department-professional-runtime-bindings.json"
    )
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: _reject_json_constant(),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DepartmentCockpitError(
            "professional_runtime_binding_registry_invalid"
        ) from error
    if (
        not isinstance(document, dict)
        or document.get("registry_version")
        != "orbit.department-professional-runtime-bindings/1"
        or document.get("status") != "fixed_control_plane_candidate"
        or not isinstance(document.get("bindings"), list)
    ):
        raise DepartmentCockpitError("professional_runtime_binding_registry_invalid")
    result: dict[str, ProfessionalRuntimeBinding] = {}
    for item in document["bindings"]:
        if not isinstance(item, dict):
            raise DepartmentCockpitError(
                "professional_runtime_binding_registry_invalid"
            )
        try:
            binding = ProfessionalRuntimeBinding(**item)
        except TypeError as error:
            raise DepartmentCockpitError(
                "professional_runtime_binding_registry_invalid"
            ) from error
        if binding.department_id in result:
            raise DepartmentCockpitError(
                "professional_runtime_binding_registry_invalid"
            )
        result[binding.department_id] = binding
    if set(result) != {"product_center", "technology_center", "market_center"}:
        raise DepartmentCockpitError("professional_runtime_binding_registry_invalid")
    return result


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DepartmentCockpitError("planning_binding_registry_duplicate_key")
        value[key] = item
    return value


def _reject_json_constant() -> None:
    raise DepartmentCockpitError("planning_binding_registry_constant_invalid")


def _departments() -> dict[str, dict[str, str]]:
    return {
        "product_center": {
            "department_id": "product_center",
            "name": "产品中心",
            "short": "产品",
            "identity": "把业务机会转成可验证的产品任务",
        },
        "technology_center": {
            "department_id": "technology_center",
            "name": "技术中心",
            "short": "技术",
            "identity": "把目标转成可实施、可评审的技术工作",
        },
        "market_center": {
            "department_id": "market_center",
            "name": "市场中心",
            "short": "市场",
            "identity": "把市场目标转成合规、可衡量的传播任务",
        },
    }


def _proposal_model_route_selection(agent: Mapping[str, Any]) -> dict[str, Any]:
    """Describe an immutable request without persisting a selection or receipt."""
    route_id = agent["model_route_refs"][0]
    selection = {
        "department_id": agent["department_id"],
        "agent_ref": agent["agent_id"],
        "agent_binding_ref": agent["agent_binding_ref"],
        "route_id": route_id,
        "route_alias": route_id,
        "route_revision_digest": agent["model_route_revision_digests"][route_id],
        "revision": 0,
        "selected_at": None,
        "selected_by_ref": None,
        "receipt_id": None,
    }
    selection["selection_digest"] = _model_selection_digest(selection)
    return selection


def _agent_source_metadata(agent: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: agent[key]
        for key in (
            "source_kind", "proposal_id", "package_digest", "proposal_revision",
            "agent_activation_status", "model_route_approval_status",
            "registry_status", "task_selectable", "selection_blocker_code",
        )
        if key in agent
    }


def _proposal_agent(proposal: Mapping[str, Any], *, department_id: str) -> dict[str, Any]:
    definition = proposal["agent_definition"]
    binding = proposal["agent_binding"]
    route = proposal["model_route"]
    if (
        proposal["department_id"] != department_id
        or definition["department_id"] != department_id
        or binding["department_id"] != department_id
        or binding["agent_definition_ref"] != definition["agent_id"]
        or binding["agent_definition_digest"] != canonical_digest(definition)
        or binding["model_route_refs"] != [{
            "route_id": route["route_id"], "revision_digest": route["revision_digest"]
        }]
        or definition.get("candidate_only") is not True
        or binding.get("candidate_only") is not True
        or binding.get("effective_grant") is not False
    ):
        raise DepartmentCockpitError("agent_proposal_projection_binding_drift")
    requirements = definition["model_requirements"]
    return {
        "agent_id": definition["agent_id"],
        "agent_binding_ref": binding["binding_id"],
        "department_id": department_id,
        "name": definition["name"],
        "kind": definition["agent_kind"],
        "identity": definition["identity"],
        "task_scope": definition["task_scope"],
        "typical_inputs": list(definition["typical_inputs"]),
        "outputs": list(definition["expected_outputs"]),
        "prohibited": list(definition["prohibited_actions"]),
        "runtime": {"langgraph": "LangGraph 规划候选", "codex": "Codex 专业候选", "hermes": "Hermes 专业候选"}[definition["runtime_kind"]],
        "qualification_status": "awaiting_registration" if proposal["agent_and_route_eligible"] else "awaiting_review",
        "availability": "unavailable",
        "source_kind": "department_proposal",
        "proposal_id": proposal["proposal_id"],
        "package_digest": proposal["package_digest"],
        "proposal_revision": proposal["revision"],
        "agent_activation_status": proposal["agent_activation_status"],
        "model_route_approval_status": proposal["model_route_approval_status"],
        "registry_status": "awaiting_registration",
        "task_selectable": False,
        "selection_blocker_code": "agent_registry_activation_missing",
        "candidate_only": True,
        "effective_grant": False,
        "model_route_refs": [route["route_id"]],
        "model_route_revision_digests": {route["route_id"]: route["revision_digest"]},
        "runtime_binding_refs": [binding["runtime_binding"]["ref"]],
        "policy_binding_refs": [binding["policy_binding"]["ref"]],
        "model_requirements": {
            "usage": "required", "capabilities": list(requirements["capabilities"]),
            "allowed_data_classifications": list(requirements["data_classifications"]),
            "fallback_allowed": False,
        },
    }


def _agents(department_id: str) -> list[dict[str, Any]]:
    professional_binding = _professional_runtime_bindings()[department_id]
    specific = {
        "product_center": (
            "产品需求分析 Agent",
            "从公开或合成材料形成需求拆解、验收标准和风险清单",
            "需求分析包",
        ),
        "technology_center": (
            "技术实现评审 Agent",
            "对 D0 合成方案形成实现拆解、接口检查和测试建议",
            "技术评审包",
        ),
        "market_center": (
            "市场内容规划 Agent",
            "从公开或合成简报形成渠道计划、内容骨架和衡量指标",
            "市场规划包",
        ),
    }[department_id]
    department_name = _departments()[department_id]["name"]
    requirements = {
        "product_center": {
            "department_planning": [
                "text",
                "structured_output",
                "reasoning",
                "streaming",
            ],
            "professional": ["text", "structured_output", "reasoning"],
        },
        "technology_center": {
            "department_planning": [
                "text",
                "structured_output",
                "reasoning",
                "streaming",
            ],
            "professional": ["text", "structured_output", "reasoning", "tool_calling"],
        },
        "market_center": {
            "department_planning": ["text", "structured_output", "streaming"],
            "professional": ["text", "structured_output", "streaming"],
        },
    }[department_id]
    route_refs = {
        "product_center": {
            "department_planning": [
                "company-route/planning-minimax-cn-approved",
                "company-route/planning-fallback-approved",
            ],
            "professional": [
                "company-route/planning-minimax-cn-approved",
                "company-route/planning-fallback-approved",
            ],
        },
        "technology_center": {
            "department_planning": [
                "company-route/planning-minimax-cn-approved",
                "company-route/planning-fallback-approved",
            ],
            "professional": ["company-route/planning-fallback-approved"],
        },
        "market_center": {
            "department_planning": [
                "company-route/planning-minimax-cn-approved",
                "company-route/planning-fallback-approved",
            ],
            "professional": [
                "company-route/planning-minimax-cn-approved",
                "company-route/planning-fallback-approved",
            ],
        },
    }[department_id]
    return [
        {
            "agent_id": f"agent_{department_id}_planning_syn",
            "department_id": department_id,
            "agent_binding_ref": _planning_agent_binding_ref(department_id),
            "name": f"{department_name}规划 Agent",
            "kind": "department_planning",
            "identity": "负责澄清、任务封装、候选推荐与监督，不代替审批和专业执行",
            "task_scope": "D0 公开或合成任务的多轮澄清与专业任务包草拟",
            "typical_inputs": ["目标描述", "受控 Artifact 引用"],
            "outputs": ["问题卡", "专业任务包草案"],
            "prohibited": ["直接签发 Grant", "确认任务完成", "读取本地路径"],
            "runtime": "LangGraph 状态图候选",
            "qualification_status": "unverified_runtime",
            "availability": "adapter_ready_transport_disabled",
            "model_route_refs": route_refs["department_planning"],
            "runtime_binding_refs": ["runtime-source://department-planning/langgraph"],
            "policy_binding_refs": [f"policy://department-cockpit/{department_id}/d0"],
            "model_requirements": {
                "usage": "required",
                "capabilities": requirements["department_planning"],
                "allowed_data_classifications": ["synthetic", "public"],
                "fallback_allowed": True,
            },
        },
        {
            "agent_id": professional_binding.professional_agent_ref,
            "department_id": department_id,
            "agent_binding_ref": _professional_agent_binding_ref(department_id),
            "name": specific[0],
            "kind": "professional",
            "identity": specific[1],
            "task_scope": "仅接受已确认、获准且 D0 的精确任务包",
            "typical_inputs": ["ProfessionalTaskPackage", "Artifact Reference"],
            "outputs": [specific[2], "TaskClarificationRequest"],
            "prohibited": ["扩大 Purpose", "新增数据范围", "对外发布"],
            "runtime": (
                "Hermes 专业 Runtime 候选"
                if professional_binding.runtime_kind == "hermes"
                else "Codex 专业 Runtime 候选"
            ),
            "runtime_binding": professional_binding.public_summary(),
            "qualification_status": professional_binding.qualification_status,
            "availability": professional_binding.availability,
            "model_route_refs": route_refs["professional"],
            "runtime_binding_refs": [
                f"runtime-source://department-professional/{professional_binding.runtime_kind}"
            ],
            "policy_binding_refs": [f"policy://department-cockpit/{department_id}/d0"],
            "model_requirements": {
                "usage": "required",
                "capabilities": requirements["professional"],
                "allowed_data_classifications": ["synthetic", "public"],
                "fallback_allowed": False,
            },
        },
    ]


def _legacy_routes(
    department_id: str,
    *,
    selected_alias: str,
    routes: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            **_public_route(item, selected=item["route_alias"] == selected_alias),
            "department_scope": department_id,
            "change_mode": "owner_select_from_company_allowlist",
        }
        for item in routes
    ]


def _model_route_catalog(department_id: str) -> list[dict[str, Any]]:
    _departments()[department_id]
    definitions = (
        {
            "route_id": "company-route/planning-minimax-cn-approved",
            "route_alias": "company-route/planning-minimax-cn-approved",
            "display_name": "公司规划路线 · MiniMax 中国",
            "connection_alias": "MiniMax 中国连接",
            "region": "中国大陆",
            "model_display_name": "MiniMax 中国规划模型",
            "model_version_label": "D0 公司批准版本",
            "capabilities": ["中文任务澄清", "结构化任务包", "文本推理", "流式反馈"],
            "capability_ids": ["text", "structured_output", "reasoning", "streaming"],
            "data_classifications": ["synthetic", "public"],
            "runtime_binding_refs": [
                "runtime-source://department-planning/langgraph",
                "runtime-source://department-professional/hermes",
            ],
            "policy_binding_refs": [
                "policy://department-cockpit/product_center/d0",
                "policy://department-cockpit/market_center/d0",
            ],
        },
        {
            "route_id": "company-route/planning-fallback-approved",
            "route_alias": "company-route/planning-fallback-approved",
            "display_name": "公司规划备用路线",
            "connection_alias": "公司备用连接",
            "region": "公司受控区域",
            "model_display_name": "公司备用模型",
            "model_version_label": "D0 公司批准版本",
            "capabilities": [
                "任务澄清",
                "结构化任务包",
                "文本推理",
                "受控工具调用",
                "流式反馈",
            ],
            "capability_ids": [
                "text",
                "structured_output",
                "reasoning",
                "tool_calling",
                "streaming",
            ],
            "data_classifications": ["synthetic", "public"],
            "runtime_binding_refs": [
                "runtime-source://department-planning/langgraph",
                "runtime-source://department-professional/hermes",
                "runtime-source://department-professional/codex",
            ],
            "policy_binding_refs": [
                "policy://department-cockpit/product_center/d0",
                "policy://department-cockpit/technology_center/d0",
                "policy://department-cockpit/market_center/d0",
            ],
        },
    )
    return [
        {
            **item,
            "route_revision_digest": canonical_digest(
                {"route_id": item["route_id"], "revision": "d0.1"}
            ),
            "compatible_agent_kinds": ["department_planning", "professional"],
            "company_approval_status": "d0_approved",
            "health_status": "ready",
            "health_summary": "合成测试夹具健康；真实模型调用仍未启用",
            "last_verified_at": None,
            "selectable": True,
            "revoked": False,
            "evidence_status": "architecture_reference",
            "recommendation_evidence_complete": False,
            "live_execution_enabled": False,
            "blocker_codes": [
                "provider_key_rotation_required",
                "budget_policy_not_configured",
            ],
        }
        for item in definitions
    ]


def _registered_model_route(
    *,
    row: ModelRouteRevisionRow,
    decisions: Sequence[ModelRouteDecisionRow],
    snapshots: Sequence[ModelRouteSnapshotRow],
    retirements: Sequence[ModelRouteRetirementRow] = (),
    observed_at: datetime,
) -> dict[str, Any]:
    exact_decisions = [
        item
        for item in decisions
        if item.route_id == row.route_id
        and item.route_revision_digest == row.revision_digest
    ]
    actions = {item.action for item in exact_decisions}
    approval_status = (
        "revoked"
        if "revoked" in actions
        else "approved"
        if "approved" in actions
        else "rejected"
        if "rejected" in actions
        else "not_reviewed"
    )
    snapshot = next(
        (
            item
            for item in reversed(snapshots)
            if item.route_id == row.route_id
            and item.route_revision_digest == row.revision_digest
        ),
        None,
    )
    snapshot_expired = (
        snapshot is not None and _aware(snapshot.expires_at) <= observed_at
    )
    health_status = (
        "missing"
        if snapshot is None
        else "expired"
        if snapshot_expired
        else snapshot.status
    )
    capabilities_value = row.parameters.get("capabilities", [])
    capability_ids = (
        [
            item
            for item in capabilities_value
            if isinstance(item, str)
            and item
            in {
                "text",
                "tool_calling",
                "structured_output",
                "reasoning",
                "streaming",
                "vision",
            }
        ]
        if isinstance(capabilities_value, list)
        else []
    )
    labels = {
        "text": "文本",
        "tool_calling": "受控工具调用",
        "structured_output": "结构化输出",
        "reasoning": "推理",
        "streaming": "流式反馈",
        "vision": "视觉",
    }
    blocker_codes = (
        ["model_route_health_snapshot_missing"]
        if snapshot is None
        else ["model_route_health_snapshot_expired"]
        if snapshot_expired
        else list(snapshot.reason_codes)
    )
    authentication_mode = (
        "api_key_ref"
        if row.authentication is None
        else str(row.authentication.get("mode", "api_key_ref"))
    )
    retired = any(
        item.route_id == row.route_id
        and item.route_revision_digest == row.revision_digest
        for item in retirements
    )
    selectable = (
        not retired
        and
        row.status == "active"
        and approval_status == "approved"
        and health_status == "ready"
    )
    return {
        "route_id": row.route_id,
        "route_alias": row.route_id,
        "route_revision_digest": row.revision_digest,
        "display_name": f"公司模型路线 · {row.route_id}",
        "connection_alias": (
            "公司专用 Codex 账号"
            if authentication_mode == "oauth_ref"
            else "公司 API 模型连接"
        ),
        "region": (
            "技术中心授权节点"
            if authentication_mode == "oauth_ref"
            else "中央 Model Gateway"
        ),
        # Department projections deliberately do not expose the provider's
        # requested/resolved model identifier.  The company console retains
        # that governance detail; departments receive a stable business label.
        "model_display_name": (
            "Codex CLI 公司账号模型"
            if authentication_mode == "oauth_ref"
            else "公司批准的 API 模型"
        ),
        "model_version_label": f"修订 {row.revision_digest[7:15]}",
        "capabilities": [labels[item] for item in capability_ids],
        "capability_ids": capability_ids,
        "data_classifications": [row.data_classification],
        "runtime_binding_refs": [str(row.runtime_binding["ref"])],
        "policy_binding_refs": [str(row.policy_binding["ref"])],
        "company_approval_status": approval_status,
        "health_status": health_status,
        "health_summary": (
            "公司健康快照有效"
            if health_status == "ready"
            else "公司健康证据缺失、过期或未通过"
        ),
        "last_verified_at": (
            None
            if snapshot is None
            else _aware(snapshot.created_at).isoformat().replace("+00:00", "Z")
        ),
        "selectable": selectable,
        "revoked": approval_status == "revoked" or retired,
        "evidence_status": "control_plane_registry",
        "recommendation_evidence_complete": False,
        "live_execution_enabled": False,
        "blocker_codes": (
            ["model_route_retired", *blocker_codes] if retired else blocker_codes
        ),
    }


def _unavailable_selected_route(selection: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "route_id": selection["route_id"],
        "route_alias": selection["route_alias"],
        "route_revision_digest": selection["route_revision_digest"],
        "display_name": "历史选择 · 当前公司目录不可用",
        "connection_alias": "公司目录未提供",
        "region": "未核验",
        "model_display_name": "不可核验",
        "model_version_label": "历史选择",
        "capabilities": [],
        "capability_ids": [],
        "data_classifications": [],
        "runtime_binding_refs": [],
        "policy_binding_refs": [],
        "company_approval_status": "not_reviewed",
        "health_status": "missing",
        "health_summary": "当前选择未在公司 ModelRoute Registry 中找到精确修订",
        "last_verified_at": None,
        "selectable": False,
        "revoked": False,
        "evidence_status": "missing_registry_evidence",
        "recommendation_evidence_complete": False,
        "live_execution_enabled": False,
        "blocker_codes": ["model_route_registry_revision_missing"],
    }


def _aware(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _public_route(route: Mapping[str, Any], *, selected: bool) -> dict[str, Any]:
    return {
        "route_id": route["route_id"],
        "route_alias": route["route_alias"],
        "route_revision_digest": route["route_revision_digest"],
        "display_name": route["display_name"],
        "connection_alias": route["connection_alias"],
        "region": route["region"],
        "model_display_name": route["model_display_name"],
        "model_version_label": route["model_version_label"],
        "capabilities": list(route["capabilities"]),
        "capability_ids": list(route["capability_ids"]),
        "selected": selected,
        "company_approval_status": route["company_approval_status"],
        "health_status": route["health_status"],
        "health_summary": route["health_summary"],
        "last_verified_at": route["last_verified_at"],
        "selectable": route["selectable"],
        "revoked": route["revoked"],
        "provider_details_visible": False,
        "evidence_status": route["evidence_status"],
        "live_execution_enabled": route["live_execution_enabled"],
        "blocker_codes": list(route["blocker_codes"]),
    }


def _route_compatibility(
    agent: Mapping[str, Any], route: Mapping[str, Any]
) -> dict[str, Any]:
    requirements = agent["model_requirements"]
    required_capabilities = set(requirements["capabilities"])
    available_capabilities = set(route["capability_ids"])
    missing_capabilities = sorted(required_capabilities - available_capabilities)
    allowed_by_binding = route["route_id"] in agent["model_route_refs"]
    pinned_revisions = agent.get("model_route_revision_digests", {})
    if pinned_revisions:
        allowed_by_binding = allowed_by_binding and pinned_revisions.get(route["route_id"]) == route["route_revision_digest"]
    agent_registered = agent.get("source_kind") != "department_proposal"
    data_compatible = bool(
        set(requirements["allowed_data_classifications"])
        & set(route["data_classifications"])
    )
    runtime_binding_compatible = bool(
        set(agent.get("runtime_binding_refs", ()))
        & set(route.get("runtime_binding_refs", ()))
    )
    policy_binding_compatible = bool(
        set(agent.get("policy_binding_refs", ()))
        & set(route.get("policy_binding_refs", ()))
    )
    company_approved = (
        route["company_approval_status"] in {"d0_approved", "approved"}
        and not route["revoked"]
    )
    health_evidence_valid = route["health_status"] == "ready"
    reasons: list[str] = []
    if not agent_registered:
        reasons.append("申报候选尚缺 Agent 登记与激活回执；审核决定不代表可用于任务")
    if not allowed_by_binding:
        reasons.append("该路线不在此 AgentBinding 的公司允许列表中")
    if missing_capabilities:
        labels = {
            "text": "文本",
            "structured_output": "结构化输出",
            "reasoning": "推理",
            "tool_calling": "工具调用",
            "streaming": "流式反馈",
            "vision": "视觉",
        }
        reasons.append(
            "缺少能力："
            + "、".join(labels.get(item, item) for item in missing_capabilities)
        )
    if not data_compatible:
        reasons.append("数据分类范围与当前 Agent 不兼容")
    if not runtime_binding_compatible:
        reasons.append("缺少该 Agent Runtime 的精确绑定证据")
    if not policy_binding_compatible:
        reasons.append("缺少该部门 Policy 的精确绑定证据")
    if not company_approved:
        reasons.append("公司批准证据无效或已撤销")
    if not health_evidence_valid:
        reasons.append("公司健康快照缺失、过期或未通过")
    compatible = (
        agent_registered
        and allowed_by_binding
        and not missing_capabilities
        and data_compatible
        and runtime_binding_compatible
        and policy_binding_compatible
        and company_approved
        and health_evidence_valid
    )
    if compatible:
        reasons.append("满足当前 Agent 的能力、数据与允许列表要求")
    return {
        "compatible": compatible,
        "agent_registration_valid": agent_registered,
        "allowed_by_binding": allowed_by_binding,
        "missing_capabilities": missing_capabilities,
        "data_classification_compatible": data_compatible,
        "runtime_binding_compatible": runtime_binding_compatible,
        "policy_binding_compatible": policy_binding_compatible,
        "company_approval_valid": company_approved,
        "health_evidence_valid": health_evidence_valid,
        "reason_summaries": reasons,
    }


def _public_agent_route(
    route: Mapping[str, Any], *, agent: Mapping[str, Any], selected: bool
) -> dict[str, Any]:
    compatibility = _route_compatibility(agent, route)
    recommendation_status = (
        "comparable" if compatibility["compatible"] else "insufficient_evidence"
    )
    if not route["recommendation_evidence_complete"]:
        recommendation_status = "insufficient_evidence"
    return {
        **_public_route(route, selected=selected),
        "blocker_codes": [*route["blocker_codes"], *(
            ["agent_registry_activation_missing"]
            if agent.get("source_kind") == "department_proposal" else []
        )],
        "compatibility": compatibility,
        "recommendation_status": recommendation_status,
        "recommendation_summary": (
            "能力与边界相容；价格、回归或任务画像证据不足，暂不标记唯一推荐"
            if compatibility["compatible"]
            else "当前路线不能用于此 Agent"
        ),
        "recommendation_evidence_expires_at": None,
        "selectable": bool(route["selectable"] and compatibility["compatible"]),
    }


def _planning_agent_binding_ref(department_id: str) -> str:
    return f"binding_{department_id}_planning_d0"


def _professional_agent_binding_ref(department_id: str) -> str:
    return f"binding_{department_id}_professional_d0"


def _model_selection_digest(selection: Mapping[str, Any]) -> str:
    return canonical_digest(
        {
            "department_id": selection["department_id"],
            "agent_ref": selection["agent_ref"],
            "agent_binding_ref": selection["agent_binding_ref"],
            "route_id": selection["route_id"],
            "route_revision_digest": selection["route_revision_digest"],
            "revision": selection["revision"],
        }
    )


def _empty_usage_bucket(
    *, agent_ref: str | None = None, route_alias: str | None = None
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "input_tokens": 0,
        "output_tokens": 0,
        "model_calls": 0,
        "receipt_count": 0,
        "cost_cny": None,
        "cost_status": "verified_price_observation_unavailable",
    }
    if agent_ref is not None:
        value["agent_ref"] = agent_ref
    if route_alias is not None:
        value["route_alias"] = route_alias
    return value


def _seed_model_route_selection(department_id: str) -> dict[str, Any]:
    agent = _agents(department_id)[0]
    return _seed_agent_model_route_selection(
        department_id=department_id, agent=agent, legacy=None
    )


def _seed_agent_model_route_selection(
    *,
    department_id: str,
    agent: Mapping[str, Any],
    legacy: Mapping[str, Any] | None,
) -> dict[str, Any]:
    default_route_alias = str(agent["model_route_refs"][0])
    route_alias = (
        str(legacy["route_alias"]) if legacy is not None else default_route_alias
    )
    if route_alias not in agent["model_route_refs"]:
        route_alias = default_route_alias
    route = next(
        item
        for item in _model_route_catalog(department_id)
        if item["route_alias"] == route_alias
    )
    selection = {
        "department_id": department_id,
        "agent_ref": agent["agent_id"],
        "agent_binding_ref": agent["agent_binding_ref"],
        "route_id": route["route_id"],
        "route_alias": route["route_alias"],
        "route_revision_digest": route["route_revision_digest"],
        "revision": int(legacy.get("revision", 1)) if legacy is not None else 1,
        "selected_by_ref": (
            legacy.get("selected_by_ref", "company_control_plane_d0_default")
            if legacy is not None
            else "company_control_plane_d0_default"
        ),
        "selected_at": (
            legacy.get("selected_at", "2026-09-01T00:00:00Z")
            if legacy is not None
            else "2026-09-01T00:00:00Z"
        ),
        "receipt_id": legacy.get("receipt_id") if legacy is not None else None,
        "company_approval_status": "d0_approved",
        "provider_details_visible": False,
        "production_authorized": False,
        "release_authorization": False,
    }
    selection["selection_digest"] = _model_selection_digest(selection)
    return selection


def _seed_tasks() -> dict[str, dict[str, Any]]:
    values: dict[str, dict[str, Any]] = {}
    seeds = {
        "product_center": (
            ("task_product_syn_001", "整理新功能需求优先级", "running", "running"),
            ("task_product_syn_002", "确认移动端验收范围", "paused", "blocked"),
        ),
        "technology_center": (
            ("task_technology_syn_001", "评审服务接口拆分方案", "queued", "ready"),
            ("task_technology_syn_002", "补齐前端回归测试", "running", "done"),
        ),
        "market_center": (
            ("task_market_syn_001", "形成公开内容发布计划", "draft", "triage"),
            ("task_market_syn_002", "复盘本周渠道反馈", "succeeded", "done"),
        ),
    }
    for department_id, records in seeds.items():
        for task_id, title, authority_state, runtime_state in records:
            values[task_id] = {
                "task_id": task_id,
                "revision": 1,
                "department_id": department_id,
                "title": title,
                "purpose": "D0 合成验收任务，不连接真实业务数据",
                "professional_agent_ref": f"agent_{department_id}_professional_syn",
                "professional_agent_name": _agents(department_id)[1]["name"],
                "authority_state": authority_state,
                "runtime_projection_state": runtime_state,
                "model_route_alias": ("company-route/planning-minimax-cn-approved"),
                "runtime_projection_authoritative": False,
                "projection_drift": runtime_state == "done"
                and authority_state == "running",
                "ui_column": _ui_column(authority_state),
                "risk_level": "low",
                "data_classification": "synthetic",
                "side_effects": False,
                "responsible_human_ref": f"human_{department_id}_owner_syn",
                "responsible_name": f"{_departments()[department_id]['short']}负责人",
                "budget_summary": "合成预算 · 上限 30 分钟",
                "deadline_summary": "本地验收窗口",
                "last_event_at": "2026-08-31T09:00:00Z",
                "evidence_status": "synthetic",
            }
    return values


def _ui_column(state: str) -> str:
    if state in {"draft", "need_details"}:
        return "inbox"
    if state == "awaiting_confirmation":
        return "awaiting_confirmation"
    if state in {"pending_approval", "queued"}:
        return "pending_execution"
    if state == "running":
        return "running"
    if state == "paused":
        return "needs_user"
    return "closed"


def _planning_task(
    *,
    department_id: str,
    task_id: str,
    title: str,
    actor_ref: str,
    actor_name: str | None,
    run_id: str,
    model_route_alias: str,
) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "revision": 1,
        "department_id": department_id,
        "title": title,
        "purpose": title,
        "professional_agent_ref": None,
        "professional_agent_name": "待规划 Agent 推荐",
        "authority_state": "need_details",
        "runtime_projection_state": "triage",
        "runtime_run_ref": run_id,
        "model_route_alias": model_route_alias,
        "runtime_projection_authoritative": False,
        "projection_drift": False,
        "ui_column": "inbox",
        "risk_level": "unassessed",
        "data_classification": "synthetic",
        "side_effects": False,
        "responsible_human_ref": actor_ref,
        "responsible_name": actor_name
        or f"{_departments()[department_id]['short']}负责人",
        "budget_summary": "待任务包确认",
        "deadline_summary": "待任务包确认",
        "last_event_at": _now(),
        "evidence_status": "synthetic",
    }


def _question_card(
    *,
    task_id: str,
    revision: int,
    round_number: int = 1,
    questions: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    projected_questions = list(questions or _workflow_questions("product_center", 1))
    return {
        "request_id": _stable_id(
            "clarification",
            {
                "task_id": task_id,
                "revision": revision,
                "round_number": round_number,
            },
        ),
        "task_id": task_id,
        "revision": revision,
        "round_number": round_number,
        "questions": projected_questions,
        "supplement_allowed": True,
        "scope_impact": "none",
    }


def _workflow_questions(
    department_id: str, round_number: int, *, strict: bool = False
) -> list[dict[str, Any]]:
    _departments()[department_id]
    common = [
        {
            "question_id": "expected_output",
            "label": "用户与问题：这次最需要形成什么成果？",
            "options": [
                {
                    "option_id": "structured_plan",
                    "label": "结构化方案（推荐）",
                    "description": "便于后续评审、分工和验收。",
                    "recommended": True,
                },
                {
                    "option_id": "review_report",
                    "label": "评审报告",
                    "description": "聚焦问题、风险与改进建议。",
                    "recommended": False,
                },
                {
                    "option_id": "execution_checklist",
                    "label": "执行清单",
                    "description": "适合目标已清楚、需要直接分步推进。",
                    "recommended": False,
                },
            ],
        },
        {
            "question_id": "completion_mode",
            "label": "验收标准：怎样判断这项工作完成？",
            "options": [
                {
                    "option_id": "owner_review",
                    "label": "负责人评审（推荐）",
                    "description": "由负责人对照任务包逐项确认。",
                    "recommended": True,
                },
                {
                    "option_id": "checklist_pass",
                    "label": "检查项全部通过",
                    "description": "用固定规则形成可重复验收。",
                    "recommended": False,
                },
            ],
        },
    ]
    if department_id == "product_center":
        return [
            common[0],
            {
                "question_id": "scope_non_goal",
                "label": "范围与非目标：本轮应怎样收口？",
                "options": [
                    {
                        "option_id": "narrow_scope",
                        "label": "窄范围先验收（推荐）",
                        "description": "先固定最小范围和明确非目标。",
                        "recommended": True,
                    },
                    {
                        "option_id": "full_scope",
                        "label": "完整范围一次验收",
                        "description": "仅在所有依赖与非目标均已明确时选择。",
                        "recommended": False,
                    },
                ],
            },
            common[1],
        ]
    if not strict:
        return common
    extra_by_department = {
        "technology_center": {
            1: (
                "current_dependency",
                "当前实现、依赖和接口中，哪一项最需要先固定？",
                ("interface_first", "先固定接口", "dependency_first", "先固定依赖"),
            ),
            2: (
                "test_rollback",
                "测试与回滚证据应优先采用哪种方式？",
                ("automated", "自动化验证", "reviewed", "人工评审记录"),
            ),
            3: (
                "delivery_evidence",
                "最终交付证据以什么为主？",
                ("test_receipt", "测试回执", "diff_review", "变更评审"),
            ),
        },
        "product_center": {},
        "market_center": {
            1: (
                "channel_compliance",
                "渠道与合规边界应优先怎样确定？",
                ("compliance_first", "先定合规边界", "channel_first", "先定渠道"),
            )
        },
    }
    extra = extra_by_department[department_id].get(round_number)
    if extra is None:
        return common[:1]
    question_id, label, values = extra
    return [
        *common,
        {
            "question_id": question_id,
            "label": label,
            "options": [
                {
                    "option_id": values[0],
                    "label": values[1] + "（推荐）",
                    "description": "用于形成可验证且边界清楚的任务包。",
                    "recommended": True,
                },
                {
                    "option_id": values[2],
                    "label": values[3],
                    "description": "保留为负责人可选择的替代路径。",
                    "recommended": False,
                },
            ],
        },
    ]


def _workflow_required_sections(department_id: str) -> list[str]:
    return {
        "technology_center": [
            "目标",
            "现状",
            "依赖",
            "接口",
            "测试",
            "回滚",
            "交付证据",
        ],
        "product_center": ["用户与问题", "范围与非目标", "验收标准"],
        "market_center": ["受众与目标", "渠道和合规", "衡量方式"],
    }[department_id]


def _workflow_package_candidate(department_id: str) -> dict[str, Any]:
    sections = _workflow_required_sections(department_id)
    return {
        "sections": [
            {"name": name, "summary": f"由负责人确认的{name}边界"}
            for name in sections
        ],
        "risk_summary": "仅处理合成或公开文本；不得扩大数据、工具或权限范围。",
        "validation": {
            "schema_valid": True,
            "required_sections_complete": True,
            "policy_valid": True,
        },
    }


def _validate_question_projection(output: Mapping[str, Any]) -> list[dict[str, Any]]:
    if output.get("result_kind") != "questions":
        raise DepartmentCockpitError("planning_question_structure_invalid")
    questions = output.get("questions")
    if not isinstance(questions, list) or not 1 <= len(questions) <= 3:
        raise DepartmentCockpitError("planning_question_structure_invalid")
    result: list[dict[str, Any]] = []
    for question in questions:
        if (
            not isinstance(question, dict)
            or not isinstance(question.get("question_id"), str)
            or not isinstance(question.get("label"), str)
            or not isinstance(question.get("options"), list)
            or not 2 <= len(question["options"]) <= 3
        ):
            raise DepartmentCockpitError("planning_question_structure_invalid")
        result.append(json.loads(json.dumps(question, ensure_ascii=False)))
    return result


def _validate_package_candidate(
    output: Mapping[str, Any], department_id: str
) -> dict[str, Any]:
    if output.get("result_kind") != "task_package_candidate" or not isinstance(
        output.get("candidate"), dict
    ):
        raise DepartmentCockpitError("planning_package_structure_invalid")
    candidate = dict(output["candidate"])
    sections = candidate.get("sections")
    names = {
        item.get("name")
        for item in sections
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    } if isinstance(sections, list) else set()
    if not set(_workflow_required_sections(department_id)).issubset(names):
        raise DepartmentCockpitError("planning_package_required_section_missing")
    validation = candidate.get("validation")
    if not isinstance(validation, dict) or not all(
        validation.get(key) is True
        for key in ("schema_valid", "required_sections_complete", "policy_valid")
    ):
        raise DepartmentCockpitError("planning_package_validation_failed")
    return json.loads(json.dumps(candidate, ensure_ascii=False))


def _formal_question_request(
    card: Mapping[str, Any], planning_agent_ref: str
) -> dict[str, Any]:
    formal_questions = []
    for question in card["questions"]:
        options = [
            {
                "option_id": f"option_{option['option_id']}",
                "label": option["label"],
                "description": option["description"],
            }
            for option in question["options"]
        ]
        recommended = next(
            (item for item in question["options"] if item.get("recommended")),
            question["options"][0],
        )
        formal_questions.append(
            {
                "question_id": f"question_{question['question_id']}",
                "prompt": question["label"],
                "options": options,
                "recommended_option_id": f"option_{recommended['option_id']}",
                "free_text_allowed": True,
            }
        )
    return {
        "api_version": "company-ai-os/v1alpha2",
        "kind": "TaskClarificationRequest",
        "metadata": {
            "request_id": card["request_id"],
            "task_id": card["task_id"],
            "version": "0.2.0",
            "status": "open",
            "evidence_status": "synthetic",
            "synthetic_only": True,
            "created_at": _now(),
        },
        "spec": {
            "package_ref": {
                "id": "pkg_pending_planning_syn",
                "version": "0.2.0",
                "digest": canonical_digest(
                    {"task_id": card["task_id"], "round": card["round_number"]}
                ),
            },
            "requested_by_agent_ref": {
                "id": _schema_id(planning_agent_ref),
                "version": "0.2.0",
                "digest": canonical_digest({"agent_ref": planning_agent_ref}),
            },
            "questions": formal_questions,
            "scope_impact": "none",
            "resume_disposition": "same_task_new_revision",
            "response": None,
            "release_authorization": False,
        },
    }


def _professional_task_package(
    *,
    session: Mapping[str, Any],
    task: Mapping[str, Any],
    answers: Mapping[str, str],
    supplement: str | None,
    professional_task_id: str | None = None,
    candidate: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    department_id = task["department_id"]
    effective_task_id = professional_task_id or task["task_id"]
    effective_candidate = dict(candidate or _workflow_package_candidate(department_id))
    package_id = _stable_id(
        "package",
        {
            "session_id": session["session_id"],
            "task_id": effective_task_id,
            "answers": dict(answers),
            "supplement": supplement,
        },
    )
    department_ref = {
        "id": f"department_{department_id}_syn",
        "version": "0.1.0",
        "digest": canonical_digest(
            {"department_id": department_id, "synthetic_only": True}
        ),
    }
    output_ref = {
        "id": f"contract_{department_id}_general_output_syn",
        "version": "0.1.0",
        "digest": canonical_digest(
            {"department_id": department_id, "output": answers["expected_output"]}
        ),
    }
    capability = {
        "product_center": "product.requirements.prepare",
        "technology_center": "technology.implementation.review",
        "market_center": "market.content.plan",
    }[department_id]
    value = {
        "api_version": "company-ai-os/v1alpha2",
        "kind": "ProfessionalTaskPackage",
        "metadata": {
            "package_id": package_id,
            "task_id": effective_task_id,
            "department_ref": department_ref,
            "version": "0.1.0",
            "revision": 1,
            "status": "ready",
            "evidence_status": "synthetic",
            "synthetic_only": True,
            "created_at": _now(),
        },
        "spec": {
            "goal": task["purpose"],
            "requested_capability": capability,
            "input_artifact_refs": list(session.get("artifact_refs", [])),
            "success_criteria": [
                answers["completion_mode"],
                "所有事实保持合成证据标记",
                *[
                    f"{item['name']}：{item['summary']}"
                    for item in effective_candidate["sections"]
                ],
            ],
            "output_contract_refs": [output_ref],
            "data_classification": task["data_classification"],
            # The local delivery adapter supplies a fixed host-owned template.
            # Model output and HTTP callers cannot select these operations.
            "requested_tool_operations": list(session.get("professional_tool_operations", [])),
            "side_effects_requested": False,
            "prohibited_actions": [
                "不得对外发布",
                "不得读取本机路径或扩大数据范围",
                "不得选择或改变 Agent、Model Route、工具、权限或批准状态",
            ],
            "budget": {
                "max_runtime_seconds": 1800,
                "max_model_tokens": 12000,
                "max_tool_calls": 0,
            },
            "deadline_at": "2026-09-07T00:00:00Z",
            "package_digest": "",
            "release_authorization": False,
        },
    }
    if supplement:
        value["spec"]["success_criteria"].append(supplement)
    digest_input = json.loads(json.dumps(value))
    del digest_input["spec"]["package_digest"]
    value["spec"]["package_digest"] = canonical_digest(digest_input)
    return value


def _professional_child_task(
    *,
    parent_task: Mapping[str, Any],
    professional_task_id: str,
    package: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "task_id": professional_task_id,
        "parent_task_ref": parent_task["task_id"],
        "task_kind": "professional_child",
        "revision": 1,
        "department_id": parent_task["department_id"],
        "title": parent_task["title"],
        "purpose": parent_task["purpose"],
        "professional_agent_ref": (
            f"agent_{parent_task['department_id']}_professional_syn"
        ),
        "professional_agent_name": _agents(parent_task["department_id"])[1]["name"],
        "authority_state": "pending_approval",
        "department_approval_status": "not_reviewed",
        "runtime_projection_state": "not_started",
        "runtime_projection_authoritative": False,
        "model_route_alias": parent_task["model_route_alias"],
        "data_classification": parent_task["data_classification"],
        "side_effects": False,
        "responsible_human_ref": parent_task["responsible_human_ref"],
        "responsible_name": parent_task["responsible_name"],
        "ui_column": "awaiting_confirmation",
        "risk_level": "bounded",
        "package_ref": package["metadata"]["package_id"],
        "planning_ready": True,
        "professional_execution_ready": False,
        "last_event_at": _now(),
        "evidence_status": "synthetic",
    }


def _planning_execution_grant(
    *,
    task_id: str,
    department_id: str,
    binding: PlanningRuntimeBinding,
    planning_selection: Mapping[str, Any],
) -> dict[str, Any]:
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(minutes=30)
    route_ref_id = _schema_id(str(planning_selection["route_id"]))
    return {
        "api_version": "company-ai-os/v1alpha1",
        "kind": "ExecutionGrant",
        "metadata": {
            "grant_id": _stable_id(
                "grant_planning",
                {
                    "task_id": task_id,
                    "route_revision_digest": planning_selection[
                        "route_revision_digest"
                    ],
                },
            ),
            "version": "0.2.0",
            "task_id": task_id,
            "status": "active",
            "evidence_status": "synthetic",
            "synthetic_only": True,
            "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        },
        "spec": {
            "agent_definition_ref": {
                "id": _schema_id(binding.planning_agent_ref),
                "version": "0.2.0",
                "digest": canonical_digest(
                    {"agent_definition_ref": binding.agent_definition_ref}
                ),
            },
            "binding_ref": {
                "id": _schema_id(str(planning_selection["agent_binding_ref"])),
                "version": "0.2.0",
                "digest": canonical_digest(
                    {
                        "selection_digest": planning_selection[
                            "selection_digest"
                        ]
                    }
                ),
            },
            "workload_identity_ref": f"wid_{department_id}_planning_syn",
            "autonomy_level": "L1",
            "tool_scopes": [],
            "data_scopes": [
                {
                    "request_name": "planning_text",
                    "asset_scope_refs": ["dataset://synthetic/planning-text/0.2.0"],
                    "classifications": ["synthetic", "public"],
                    "operations": ["query"],
                    "policy_refs": [f"pol_{department_id}_planning_d0"],
                }
            ],
            "agent_scopes": [],
            "model_route_refs": [
                {
                    "id": route_ref_id,
                    "version": "0.2.0",
                    "digest": planning_selection["route_revision_digest"],
                }
            ],
            "memory_classes": ["working"],
            "environment": {
                "environment_id": f"env_{department_id}_planning_syn",
                "security_zone": "corporate_office",
                "filesystem": "deny",
                "network": "allowlisted",
                "workspace_mode": "none",
            },
            "resource_limits": {
                "max_tool_calls": 0,
                "max_concurrency": 1,
                "max_runtime_seconds": 1800,
                "max_model_tokens": 24000,
            },
            "source_decision_refs": [
                "policy-decision://department-planning/deterministic",
                str(planning_selection["selection_digest"]),
            ],
            "explicit_denies": [
                "all tool operations and side effects",
                "internal standard medical and unscanned file content",
                "agent route permission and approval selection",
                "agent to agent call handoff delegation and spawn",
            ],
            "revocation": {
                "on_task_terminal": True,
                "on_owner_revocation": True,
                "on_policy_change": "recompute_or_revoke",
            },
        },
    }


def _task_scope_digest(task: Mapping[str, Any]) -> str:
    return canonical_digest(
        {
            "task_id": task["task_id"],
            "revision": task["revision"],
            "department_id": task["department_id"],
            "purpose": task["purpose"],
            "data_classification": task["data_classification"],
            "side_effects": task["side_effects"],
            "model_route_alias": task["model_route_alias"],
        }
    )


def _planning_event(
    sequence: int, event_type: str, stage: str, resource_revision: int
) -> dict[str, Any]:
    value = {
        "sequence": sequence,
        "event_type": event_type,
        "resource_revision": resource_revision,
    }
    if event_type in {
        "planning.package_ready",
        "planning.clarification_blocked",
        "planning.provider_failed",
        "planning.failed_closed",
        "planning.stop_recorded",
        "planning.successor_created",
    }:
        return value
    return {**value, "stage": stage, "recorded_at": _now()}


def _reject_prompt_injection(value: str) -> None:
    if _PROMPT_INJECTION.search(value):
        raise DepartmentCockpitError("planning_prompt_injection_rejected")


def _schema_id(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9_-]+", "_", value.lower()).strip("_")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "ref_" + cleaned
    return cleaned[:72]


def _parse_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise DepartmentCockpitError("planning_datetime_invalid") from error
    if parsed.tzinfo is None:
        raise DepartmentCockpitError("planning_datetime_invalid")
    return parsed.astimezone(timezone.utc)


def _optional_safe_text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 192:
        raise DepartmentCockpitError("planning_evidence_identifier_invalid")
    if _SENSITIVE_EVIDENCE.search(value):
        raise DepartmentCockpitError("planning_evidence_sensitive")
    return value


def _nonnegative_int(value: Any) -> int:
    return value if type(value) is int and value >= 0 else 0

