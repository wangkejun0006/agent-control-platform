"""Delivery orchestration links native Tasks, approvals, queue, leases and evaluation.

Workflow records store relationships and immutable evidence, not a second
authoritative queue/task state machine. Every reviewer is a real local session;
the identity and permissions remain explicitly non-production.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import threading
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from orbit_agent_control_plane.evaluator import CompanyEvaluator
from orbit_agent_control_plane.ids import COMPANY_TASK_ROUTER_AGENT_ID
from orbit_agent_control_plane.models import (
    AgentReleaseSelection,
    AuditEvent,
    RoutingTarget,
    RuntimeCompositionRequest,
    TaskEnvelope,
    TaskResult,
    ToolCapabilityRequirement,
)
from orbit_agent_control_plane.router import CompanyTaskRouter, RuntimeComposer
from orbit_agent_control_plane.service_runtime.department_cockpit import (
    DeterministicPlanningModelPort,
)
from orbit_agent_control_plane.service_runtime.models import (
    ReceiptRow,
    RuntimeRunRow,
    WorkerLeaseRow,
)
from orbit_agent_control_plane.service_runtime.repositories import (
    SqlGrantRevocationRegistry,
)
from orbit_agent_control_plane.service_runtime.runner_queue import (
    SqlRunnerTransport,
    SqlSignedGrantRegistry,
    build_signed_grant_document,
    canonical_bytes,
)
from orbit_agent_control_plane.service_runtime.runtime_adapter import RuntimeInvocation
from orbit_agent_control_plane.service_runtime.security import (
    Ed25519EvaluationGrantSigner,
    Ed25519EvaluationGrantVerifier,
)
from showcase.live_budget import (
    atomic_private,
    digest,
    encoded,
    private_read,
    require,
    strict_json,
)

from .assets import DEPARTMENTS, DEPT_NAMES, HERE, DeliveryAssets
from .documents import parse_document
from .model_gateway import DeliveryModelGateway
from .storage import DeliveryRecordRow, DeliveryStore
from .tools import OPERATIONS

ROOT = HERE.parents[1]
SCENARIOS = (
    "normal",
    "scope_conflict",
    "missing_evidence",
    "permission_failure",
    "slow",
    "timeout",
)


def stamp():
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def identifier(prefix):
    return prefix + "_" + uuid.uuid4().hex[:20]


def legacy_human_ref(local_ref):
    """Reversible identifier bridge after cookie authentication and role checks.

    Local identity issues hum_local_*; inherited queue/governance consumers
    require human_*. Stripping human_ resolves to the exact local account ref.
    This mapping never creates a principal or adds a role.
    """
    require(
        isinstance(local_ref, str)
        and re.fullmatch(r"hum_local_[0-9a-f]{24}_syn", local_ref),
        "local_identity_bridge_invalid",
    )
    return "human_" + local_ref


def source_revision():
    paths = [
        HERE / "tools.py",
        HERE / "documents.py",
        HERE / "worker.py",
        HERE / "model_gateway.py",
        HERE / "live.py",
        HERE / "sharing_policy.py",
        HERE / "content_contract.py",
        HERE / "planning_contract.py",
        HERE / "assets.py",
        *sorted((HERE / "contracts").glob("*.json")),
    ]
    require(
        all(p.is_file() and not p.is_symlink() for p in paths),
        "delivery_source_invalid",
    )
    return digest(
        {
            str(p.relative_to(HERE)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in paths
        }
    )


class OfflineDeliveryPlanningPort(DeterministicPlanningModelPort):
    live_model_enabled = False

    def invoke(self, **kwargs):
        value = dict(
            DeliveryModelGateway().offline(
                lambda: super(OfflineDeliveryPlanningPort, self).invoke(**kwargs)
            )
        )
        value.update(input_tokens=0, output_tokens=0, cost_cny_micros=0)
        if value.get("output", {}).get("result_kind") == "task_package_candidate":
            from .sharing_policy import POLICY_TEXT

            value["output"]["candidate"]["risk_summary"] += " " + POLICY_TEXT
        return value


def queue_components(database, root):
    key_file = root / "local-signing.pem"
    if not key_file.exists():
        raw = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(
            key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    signer = Ed25519EvaluationGrantSigner(
        private_key_pem=private_read(key_file), key_id="delivery_local_signer"
    )
    revocations = SqlGrantRevocationRegistry(database)
    grants = SqlSignedGrantRegistry(
        database,
        verifier=Ed25519EvaluationGrantVerifier(
            public_key_pem=signer.public_key_pem(), key_id="delivery_local_signer"
        ),
        revocations=revocations,
    )
    return signer, revocations, grants, SqlRunnerTransport(database, grants=grants)


class DeliveryService:
    def __init__(self, runtime, cockpit, root):
        self.runtime, self.database, self.cockpit, self.root = (
            runtime,
            runtime.database,
            cockpit,
            Path(root),
        )
        self.store = DeliveryStore(self.database)
        self.assets = DeliveryAssets(self.root)
        self.signer, self.revocations, self.grants, self.transport = queue_components(
            self.database, self.root
        )
        self.lock = threading.RLock()
        self.live_campaign = None

    def model_usage(self):
        if self.live_campaign is None:
            return {
                "model_requests": 0,
                "cost_cny_micros": 0,
                "live_model_enabled": False,
            }
        state = self.live_campaign.state()
        return {
            "model_requests": len(state["attempts"]),
            "cost_cny_micros": self.live_campaign.charge(state),
            "live_model_enabled": True,
            "campaign_closed": state["closed"],
            "request_limit": state["max_requests"],
            "cost_limit_cny_micros": state["max_cost_micros"],
            "usage_scope": "entire_explicit_campaign_including_failed_requests",
        }

    def current_sharing_checks(self, candidate):
        from .content_contract import payload_checks
        from .sharing_policy import VERSION, sharing_checks

        payload = (candidate or {}).get("payload", {})
        prose = payload.get("authored_prose", "")
        body = payload.get("body", "")
        # Bind the independently checked region, not an arbitrary safe appendix.
        actual = (
            body.partition("\n\n## 部门交付说明\n")[2].partition("\n\n## 依据\n")[0]
            if isinstance(body, str)
            else ""
        )
        attempt = self.store.get((candidate or {}).get("attempt_id", "")) or {}
        return (
            sharing_checks(prose if isinstance(prose, str) else "")
            + payload_checks(
                payload,
                attempt.get("documents", []),
                (candidate or {}).get("department_id", ""),
            )
            + [
                {
                    "name": "当前规则版本与正文检查范围一致",
                    "code": "current_policy_and_prose_binding",
                    "passed": bool(prose)
                    and prose == actual
                    and payload.get("sharing_policy_version") == VERSION,
                }
            ]
        )

    def require_current_sharing(self, candidate):
        require(
            all(c["passed"] for c in self.current_sharing_checks(candidate)),
            "当前共享语义规则未通过，请保留旧记录并创建修订",
        )

    def command(self, principal, key, request, operation):
        require(
            isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9._:-]{8,120}", key),
            "idempotency_key_invalid",
        )
        command_key = (
            "command:" + digest({"key": key, "actor": principal["human_ref"]})[7:]
        )
        request_digest = digest(request)
        with self.lock:
            previous = self.store.get(command_key)
            if previous:
                require(
                    previous["request_digest"] == request_digest, "idempotency_conflict"
                )
                require(
                    previous["status"] == "completed",
                    "previous_command_failed_use_new_key",
                )
                return previous["response"]
            document = {
                "request_digest": request_digest,
                "status": "pending",
                "actor": principal["human_ref"],
            }
            self.store.put("command", command_key, document)
            try:
                response = operation()
            except Exception as error:
                document.update(
                    status="failed",
                    reason=str(error)
                    if isinstance(error, ValueError)
                    else getattr(error, "reason_code", "command_failed"),
                )
                self.store.put("command", command_key, document, mutable=True)
                raise
            document.update(status="completed", response=response)
            self.store.put("command", command_key, document, mutable=True)
            return response

    @staticmethod
    def authorize(principal, department=None, *, owner=False, admin=False):
        roles = set(principal.get("role_refs", []))
        if "role_control_plane_admin" in roles:
            return
        require(not admin, "需要管理员权限")
        require(department in principal.get("department_refs", []), "无权访问此部门")
        if owner:
            require("role_department_owner" in roles, "需要本部门负责人审核")

    def event(self, workflow_id, kind, payload):
        previous = self.store.list("event", workflow_id)
        record = {
            "event_id": identifier("event"),
            "sequence": len(previous),
            "kind": kind,
            "recorded_at": stamp(),
            "payload": payload,
            "previous_digest": digest(previous[-1]) if previous else "genesis",
        }
        self.store.put("event", record["event_id"], record, workflow_id=workflow_id)
        return record

    def workflow(self, workflow_id):
        value = self.store.get(workflow_id)
        require(
            value is not None and value.get("kind") == "DeliveryWorkflow",
            "交付任务不存在",
        )
        return value

    def create(self, principal, body):
        department = body.get("department_id", "product_center")
        require(department == "product_center", "交付从产品部门发起")
        self.authorize(principal, department)
        title, goal = body.get("title", "").strip(), body.get("goal", "").strip()
        require(
            2 <= len(title) <= 100 and 8 <= len(goal) <= 1500,
            "请填写任务标题和具体交付目标",
        )
        scenario = body.get("scenario", "normal")
        require(scenario in SCENARIOS, "scenario_invalid")
        workflow_id = identifier("workflow")
        record = {
            "kind": "DeliveryWorkflow",
            "workflow_id": workflow_id,
            "title": title,
            "goal": goal,
            "template": "knowledge-assistant-delivery/1",
            "created_by": principal["human_ref"],
            "created_at": stamp(),
            "scenario": scenario,
            "nodes": {d: {"attempt_ids": [], "current": None} for d in DEPARTMENTS},
            "model_mode": "offline_deterministic",
            "production_authorized": False,
        }
        self.store.put("workflow", workflow_id, record, workflow_id=workflow_id)
        self.event(
            workflow_id,
            "workflow_created",
            {"actor": principal["human_ref"], "template": record["template"]},
        )
        return self.view(principal, workflow_id)

    def documents(self, workflow_id, department=None, *, active=False):
        docs = self.store.list("artifact", workflow_id)
        if department:
            docs = [d for d in docs if d["department_id"] == department]
        if active:
            latest = {}
            for doc in docs:
                latest[doc["document_id"]] = max(
                    doc["version"], latest.get(doc["document_id"], 0)
                )
            docs = [d for d in docs if d["version"] == latest[d["document_id"]]]
        return docs

    def upload(self, principal, workflow_id, body):
        self.workflow(workflow_id)
        department = body["department_id"]
        require(department in DEPARTMENTS, "department_invalid")
        self.authorize(principal, department)
        current = self.attempt(workflow_id, department)
        require(
            current is None
            or current.get("invalidated")
            or self.node_state(current)["status"] in {"failed", "cancelled", "blocked"},
            "规划后资料不可原地替换，请先从产物审核退回；新资料仅供新尝试使用",
        )
        try:
            content = base64.b64decode(body["content_base64"], validate=True)
        except (ValueError, TypeError):
            require(False, "资料编码无效")
        parsed = parse_document(body["filename"], content)
        version = body.get("version", 1)
        require(type(version) is int and 1 <= version <= 1000, "资料版本无效")
        document_id = body.get("document_id") or Path(body["filename"]).stem
        require(
            isinstance(document_id, str)
            and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", document_id),
            "资料ID须为字母数字或横线",
        )
        native = self.cockpit.artifact_store.upload(
            department_id=department,
            filename=body["filename"],
            media_type=parsed["media_type"],
            content=content,
            data_classification="public",
            actor_ref=principal["human_ref"],
        )
        key = (
            "artifact:"
            + digest(
                {
                    "workflow": workflow_id,
                    "ref": native["artifact_ref"],
                    "version": version,
                }
            )[7:]
        )
        document = {
            "record_id": key,
            "artifact_ref": native["artifact_ref"],
            "filename": body["filename"],
            "document_id": document_id,
            "version": version,
            "department_id": department,
            "shared_with": [department],
            "scan_status": "stored_unscanned",
            **parsed,
        }
        self.store.put(
            "artifact", key, document, workflow_id=workflow_id, department_id=department
        )
        self.event(
            workflow_id,
            "document_parsed",
            {
                "artifact_ref": native["artifact_ref"],
                "department_id": department,
                "version": version,
                "parse_status": "parsed",
                "warnings": parsed["warnings"],
            },
        )
        return {"artifact": document}

    def import_fixtures(self, principal, workflow_id):
        self.authorize(principal, admin=True)
        self.workflow(workflow_id)
        manifest = strict_json((HERE / "fixtures/manifest.json").read_bytes())
        for dept in DEPARTMENTS:
            for doc in manifest["documents"]:
                content = (HERE / "fixtures" / doc["filename"]).read_bytes()
                require(
                    hashlib.sha256(content).hexdigest() == doc["sha256"],
                    "fixture_source_drift",
                )
                self.upload(
                    principal,
                    workflow_id,
                    {
                        **doc,
                        "department_id": dept,
                        "content_base64": base64.b64encode(content).decode(),
                    },
                )
        self.event(
            workflow_id,
            "fixture_share_authorized",
            {
                "actor": principal["human_ref"],
                "departments": list(DEPARTMENTS),
                "documents": 13,
                "synthetic_only": True,
            },
        )
        return self.view(principal, workflow_id)

    def attempt(self, workflow_id, department):
        workflow = self.workflow(workflow_id)
        require(department in DEPARTMENTS, "department_invalid")
        key = workflow["nodes"][department]["current"]
        return self.store.get(key) if key else None

    def start_plan(self, principal, workflow_id, department, key):
        self.authorize(principal, department)
        workflow = self.workflow(workflow_id)
        current = self.attempt(workflow_id, department)
        if current:
            require(
                current.get("invalidated") or current.get("retry_allowed"),
                "当前尝试已存在，请继续澄清或执行",
            )
            if current.get("run_id"):
                require(
                    self.transport.status(current["run_id"])["status"]
                    in {"completed", "failed", "cancelled"},
                    "旧执行尚未终止，不能开始新尝试",
                )
        index = DEPARTMENTS.index(department)
        if index:
            source = self.attempt(workflow_id, DEPARTMENTS[index - 1])
            require(
                source and self.node_state(source)["status"] == "approved",
                "上游产物尚未批准",
            )
            self.require_current_sharing(
                self.store.get("candidate:" + source["attempt_id"])
            )
            require(
                any(
                    h["target_department"] == department
                    and h["source_attempt"] == source["attempt_id"]
                    for h in self.store.list("handoff", workflow_id)
                ),
                "上游尚未明确授权资料交接",
            )
        docs = self.documents(workflow_id, department, active=True)
        require(bool(docs), "请先导入本部门资料或授权的演示资料")
        manifest = {
            "documents": [
                {
                    k: d[k]
                    for k in (
                        "artifact_ref",
                        "document_id",
                        "version",
                        "content_digest",
                    )
                }
                for d in docs
            ]
        }
        bundle = self.cockpit.artifact_store.upload(
            department_id=department,
            filename="delivery-input-manifest.json",
            media_type="application/json",
            content=encoded(manifest),
            data_classification="public",
            actor_ref=principal["human_ref"],
        )
        revision = len(workflow["nodes"][department]["attempt_ids"]) + 1
        feedback = current.get("business_feedback") if current else ""
        if feedback is None:
            # Legacy untyped recovery text is not a business instruction. Only
            # an actual request-changes review can supply legacy business text.
            reviews = [
                r
                for r in self.store.list("review", workflow_id)
                if r["department_id"] == department
                and r["decision"] == "request_changes"
            ]
            feedback = reviews[-1]["reason"] if reviews else ""
        session = self.cockpit.create_session(
            department_id=department,
            actor_ref=principal["human_ref"],
            message=workflow["goal"] + ("\n修订要求：" + feedback if feedback else ""),
            artifact_refs=[bundle["artifact_ref"]],
            idempotency_key="delivery-plan:" + key,
        )
        sid = session["session_id"]
        self.cockpit.sessions[sid]["professional_tool_operations"] = list(OPERATIONS)
        self.cockpit._persist("session", sid, department, self.cockpit.sessions[sid])
        attempt_id = identifier("attempt")
        record = {
            "attempt_id": attempt_id,
            "workflow_id": workflow_id,
            "department_id": department,
            "revision": revision,
            "session_id": sid,
            "manifest_ref": bundle["artifact_ref"],
            "documents": docs,
            "snapshot_input_digest": digest(manifest),
            "run_id": None,
            "review_feedback": feedback,
            "business_feedback": feedback,
            "recovery_notes": current.get("recovery_notes", "") if current else "",
            "created_at": stamp(),
        }
        self.store.put(
            "attempt",
            attempt_id,
            record,
            workflow_id=workflow_id,
            department_id=department,
        )
        node = workflow["nodes"][department]
        node["current"] = attempt_id
        node["attempt_ids"].append(attempt_id)
        self.store.put(
            "workflow", workflow_id, workflow, workflow_id=workflow_id, mutable=True
        )
        self.event(
            workflow_id,
            "planning_started",
            {"attempt_id": attempt_id, "department_id": department, "session_id": sid},
        )
        return self.view(principal, workflow_id)

    def answer(self, principal, workflow_id, department, body, key):
        self.authorize(principal, department)
        attempt = self.attempt(workflow_id, department)
        require(
            attempt is not None and not attempt.get("invalidated"), "没有可回答的规划"
        )
        self.cockpit.continue_session(
            department_id=department,
            session_id=attempt["session_id"],
            actor_ref=principal["human_ref"],
            answers=body["answers"],
            supplement=body.get("supplement"),
            idempotency_key="delivery-turn:" + key,
        )
        self.event(
            workflow_id,
            "clarification_answered",
            {"department_id": department, "attempt_id": attempt["attempt_id"]},
        )
        return self.view(principal, workflow_id)

    def approve_plan(self, principal, workflow_id, department, body, key):
        self.authorize(principal, department, owner=True)
        attempt = self.attempt(workflow_id, department)
        require(
            attempt is not None and not attempt.get("invalidated"), "规划不存在或已失效"
        )
        response = self.cockpit.planning_session(
            department_id=department, session_id=attempt["session_id"]
        )
        subject = response["task_approval_subject"]
        require(
            subject and body.get("package_digest") == subject["package_digest"],
            "计划摘要已变化，请刷新后审核",
        )
        self.cockpit.decide_task(
            department_id=department,
            actor_ref=principal["human_ref"],
            actor_role_ref="role_department_owner",
            package_id=response["task_package"]["metadata"]["package_id"],
            **{
                k: subject[k]
                for k in (
                    "task_id",
                    "task_revision",
                    "task_scope_digest",
                    "package_digest",
                )
            },
            decision="approved",
            reason=body["reason"],
            idempotency_key="delivery-approval:" + key,
        )
        self.event(
            workflow_id,
            "plan_approved",
            {
                "department_id": department,
                "attempt_id": attempt["attempt_id"],
                "actor": principal["human_ref"],
                "subject": subject,
                "reason": body["reason"],
            },
        )
        return self.view(principal, workflow_id)

    def execute(self, principal, workflow_id, department, key):
        self.authorize(principal, department)
        workflow, attempt = (
            self.workflow(workflow_id),
            self.attempt(workflow_id, department),
        )
        require(
            attempt is not None and not attempt.get("invalidated"),
            "执行尝试不存在或已失效",
        )
        require(not attempt.get("run_id"), "该尝试已提交，不可重复执行")
        approval = [
            e
            for e in self.store.list("event", workflow_id)
            if e["kind"] == "plan_approved"
            and e["payload"]["attempt_id"] == attempt["attempt_id"]
        ]
        require(bool(approval), "计划必须由负责人确认后才可执行")
        response = self.cockpit.planning_session(
            department_id=department, session_id=attempt["session_id"]
        )
        require(
            response["task_package"]["spec"]["package_digest"]
            == approval[-1]["payload"]["subject"]["package_digest"],
            "批准计划已失效",
        )
        agent_id = "agt_delivery_" + department
        agent = self.assets.agents.replay().agent(agent_id)
        require(
            agent.status == "active",
            "专业Agent尚未评估并批准激活，请到Agent与工具页面处理",
        )
        task_id = response["task_package"]["metadata"]["task_id"]
        grant_id = "grant_delivery_" + digest(attempt["attempt_id"])[7:30]
        task = TaskEnvelope(
            task_id, "delivery." + department, "public", grant_id, True, agent_id
        )
        route = CompanyTaskRouter().route(
            task,
            [
                RoutingTarget(
                    agent_id, frozenset({task.capability}), frozenset({"public"}), True
                )
            ],
        )
        route_audit = AuditEvent(
            "audit_" + route.decision_id,
            task.task_id,
            "route_decision_recorded",
            COMPANY_TASK_ROUTER_AGENT_ID,
        )
        require(route.status == "routed", "任务路由被拒绝")
        source = source_revision()
        task_binding = {
            "task": asdict(task),
            "package_digest": response["task_package"]["spec"]["package_digest"],
            "task_scope_digest": response["task_approval_subject"]["task_scope_digest"],
        }
        snapshot = {
            "task_id": task_id,
            "attempt_id": attempt["attempt_id"],
            "department_id": department,
            "goal": workflow["goal"],
            "scenario": workflow["scenario"],
            "documents": attempt["documents"],
            "review_feedback": attempt["review_feedback"],
            "source_revision": source,
            "task_binding": task_binding,
            "manifest_ref": attempt["manifest_ref"],
        }
        if self.live_campaign is not None:
            snapshot["model_mode"] = "live_authorized_campaign"
        scoped_grant_digest = digest({"grant": grant_id, "snapshot": digest(snapshot)})
        tool_caps = frozenset(
            c for t in self.assets.bundle.candidates for c in t.capabilities
        )
        composition = RuntimeComposer().compose(
            RuntimeCompositionRequest(
                task_id=task_id,
                data_classification="public",
                agent=AgentReleaseSelection(
                    agent_id,
                    agent.candidate.release_digest,
                    frozenset({task.capability}),
                    tool_caps,
                    frozenset({"public"}),
                    True,
                ),
                tool_requirements=tuple(
                    ToolCapabilityRequirement(op, "delivery." + op, op)
                    for op in OPERATIONS
                ),
                model_route_ref="model_route_delivery_live_syn"
                if self.live_campaign
                else "model_route_delivery_offline_syn",
                model_route_digest=digest(
                    {"model_mode": snapshot.get("model_mode", "offline_deterministic")}
                ),
                policy_ref="policy_delivery_local_syn",
                policy_digest=digest({"operations": OPERATIONS, "publication": False}),
                execution_grant_ref=grant_id,
                execution_grant_digest=scoped_grant_digest,
                input_registry_revision=attempt["snapshot_input_digest"],
                budget_units=1,
            ),
            self.assets.tools.replay().tools,
        )
        atomic_private(self.root / (grant_id + ".json"), snapshot)
        invocation = RuntimeInvocation.from_mapping(
            {
                "task_id": task_id,
                "task_digest": digest(task_binding),
                "grant_id": grant_id,
                "grant_digest": scoped_grant_digest,
                "composition_digest": digest(asdict(composition)),
                "runtime_source_digest": source,
                "workload_identity": "workload_delivery_runner",
                "operation": "run_delivery_professional",
                "input_refs": [attempt["manifest_ref"]],
                "idempotency_key": "delivery-run:" + attempt["attempt_id"],
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10))
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                "timeout_seconds": 2 if workflow["scenario"] == "timeout" else 120,
                "data_classification": "public",
                "synthetic_only": True,
                "production_authorization": False,
            }
        )
        grant = build_signed_grant_document(
            invocation=invocation, evidence_status="synthetic", issued_at=stamp()
        )
        signature = self.signer.sign_grant(
            canonical_grant=canonical_bytes(grant), key_id="delivery_local_signer"
        )
        self.grants.register(
            document=grant, key_id="delivery_local_signer", signature=signature
        )
        run_id = self.transport.start(invocation=invocation)
        attempt.update(
            run_id=run_id,
            grant_id=grant_id,
            task=asdict(task),
            route=asdict(route),
            route_audit=asdict(route_audit),
            composition=asdict(composition),
            source_revision=source,
            snapshot_digest=digest(snapshot),
        )
        self.store.put(
            "attempt",
            attempt["attempt_id"],
            attempt,
            workflow_id=workflow_id,
            department_id=department,
            mutable=True,
        )
        self.event(
            workflow_id,
            "execution_queued",
            {
                "attempt_id": attempt["attempt_id"],
                "department_id": department,
                "run_id": run_id,
                "grant_id": grant_id,
                "composition_digest": invocation.composition_digest,
            },
        )
        self.native_projection(attempt, runtime_state="queued")
        return self.view(principal, workflow_id)

    def native_projection(
        self, attempt, *, runtime_state=None, authority_state=None, receipt=None
    ):
        """Update the native CompanyTask only from durable execution/review evidence."""
        task_id = attempt.get("task", {}).get("task_id")
        if not task_id:
            return
        native = self.cockpit.tasks[task_id]
        before = digest(native)
        if runtime_state:
            native["runtime_projection_state"] = runtime_state
            native["professional_run_ref"] = attempt["run_id"]
        if authority_state:
            native["authority_state"] = authority_state
            native["delivery_review_receipt_ref"] = receipt
        native["runtime_projection_authoritative"] = False
        if digest(native) != before:
            self.cockpit._persist("task", task_id, attempt["department_id"], native)

    def reconcile(self):
        with self.lock:
            for attempt in self.store.list("attempt"):
                run_id = attempt.get("run_id")
                if not run_id or self.store.get("candidate:" + attempt["attempt_id"]):
                    continue
                result = self.transport.result(run_id=run_id)
                if not result:
                    status = self.transport.status(run_id)
                    self.native_projection(attempt, runtime_state=status["status"])
                    continue
                if result["status"] != "completed":
                    self.native_projection(
                        attempt,
                        runtime_state=result["status"],
                        authority_state=result["status"],
                    )
                    record_id = "terminal:" + attempt["attempt_id"]
                    if not self.store.get(record_id):
                        payload = {
                            "attempt_id": attempt["attempt_id"],
                            "department_id": attempt["department_id"],
                            "run_id": run_id,
                            "status": result["status"],
                            "reason": result["failure_reason_code"],
                        }
                        self.store.put(
                            "terminal",
                            record_id,
                            payload,
                            workflow_id=attempt["workflow_id"],
                        )
                        self.event(
                            attempt["workflow_id"], "execution_terminal", payload
                        )
                    continue
                value = result["result"]
                task = TaskEnvelope(**attempt["task"])
                from orbit_agent_control_plane.models import RouteDecision

                route = RouteDecision(
                    **{
                        **attempt["route"],
                        "reason_codes": tuple(attempt["route"]["reason_codes"]),
                    }
                )
                route_audit = AuditEvent(**attempt["route_audit"])
                completion = AuditEvent(
                    "audit_delivery_" + attempt["attempt_id"],
                    task.task_id,
                    "synthetic_worker_completed",
                    route.target_id,
                )
                normalized = TaskResult(
                    "result_" + attempt["attempt_id"],
                    task.task_id,
                    route.target_id,
                    "completed",
                    value["artifact_ref"],
                    (completion.event_id,),
                )
                evaluation = CompanyEvaluator().evaluate(
                    task=task,
                    route_decision=route,
                    result=normalized,
                    audit_events=(route_audit, completion),
                    subject_agent_id=route.target_id,
                )
                citations = value.get("citations", [])
                docs = {d["artifact_ref"]: d for d in attempt["documents"]}
                citations_valid = bool(citations) and all(
                    c.get("artifact_ref") in docs
                    and c.get("digest") == docs[c["artifact_ref"]]["content_digest"]
                    and any(
                        x["line"] == c.get("line") and x["text"] == c.get("text")
                        for x in docs[c["artifact_ref"]]["chunks"]
                    )
                    for c in citations
                )
                from .sharing_policy import sharing_checks

                # Recompute from authored prose; do not trust worker PASS flags.
                semantic_checks = sharing_checks(value.get("authored_prose", ""))
                semantic_codes = {c["code"] for c in semantic_checks}
                checks = (
                    [
                        c
                        for c in value.get("checks", [])
                        if c.get("code") not in semantic_codes
                    ]
                    + semantic_checks
                    + [
                        {
                            "name": "受检正文与实际产物一致",
                            "passed": bool(value.get("authored_prose"))
                            and value["authored_prose"] in value.get("body", ""),
                        },
                        {
                            "name": "独立CompanyEvaluator",
                            "passed": evaluation.verdict == "pass",
                        },
                        {
                            "name": "引用对应批准的资料版本与原文",
                            "passed": citations_valid,
                        },
                        {
                            "name": "执行快照与授权绑定一致",
                            "passed": value.get("snapshot_digest")
                            == attempt["snapshot_digest"],
                        },
                        {
                            "name": "固定工具确实执行且模型模式与授权一致",
                            "passed": len(value.get("tool_receipts", []))
                            == len(OPERATIONS)
                            and (
                                (
                                    self.live_campaign is None
                                    and value.get("model_requests") == 0
                                )
                                or (
                                    self.live_campaign is not None
                                    and value.get("model_mode")
                                    == "live_authorized_campaign"
                                    and value.get("model_requests") == 3
                                )
                            ),
                        },
                    ]
                )
                from .content_contract import payload_checks

                checks += payload_checks(
                    value, attempt["documents"], attempt["department_id"]
                )
                payload = {**value, "checks": checks}
                candidate = {
                    "candidate_id": "candidate:" + attempt["attempt_id"],
                    "attempt_id": attempt["attempt_id"],
                    "workflow_id": attempt["workflow_id"],
                    "department_id": attempt["department_id"],
                    "revision": attempt["revision"],
                    "run_id": run_id,
                    "payload": payload,
                    "candidate_digest": digest(payload),
                    "evaluation": asdict(evaluation),
                    "checks_passed": all(c["passed"] for c in checks),
                    "created_at": stamp(),
                }
                self.store.put(
                    "candidate",
                    candidate["candidate_id"],
                    candidate,
                    workflow_id=attempt["workflow_id"],
                    department_id=attempt["department_id"],
                )
                self.event(
                    attempt["workflow_id"],
                    "candidate_evaluated",
                    {
                        "attempt_id": attempt["attempt_id"],
                        "candidate_digest": candidate["candidate_digest"],
                        "checks_passed": candidate["checks_passed"],
                        "evaluator_scope": "引用、结构、权限与固定验收；不认证全部语义",
                        "release_authorization": False,
                    },
                )
                self.native_projection(
                    attempt,
                    runtime_state="completed",
                    authority_state="pending_approval",
                )

    def node_state(self, attempt):
        if attempt is None:
            return {"status": "not_started", "next_action": "导入资料并开始规划"}
        reviews = self.store.list("review", attempt["workflow_id"])
        review = next(
            (r for r in reviews if r["attempt_id"] == attempt["attempt_id"]), None
        )
        if attempt.get("invalidated"):
            return {
                "status": "changes_requested"
                if review and review["decision"] == "request_changes"
                else "stale",
                "next_action": "审核已退回，请补充资料并创建修订"
                if review
                else "上游已修订，请重新规划",
                "review": review,
            }
        if review:
            with self.database.session() as database_session:
                receipt = database_session.scalar(
                    select(ReceiptRow).where(
                        ReceiptRow.receipt_id == "receipt_" + review["review_id"]
                    )
                )
                require(
                    receipt is not None
                    and receipt.receipt_digest == digest(review)
                    and receipt.subject_ref == attempt["task"]["task_id"],
                    "delivery_review_receipt_missing_or_mismatched",
                )
            next_action = "按审核意见创建修订"
            if review["decision"] == "approve":
                dept = attempt["department_id"]
                if dept == DEPARTMENTS[-1]:
                    next_action = "等待最终交付审核"
                elif any(
                    h["source_attempt"] == attempt["attempt_id"]
                    for h in self.store.list("handoff", attempt["workflow_id"])
                ):
                    next_action = "已完成交接，等待下游部门"
                else:
                    next_action = "明确授权交接下一部门"
            return {
                "status": "approved"
                if review["decision"] == "approve"
                else "changes_requested",
                "next_action": next_action,
                "review": review,
            }
        if attempt.get("run_id"):
            run = self.transport.status(attempt["run_id"])
            candidate = self.store.get("candidate:" + attempt["attempt_id"])
            status = (
                ("awaiting_review" if candidate["checks_passed"] else "blocked")
                if candidate
                else run["status"]
            )
            return {
                "status": status,
                "next_action": {
                    "awaiting_review": "负责人审核候选",
                    "blocked": "检查失败，退回修订",
                    "failed": "查看失败记录，明确确认后创建新尝试",
                    "cancelled": "确认取消后可创建新尝试",
                }.get(status, "等待执行或取消"),
                "run": run,
            }
        response = self.cockpit.planning_session(
            department_id=attempt["department_id"], session_id=attempt["session_id"]
        )
        approved = any(
            e["kind"] == "plan_approved"
            and e["payload"]["attempt_id"] == attempt["attempt_id"]
            for e in self.store.list("event", attempt["workflow_id"])
        )
        return {
            "status": "plan_approved" if approved else response["status"],
            "next_action": "启动受控执行"
            if approved
            else "回答问题卡"
            if response["status"] == "needs_input"
            else "查看规划失败记录，确认后创建新尝试"
            if response["status"] == "failed_recoverable"
            else "负责人确认计划",
        }

    def view(self, principal, workflow_id):
        workflow = self.workflow(workflow_id)
        visible = (
            set(DEPARTMENTS)
            if "role_control_plane_admin" in principal["role_refs"]
            else set(principal["department_refs"])
        )
        require(bool(visible.intersection(DEPARTMENTS)), "无可访问部门")
        nodes = []
        for dept in DEPARTMENTS:
            attempt = self.attempt(workflow_id, dept)
            state = self.node_state(attempt)
            item = {
                "department_id": dept,
                "name": DEPT_NAMES[dept],
                "status": state["status"],
                "next_action": state["next_action"],
                "accessible": dept in visible,
                "attempt_id": attempt["attempt_id"] if attempt else None,
                "revision": attempt["revision"] if attempt else 0,
            }
            if dept in visible and attempt:
                item.update(
                    attempt=attempt,
                    planning=self.cockpit.planning_session(
                        department_id=dept, session_id=attempt["session_id"]
                    ),
                    candidate=self.store.get("candidate:" + attempt["attempt_id"]),
                    history=[
                        {
                            "attempt_id": a["attempt_id"],
                            "revision": a["revision"],
                            "state": self.node_state(a)["status"],
                            "candidate": self.store.get("candidate:" + a["attempt_id"]),
                        }
                        for key in workflow["nodes"][dept]["attempt_ids"]
                        if (a := self.store.get(key))
                    ],
                    runtime=state.get("run"),
                    review=state.get("review"),
                )
                if item.get("candidate"):
                    item["current_sharing_checks"] = self.current_sharing_checks(
                        item["candidate"]
                    )
                    item["current_sharing_passed"] = all(
                        c["passed"] for c in item["current_sharing_checks"]
                    )
            nodes.append(item)
        final = self.store.get("delivery:" + workflow_id)
        current = next((n for n in nodes if n["status"] != "approved"), None)
        status = (
            "delivered"
            if final and self.delivery_valid(workflow_id, final)
            else "awaiting_final_review"
            if current is None
            else current["status"]
        )
        docs = [d for d in self.documents(workflow_id) if d["department_id"] in visible]
        latest = {}
        for document in docs:
            key = (document["department_id"], document["document_id"])
            latest[key] = max(document["version"], latest.get(key, 0))
        for document in docs:
            document["is_current"] = (
                document["version"]
                == latest[(document["department_id"], document["document_id"])]
            )
        return {
            **{k: v for k, v in workflow.items() if k != "nodes"},
            "nodes": nodes,
            "status": status,
            "current_department": current["department_id"] if current else None,
            "documents": docs,
            "handoffs": self.store.list("handoff", workflow_id),
            "events": [
                e
                for e in self.store.list("event", workflow_id)
                if not e["payload"].get("department_id")
                or e["payload"]["department_id"] in visible
            ],
            "delivery": final
            if final and self.delivery_valid(workflow_id, final)
            else None,
            **self.model_usage(),
        }

    def review(self, principal, workflow_id, department, body, key):
        self.authorize(principal, department, owner=True)
        attempt = self.attempt(workflow_id, department)
        require(attempt and not attempt.get("invalidated"), "当前产物已失效")
        candidate = self.store.get("candidate:" + attempt["attempt_id"])
        require(
            candidate
            and body.get("candidate_digest") == candidate["candidate_digest"]
            and body.get("revision") == attempt["revision"],
            "候选版本或摘要已变化，请刷新",
        )
        require(
            not any(
                r["attempt_id"] == attempt["attempt_id"]
                for r in self.store.list("review", workflow_id)
            ),
            "该版本已有审核决定",
        )
        decision, reason = body.get("decision"), body.get("reason", "").strip()
        require(
            decision in {"approve", "request_changes"} and 8 <= len(reason) <= 1000,
            "请填写至少8字的审核意见",
        )
        require(
            decision != "approve" or candidate["checks_passed"], "检查未通过，不能批准"
        )
        if decision == "approve":
            self.require_current_sharing(candidate)
        record = {
            "review_id": identifier("review"),
            "attempt_id": attempt["attempt_id"],
            "candidate_digest": candidate["candidate_digest"],
            "revision": attempt["revision"],
            "decision": decision,
            "reason": reason,
            "actor": principal["human_ref"],
            "department_id": department,
            "recorded_at": stamp(),
            "identity_mode": "local_cookie_session",
            "production_authorized": False,
        }
        receipt_id = "receipt_" + record["review_id"]
        with self.database.session() as database_session:
            # Candidate decision and native Receipt share one SQL transaction.
            database_session.add(
                DeliveryRecordRow(
                    record_id=record["review_id"],
                    kind="review",
                    workflow_id=workflow_id,
                    department_id=department,
                    document=record,
                    document_digest=digest(record),
                    recorded_at=datetime.now(timezone.utc),
                )
            )
            database_session.add(
                ReceiptRow(
                    receipt_id=receipt_id,
                    receipt_type="local_delivery_candidate_review",
                    receipt_digest=digest(record),
                    subject_ref=attempt["task"]["task_id"],
                    document=record,
                    recorded_at=datetime.now(timezone.utc),
                )
            )
        self.native_projection(
            attempt,
            authority_state="succeeded"
            if decision == "approve"
            else "remediation_required",
            receipt=receipt_id,
        )
        self.event(workflow_id, "candidate_reviewed", record)
        if decision == "request_changes":
            self.invalidate(workflow_id, department, reason, principal)
        elif body.get("handoff_to"):
            self.handoff(principal, workflow_id, department, body["handoff_to"])
        return self.view(principal, workflow_id)

    def handoff(self, principal, workflow_id, source, target):
        self.authorize(principal, source, owner=True)
        index = DEPARTMENTS.index(source)
        require(
            index < 2 and target == DEPARTMENTS[index + 1],
            "只允许按产品、技术、市场顺序交接",
        )
        attempt = self.attempt(workflow_id, source)
        require(
            attempt and self.node_state(attempt)["status"] == "approved",
            "来源产物尚未批准",
        )
        candidate = self.store.get("candidate:" + attempt["attempt_id"])
        self.require_current_sharing(candidate)
        record_id = (
            "handoff:"
            + digest({"attempt": attempt["attempt_id"], "target": target})[7:]
        )
        if self.store.get(record_id):
            return
        content = candidate["payload"]["body"].encode()
        name = "approved-" + source + "-v" + str(attempt["revision"]) + ".md"
        native = self.cockpit.artifact_store.upload(
            department_id=target,
            filename=name,
            media_type="text/markdown",
            content=content,
            data_classification="public",
            actor_ref=principal["human_ref"],
        )
        parsed = parse_document(name, content)
        artifact_id = (
            "artifact:" + digest({"workflow": workflow_id, "handoff": record_id})[7:]
        )
        self.store.put(
            "artifact",
            artifact_id,
            {
                "record_id": artifact_id,
                "artifact_ref": native["artifact_ref"],
                "filename": name,
                "document_id": "approved-" + source,
                "version": attempt["revision"],
                "department_id": target,
                "shared_with": [source, target],
                "source_candidate_digest": candidate["candidate_digest"],
                "source_department": source,
                "scan_status": "stored_unscanned",
                **parsed,
            },
            workflow_id=workflow_id,
            department_id=target,
        )
        record = {
            "handoff_id": record_id,
            "source_attempt": attempt["attempt_id"],
            "source_department": source,
            "target_department": target,
            "candidate_digest": candidate["candidate_digest"],
            "artifact_ref": native["artifact_ref"],
            "approved_by": principal["human_ref"],
            "recorded_at": stamp(),
        }
        self.store.put("handoff", record_id, record, workflow_id=workflow_id)
        self.event(workflow_id, "handoff_authorized", record)

    def invalidate(
        self,
        workflow_id,
        department,
        reason,
        principal,
        *,
        feedback_kind="business_rework",
    ):
        self.workflow(workflow_id)
        for dept in DEPARTMENTS[DEPARTMENTS.index(department) :]:
            attempt = self.attempt(workflow_id, dept)
            if not attempt:
                continue
            attempt.update(invalidated=True, retry_allowed=True)
            if dept != department:
                # Upstream invalidation is a dependency event, not this
                # department's own business review or recovery instruction.
                attempt["dependency_notes"] = {
                    "source_department": department,
                    "reason": reason,
                }
            elif feedback_kind == "business_rework":
                attempt.update(review_feedback=reason, business_feedback=reason)
            else:
                attempt["recovery_notes"] = reason
            self.store.put(
                "attempt",
                attempt["attempt_id"],
                attempt,
                workflow_id=workflow_id,
                department_id=dept,
                mutable=True,
            )
            if attempt.get("run_id"):
                run = self.transport.status(attempt["run_id"])
                if run["status"] in {"queued", "running", "cancel_requested"}:
                    self.revocations.revoke(
                        grant_id=attempt["grant_id"],
                        reason_code="upstream_revision_changed",
                        revoked_by_ref=legacy_human_ref(principal["human_ref"]),
                    )
                    self.transport.cancel(
                        run_id=run["run_id"], reason_code="upstream_revision_changed"
                    )
        self.event(
            workflow_id,
            "downstream_invalidated",
            {
                "department_id": department,
                "reason": reason,
                "feedback_kind": feedback_kind,
                "actor": principal["human_ref"],
            },
        )

    def revise(self, principal, workflow_id, department, body, key):
        self.authorize(principal, department, owner=True)
        attempt = self.attempt(workflow_id, department)
        require(attempt is not None, "没有可修订的尝试")
        state = self.node_state(attempt)["status"]
        require(
            state
            in {
                "stale",
                "changes_requested",
                "failed",
                "cancelled",
                "blocked",
                "approved",
                "failed_closed",
                "failed_recoverable",
                "stop_requested",
            },
            "运行或规划尚未结束",
        )
        reason = body.get("reason", "").strip()
        require(
            len(reason) >= 8 and body.get("acknowledge_uncertain") is True,
            "请说明修订原因，并确认不会盲目重放不确定步骤",
        )
        recovery_states = {
            "failed",
            "cancelled",
            "failed_closed",
            "failed_recoverable",
            "stop_requested",
        }
        kind = body.get(
            "revision_kind",
            "execution_recovery" if state in recovery_states else "business_rework",
        )
        require(
            kind in {"business_rework", "execution_recovery"}, "revision_kind_invalid"
        )
        require(
            kind != "execution_recovery" or state in recovery_states,
            "恢复入口仅用于失败或已取消的尝试",
        )
        self.invalidate(workflow_id, department, reason, principal, feedback_kind=kind)
        return self.start_plan(principal, workflow_id, department, key)

    def cancel(self, principal, workflow_id, department, *, revoke=False):
        self.authorize(principal, department, owner=revoke)
        attempt = self.attempt(workflow_id, department)
        require(attempt and not attempt.get("invalidated"), "没有可取消的执行")
        if attempt.get("run_id"):
            run = self.transport.status(attempt["run_id"])
            require(
                run["status"] in {"queued", "running", "cancel_requested"},
                "执行已经结束",
            )
            if revoke:
                self.revocations.revoke(
                    grant_id=attempt["grant_id"],
                    reason_code="local_operator_revoked",
                    revoked_by_ref=legacy_human_ref(principal["human_ref"]),
                )
            self.transport.cancel(
                run_id=attempt["run_id"],
                reason_code="local_operator_revoked"
                if revoke
                else "local_operator_cancelled",
            )
        else:
            self.cockpit.stop_session(
                department_id=department,
                session_id=attempt["session_id"],
                actor_ref=principal["human_ref"],
            )
        self.event(
            workflow_id,
            "execution_revoked" if revoke else "execution_cancel_requested",
            {
                "department_id": department,
                "attempt_id": attempt["attempt_id"],
                "actor": principal["human_ref"],
            },
        )
        return self.view(principal, workflow_id)

    def delivery_valid(self, workflow_id, delivery):
        return delivery["attempt_ids"] == [
            self.workflow(workflow_id)["nodes"][d]["current"] for d in DEPARTMENTS
        ] and all(
            self.node_state(self.attempt(workflow_id, d))["status"] == "approved"
            for d in DEPARTMENTS
        )

    def deliver(self, principal, workflow_id, reason):
        self.authorize(principal, admin=True)
        require(len(reason.strip()) >= 8, "请填写最终审核说明")
        attempts = [self.attempt(workflow_id, d) for d in DEPARTMENTS]
        require(
            all(a and self.node_state(a)["status"] == "approved" for a in attempts),
            "所有部门的当前产物都需要批准",
        )
        for attempt in attempts:
            self.require_current_sharing(
                self.store.get("candidate:" + attempt["attempt_id"])
            )
        record = {
            "workflow_id": workflow_id,
            "attempt_ids": [a["attempt_id"] for a in attempts],
            "approved_by": principal["human_ref"],
            "reason": reason,
            "recorded_at": stamp(),
            "external_publication": False,
        }
        previous = self.store.get("delivery:" + workflow_id)
        if previous and previous["attempt_ids"] != record["attempt_ids"]:
            self.store.put(
                "delivery_history",
                identifier("delivery_history"),
                previous,
                workflow_id=workflow_id,
            )
        self.store.put(
            "delivery",
            "delivery:" + workflow_id,
            record,
            workflow_id=workflow_id,
            mutable=True,
        )
        self.event(workflow_id, "local_delivery_approved", record)
        return self.view(principal, workflow_id)

    def catalog(self):
        return {
            **self.assets.status(),
            "runtime": {
                "name": "本机受控专业执行器",
                "family": "durable_runner_process",
                "model_mode": "live_authorized_campaign"
                if self.live_campaign
                else "offline_deterministic",
                "queue": "sqlite_single_worker",
                "source_revision": source_revision(),
                "supports_arbitrary_code": False,
                "strong_os_sandbox": False,
                "hermes_codex_status": "candidate_not_connected",
            },
            "budget": {
                **self.model_usage(),
                "real_model_enabled": self.live_campaign is not None,
                "reason": "显式独立授权活动；旧Campaign不沿用"
                if self.live_campaign
                else "本轮离线；旧真实Campaign已关闭，不沿用额度",
            },
        }

    def asset_action(self, kind, identity, action, actor, key):
        value = self.assets.action(kind, identity, action, actor, key)
        if action == "suspend":
            for attempt in self.store.list("attempt"):
                if not attempt.get("run_id") or (
                    kind == "agents"
                    and attempt["task"]["requested_target_id"] != identity
                ):
                    continue
                run = self.transport.status(attempt["run_id"])
                if run["status"] in {"queued", "running", "cancel_requested"}:
                    self.revocations.revoke(
                        grant_id=attempt["grant_id"],
                        reason_code="local_asset_suspended",
                        revoked_by_ref=legacy_human_ref(actor),
                    )
                    self.transport.cancel(
                        run_id=run["run_id"], reason_code="local_asset_suspended"
                    )
                    self.event(
                        attempt["workflow_id"],
                        "execution_revoked",
                        {
                            "department_id": attempt["department_id"],
                            "reason": "local_asset_suspended",
                            "asset": identity,
                            "actor": actor,
                        },
                    )
        return value

    def asset_batch(self, action, items, actor, key):
        require(
            action in {"evaluate", "activate"}
            and isinstance(items, list)
            and 1 <= len(items) <= 8,
            "asset_batch_invalid",
        )
        catalog = self.assets.status()
        seen = set()
        for item in items:
            require(
                set(item) == {"kind", "id", "release_digest"}
                and item["kind"] in {"agents", "tools"},
                "asset_batch_item_invalid",
            )
            require((item["kind"], item["id"]) not in seen, "asset_batch_duplicate")
            seen.add((item["kind"], item["id"]))
            match = next(
                (a for a in catalog[item["kind"]] if a["id"] == item["id"]), None
            )
            require(
                match
                and match["release_digest"] == item["release_digest"]
                and match["status"]
                == ("draft" if action == "evaluate" else "evaluation"),
                "asset_batch_revision_or_state_changed",
            )
        for item in items:
            self.asset_action(
                item["kind"],
                item["id"],
                action,
                actor,
                "batch:" + digest({"key": key, "item": item})[7:],
            )
        return self.catalog()

    def runtime_status(self):
        with self.database.session() as session:
            runs = session.scalars(
                select(RuntimeRunRow)
                .where(
                    RuntimeRunRow.invocation["operation"].as_string()
                    == "run_delivery_professional"
                )
                .order_by(RuntimeRunRow.created_at.desc())
                .limit(100)
            ).all()
            leases = session.scalars(select(WorkerLeaseRow)).all()
            result = [
                {
                    "run_id": r.run_id,
                    "task_id": r.task_id,
                    "status": r.status,
                    "grant_id": r.grant_id,
                    "failure_reason_code": r.failure_reason_code,
                    "lease": next(
                        (
                            {
                                "lease_id": l.lease_id,
                                "status": l.status,
                                "outcome": l.outcome,
                                "expires_at": l.expires_at.isoformat(),
                            }
                            for l in leases
                            if l.run_id == r.run_id
                        ),
                        None,
                    ),
                }
                for r in runs
            ]
        heartbeat = self.root / "worker-heartbeat.json"
        worker = strict_json(private_read(heartbeat)) if heartbeat.exists() else None
        return {
            "runs": result,
            "worker": worker,
            "worker_online": bool(worker and time.time() - worker["at"] < 5),
            **self.catalog(),
        }
