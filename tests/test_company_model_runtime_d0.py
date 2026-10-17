from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from orbit_agent_control_plane.service_runtime.codex_account_runtime import (
    CodexAccountRuntimeAdapter,
    CodexAccountRuntimeError,
    canonical_digest,
)
from orbit_agent_control_plane.service_runtime.runtime_adapter import RuntimeInvocation

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "deploy/lan-stage1/runtime/technology-delivery-review-d0"
DEVICE_PROMPT = (
    ROOT
    / "deploy/lan-stage1/department-device/TECHNOLOGY-CENTER-CHATGPT-PROMPT.md"
)
DIGESTS = {
    name: "sha256:" + digit * 64
    for name, digit in {
        "task": "1", "grant": "2", "composition": "3", "source": "4",
        "artifact": "5", "image": "6", "isolation": "7", "binding": "8",
        "adapter": "9",
    }.items()
}


def zulu(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class DeterministicTechnologyAgentTests(unittest.TestCase):
    def test_agent_is_deterministic_and_contract_shaped(self) -> None:
        source = (RUNTIME / "input.synthetic.json").read_bytes()
        first = subprocess.run(
            [sys.executable, str(RUNTIME / "agent.py")], input=source,
            capture_output=True, check=True,
        )
        second = subprocess.run(
            [sys.executable, str(RUNTIME / "agent.py")], input=source,
            capture_output=True, check=True,
        )
        self.assertEqual(first.stdout, second.stdout)
        result = json.loads(first.stdout)
        self.assertEqual("0.3", result["schema_version"])
        self.assertEqual("succeeded", result["status"])
        self.assertEqual([], result["model_usage_refs"])
        self.assertEqual([], result["tool_usage"])
        self.assertEqual("not_run", result["evaluation"]["state"])
        self.assertEqual("pending", result["human_disposition"]["state"])
        self.assertTrue(result["execution_grant_ref"]["id"].startswith("grant_"))

    def test_agent_rejects_non_detached_or_remote_snapshot(self) -> None:
        source = json.loads((RUNTIME / "input.synthetic.json").read_text())
        source["source_snapshot"]["remote_configured"] = True
        completed = subprocess.run(
            [sys.executable, str(RUNTIME / "agent.py")],
            input=json.dumps(source).encode(), capture_output=True, check=False,
        )
        self.assertEqual(2, completed.returncode)
        result = json.loads(completed.stdout)
        self.assertEqual("rejected", result["status"])
        self.assertFalse(result["model_called"])
        self.assertFalse(result["production_authorization"])

    def test_container_source_is_pinned_and_has_no_runtime_dependency_install(self) -> None:
        dockerfile = (RUNTIME / "Dockerfile").read_text()
        self.assertIn("@sha256:9c47360a2a0355e2", dockerfile)
        self.assertNotIn(":latest", dockerfile)
        self.assertNotIn("apt-get", dockerfile)
        self.assertNotIn("pip install", dockerfile)
        self.assertIn("USER 65532:65532", dockerfile)
        lock = json.loads((RUNTIME / "runtime-source-lock.json").read_text())
        self.assertFalse(lock["network_required_at_runtime"])
        self.assertFalse(lock["model_required"])
        self.assertFalse(lock["production_authorization"])

    def test_device_prompt_preserves_the_human_and_grant_gates(self) -> None:
        prompt = DEVICE_PROMPT.read_text(encoding="utf-8")
        self.assertIn("本轮不处理账号登录型 Agent Runtime", prompt)
        self.assertIn("大语言模型 API 密钥仅由中央 Secret Provider 持有", prompt)
        self.assertIn("ExecutionGrant", prompt)
        self.assertIn("RuntimeComposition", prompt)
        self.assertIn("Lease", prompt)
        self.assertIn("不得使用此前聊天里出现过的任何密钥", prompt)
        self.assertIn("不得在技术电脑输入密钥", prompt)
        self.assertNotIn("codex login", prompt)
        self.assertIn("runtime_started", prompt)
        self.assertIn("model_called", prompt)
        self.assertNotIn("sk-cp-", prompt)
        builder = (ROOT / "deploy/lan-stage1/build-lan-install-bundle.py").read_text()
        self.assertIn("TECHNOLOGY-CENTER-CHATGPT-PROMPT.md", builder)


class CodexAccountRuntimeAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime.now(timezone.utc)
        self.adapter = CodexAccountRuntimeAdapter(now=lambda: self.now)
        self.invocation = RuntimeInvocation.from_mapping(invocation(self.now))
        self.route = account_route()
        self.route_digest = canonical_digest(self.route)
        invocation_digest = canonical_digest(self.invocation.to_mapping())
        self.lease = {
            "claimed": True,
            "lease_id": "lease_technology_codex_syn_001",
            "run_id": "run_technology_codex_syn_001",
            "invocation_digest": invocation_digest,
            "expires_at": zulu(self.now + timedelta(minutes=5)),
            "status": "active",
            "production_authorization": False,
            "release_authorization": False,
        }
        self.grant = {
            "grant_id": self.invocation.grant_id,
            "grant_digest": self.invocation.grant_digest,
            "task_id": self.invocation.task_id,
            "invocation_digest": invocation_digest,
            "status": "active",
            "signature_verified": True,
            "revoked": False,
            "expires_at": zulu(self.now + timedelta(minutes=10)),
            "production_authorization": False,
            "release_authorization": False,
        }
        self.qualification = {
            "status": "qualified",
            "route_id": self.route["route_id"],
            "route_revision_digest": self.route_digest,
            "credential_binding_ref": self.route["authentication"]["credential_binding_ref"],
            "node_id": "node_technology_001",
            "codex_cli_revision": "codex-cli/1.2.3",
            "adapter_capability_digest": DIGESTS["adapter"],
            "verified_at": zulu(self.now - timedelta(minutes=1)),
            "expires_at": zulu(self.now + timedelta(hours=1)),
            "runtime_started": False,
            "model_called": False,
            "production_authorization": False,
            "release_authorization": False,
        }

    def request(self, **overrides):
        values = {
            "invocation": self.invocation,
            "run_id": "run_technology_codex_syn_001",
            "node_id": "node_technology_001",
            "lease": self.lease,
            "verified_grant": self.grant,
            "route_revision": self.route,
            "route_revision_digest": self.route_digest,
            "account_qualification": self.qualification,
            "requested_budget": {
                "max_input_tokens": 20000,
                "max_output_tokens": 4000,
                "max_turns": 6,
                "max_duration_seconds": 900,
                "max_concurrency": 1,
            },
            "active_task_count": 0,
            "output_schema_ref": "artifact://contracts/result-package/0.3",
        }
        values.update(overrides)
        return self.adapter.build_task_request(**values)

    def test_builds_secret_free_non_executing_single_task_request(self) -> None:
        result = self.request()
        self.assertFalse(result["execute"])
        self.assertTrue(result["execution_grant_verified"])
        self.assertEqual("node_local_adapter_only", result["credential_resolution"])
        self.assertFalse(result["credential_mounted_into_task_container"])
        self.assertEqual("read_only", result["sandbox"]["mode"])
        self.assertFalse(result["sandbox"]["push_allowed"])
        self.assertFalse(result["model_called"])
        self.assertFalse(result["runtime_started"])
        encoded = json.dumps(result)
        self.assertNotIn("auth.json", encoded)
        self.assertNotIn("access_token", encoded.lower())
        self.assertNotIn("bearer ", encoded.lower())
        self.assertNotIn("sk-", encoded.lower())

    def test_account_qualification_never_substitutes_for_execution_grant(self) -> None:
        invalid = dict(self.grant)
        invalid["signature_verified"] = False
        with self.assertRaisesRegex(
            CodexAccountRuntimeError, "codex_account_execution_grant_invalid"
        ):
            self.request(verified_grant=invalid)

    def test_wrong_node_expired_qualification_and_concurrency_fail_closed(self) -> None:
        wrong_route = copy.deepcopy(self.route)
        wrong_route["authorized_node_refs"] = ["node_market_001"]
        with self.assertRaisesRegex(
            CodexAccountRuntimeError, "codex_account_model_route_invalid"
        ):
            self.request(
                route_revision=wrong_route,
                route_revision_digest=canonical_digest(wrong_route),
            )
        expired = dict(self.qualification)
        expired["expires_at"] = zulu(self.now - timedelta(seconds=1))
        with self.assertRaisesRegex(
            CodexAccountRuntimeError, "codex_account_qualification_invalid"
        ):
            self.request(account_qualification=expired)
        with self.assertRaisesRegex(
            CodexAccountRuntimeError, "codex_account_budget_exceeded"
        ):
            self.request(active_task_count=1)


def invocation(now: datetime) -> dict:
    return {
        "task_id": "task_technology_codex_syn_001",
        "task_digest": DIGESTS["task"],
        "grant_id": "grant_technology_codex_syn_001",
        "grant_digest": DIGESTS["grant"],
        "composition_digest": DIGESTS["composition"],
        "runtime_source_digest": DIGESTS["source"],
        "runtime_artifact_digest": DIGESTS["artifact"],
        "runtime_image_digest": DIGESTS["image"],
        "isolation_profile_digest": DIGESTS["isolation"],
        "input_snapshot_refs": ["artifact://synthetic/technology/source-snapshot-001"],
        "department_id": "technology_center",
        "agent_binding_ref": "agent_binding_technology_codex_syn",
        "agent_binding_digest": DIGESTS["binding"],
        "workload_identity": "workload_technology_runner_syn",
        "operation": "codex_read_only_review",
        "input_refs": ["task://synthetic/technology/package-001"],
        "idempotency_key": "codex-account-runtime-test-001",
        "expires_at": zulu(now + timedelta(minutes=10)),
        "timeout_seconds": 900,
        "data_classification": "synthetic",
        "synthetic_only": True,
        "production_authorization": False,
    }


def account_route() -> dict:
    return {
        "route_version": "orbit.model-route-revision/2",
        "route_id": "model_route_technology_codex_account_d0",
        "provider": "openai_codex_account",
        "endpoint": "https://chatgpt.com/",
        "requested_model": "gpt-5.6-luna",
        "parameters": {"permissions": ["model.invoke"], "max_concurrency": 1},
        "data_classification": "synthetic",
        "budget_policy": {
            "max_input_tokens": 20000,
            "max_output_tokens": 4000,
            "max_turns": 6,
            "max_duration_seconds": 900,
            "max_concurrency": 1,
        },
        "budget_control_mode": "usage_limits",
        "resolution_mode": "pinned",
        "authentication": {
            "mode": "oauth_ref",
            "credential_binding_ref": "oauth://company/codex/technology",
        },
        "credential_scope": "company",
        "authorized_node_refs": ["node_technology_001"],
        "qualification_evidence_refs": [DIGESTS["adapter"]],
        "approved_scope": {
            "provider": "openai_codex_account",
            "endpoint": "https://chatgpt.com/",
            "model_family": "gpt-5.6-luna",
            "resolved_model_ids": ["gpt-5.6-luna"],
            "data_classification": "synthetic",
            "permissions": ["model.invoke"],
        },
        "runtime_binding": {
            "ref": "runtime-binding://technology/codex-read-only-d0",
            "digest": DIGESTS["artifact"],
        },
        "policy_binding": {
            "ref": "policy://stage1-lan/d0-synthetic-only",
            "digest": DIGESTS["composition"],
        },
        "status": "active",
    }


if __name__ == "__main__":
    unittest.main()

