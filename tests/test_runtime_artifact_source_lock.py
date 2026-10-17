from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

from orbit_agent_control_plane.qualification.automation import canonical_digest
from orbit_agent_control_plane.service_runtime.models import Base

ROOT = Path(__file__).resolve().parents[1]
LOCK = (
    ROOT
    / "evidence/runtime-artifacts/2026-09-01-wsl-container-runtime-d0/"
    / "control-plane-runtime-source-lock.synthetic.json"
)
INTEGRATED_LAN_LOCK = (
    ROOT
    / "evidence/lan-stage1/2026-09-04-control-console-first-install-integration/"
    / "control-plane-lan-source-lock.synthetic.json"
)
LAN_LOCK = (
    ROOT
    / "evidence/lan-stage1/2026-09-05-local-ui-module-repair/"
    / "control-plane-lan-source-lock.synthetic.json"
)
TRANSPORT_BASELINE_LOCK = (
    ROOT
    / "evidence/lan-stage1/2026-09-04-transport-receipts/"
    / "control-plane-lan-source-lock.synthetic.json"
)
RECOVERY_BASELINE_LOCK = (
    ROOT
    / "evidence/lan-stage1/2026-09-04-lan-update-recovery/"
    / "control-plane-lan-source-lock.synthetic.json"
)
ACCEPTANCE_BASELINE_LOCK = (
    ROOT
    / "evidence/lan-stage1/2026-09-04-autonomous-acceptance/"
    / "control-plane-lan-source-lock.synthetic.json"
)
MODEL_CATALOG_BASELINE_LOCK = (
    ROOT
    / "evidence/lan-stage1/2026-09-04-model-catalog-integrity/"
    / "control-plane-lan-source-lock.synthetic.json"
)
FROZEN_LAN_LOCK = (
    ROOT
    / "evidence/lan-stage1/2026-09-01-control-plane-d0/"
    / "control-plane-lan-source-lock.synthetic.json"
)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
EXPECTED_PATHS = {
    "alembic/versions/20260901_0008_runtime_artifacts.py",
    "src/orbit_agent_control_plane/service_runtime/api.py",
    "src/orbit_agent_control_plane/service_runtime/cockpit_local_identity.py",
    "src/orbit_agent_control_plane/service_runtime/container_engine.py",
    "src/orbit_agent_control_plane/service_runtime/control_console_d0_main.py",
    "src/orbit_agent_control_plane/service_runtime/department_cockpit.py",
    "src/orbit_agent_control_plane/service_runtime/department_cockpit_api.py",
    "src/orbit_agent_control_plane/service_runtime/models.py",
    "src/orbit_agent_control_plane/service_runtime/runner_queue.py",
    "src/orbit_agent_control_plane/service_runtime/runtime_adapter.py",
    "src/orbit_agent_control_plane/service_runtime/runtime_artifact_api.py",
    "src/orbit_agent_control_plane/service_runtime/runtime_artifact_models.py",
    "src/orbit_agent_control_plane/service_runtime/runtime_artifacts.py",
}
EXPECTED_TABLES = {
    "control_plane_runtime_artifact_revisions",
    "control_plane_runtime_artifact_revocations",
    "control_plane_runtime_node_capability_reports",
    "control_plane_runtime_artifact_import_receipts",
    "control_plane_runtime_node_lease_claims",
    "control_plane_runtime_container_evidence",
    "control_plane_model_gateway_token_exchanges",
    "control_plane_department_task_decisions",
}


class RuntimeArtifactSourceLockTests(unittest.TestCase):
    def test_native_args_lock_keeps_deployed_revision_20_bytes(self) -> None:
        revision = "d4845822dd02c7a5f6f53d735f4ae24407658df3"
        relative = "evidence/lan-stage1/2026-09-04-first-install-native-args/control-plane-lan-source-lock.synthetic.json"

        def committed(path):
            return subprocess.run(["git", "show", f"{revision}:{path}"], cwd=ROOT,
                                  check=True, capture_output=True).stdout

        raw = (ROOT / relative).read_bytes()
        self.assertEqual(committed(relative), raw)
        previous = json.loads(raw)
        current = json.loads(LAN_LOCK.read_bytes())
        self.assertEqual([{"path": relative, "revision": revision,
                           "sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}],
                         current["predecessor_source_locks"])
        self.assertTrue({entry["path"] for entry in previous["entries"]}.issubset(
            {entry["path"] for entry in current["entries"]}))
        for entry in previous["entries"]:
            self.assertEqual(entry["sha256"],
                             "sha256:" + hashlib.sha256(committed(entry["path"])).hexdigest())

    def test_integrated_lock_preserves_both_reviewed_candidates(self) -> None:
        current = json.loads(INTEGRATED_LAN_LOCK.read_bytes())
        expected = {
            "evidence/lan-stage1/2026-09-04-department-first-install/control-plane-lan-source-lock.synthetic.json":
                "94a3b09767510136d081cc2f860fdd457f72f683",
            "evidence/lan-stage1/2026-09-04-control-console-ux/control-plane-lan-source-lock.synthetic.json":
                "c1eaa2cfc72e241caca15c9f6213fb75ec4f1c57",
        }
        self.assertEqual(expected, {row["path"]: row["revision"]
                                   for row in current["predecessor_source_locks"]})
        reviewed_paths = set()
        for row in current["predecessor_source_locks"]:
            with self.subTest(candidate=row["path"]):
                def committed_bytes(relative):
                    return subprocess.run(["git", "show", f"{row['revision']}:{relative}"],
                                          cwd=ROOT, check=True, capture_output=True).stdout
                raw = (ROOT / row["path"]).read_bytes()
                self.assertEqual(committed_bytes(row["path"]), raw)
                self.assertEqual(row["sha256"], "sha256:" + hashlib.sha256(raw).hexdigest())
                previous = json.loads(raw)
                self.assertEqual(previous["source_set_digest"], canonical_digest(
                    {key: value for key, value in previous.items() if key != "source_set_digest"}))
                for entry in previous["entries"]:
                    self.assertEqual(entry["sha256"],
                                     "sha256:" + hashlib.sha256(committed_bytes(entry["path"])).hexdigest())
                    reviewed_paths.add(entry["path"])
        self.assertTrue(reviewed_paths.issubset({entry["path"] for entry in current["entries"]}))

    def test_model_key_publication_lock_keeps_committed_predecessor_bytes(self) -> None:
        revision = "c244eca57ecc7fd9dd4e70d23dfdc60ae77465bf"
        relative = "evidence/lan-stage1/2026-09-04-model-key-publication/control-plane-lan-source-lock.synthetic.json"
        raw = subprocess.run(["git", "show", f"{revision}:{relative}"], cwd=ROOT,
                             check=True, capture_output=True).stdout
        self.assertEqual(raw, (ROOT / relative).read_bytes())
        for entry in json.loads(raw)["entries"]:
            source = subprocess.run(["git", "show", f"{revision}:{entry['path']}"], cwd=ROOT,
                                    check=True, capture_output=True).stdout
            self.assertEqual(entry["sha256"], "sha256:" + hashlib.sha256(source).hexdigest())

    def test_receipt_binding_lock_keeps_committed_predecessor_bytes(self) -> None:
        revision = "48bf03c3dd45df24b4971d4e2675621024bbf4f7"
        relative = "evidence/lan-stage1/2026-09-04-codex-receipt-binding/control-plane-lan-source-lock.synthetic.json"
        def committed(path):
            return subprocess.run(["git", "show", f"{revision}:{path}"], cwd=ROOT,
                                  check=True, capture_output=True).stdout
        self.assertEqual(committed(relative), (ROOT / relative).read_bytes())
        for entry in json.loads(committed(relative))["entries"]:
            self.assertEqual(entry["sha256"], "sha256:" + hashlib.sha256(committed(entry["path"])).hexdigest())

    def test_transport_source_lock_keeps_revision_15_commit_bytes(self) -> None:
        revision = "02b1cfffe882bc794961dabf813fdfa7ba186521"
        def committed_bytes(relative):
            return subprocess.run(
                ["git", "show", f"{revision}:{relative}"], cwd=ROOT,
                check=True, capture_output=True,
            ).stdout
        self.assertEqual(
            committed_bytes(str(TRANSPORT_BASELINE_LOCK.relative_to(ROOT))),
            TRANSPORT_BASELINE_LOCK.read_bytes(),
        )
        for entry in json.loads(TRANSPORT_BASELINE_LOCK.read_bytes())["entries"]:
            self.assertEqual(entry["sha256"],
                             "sha256:" + hashlib.sha256(committed_bytes(entry["path"])).hexdigest())

    def test_recovery_source_lock_keeps_revision_14_commit_bytes(self) -> None:
        revision = "b3f8f806cc5f4bbe5340ccda6f2c653bf5c7c175"
        def committed_bytes(relative):
            return subprocess.run(
                ["git", "show", f"{revision}:{relative}"], cwd=ROOT,
                check=True, capture_output=True,
            ).stdout
        self.assertEqual(
            committed_bytes(str(RECOVERY_BASELINE_LOCK.relative_to(ROOT))),
            RECOVERY_BASELINE_LOCK.read_bytes(),
        )
        for entry in json.loads(RECOVERY_BASELINE_LOCK.read_bytes())["entries"]:
            self.assertEqual(
                entry["sha256"],
                "sha256:" + hashlib.sha256(committed_bytes(entry["path"])).hexdigest(),
            )

    def test_acceptance_source_lock_keeps_pre_recovery_commit_bytes(self) -> None:
        revision = "8b14cf139df9d94144f4ca7be1b1461114b1ec90"
        def committed_bytes(relative):
            return subprocess.run(
                ["git", "show", f"{revision}:{relative}"], cwd=ROOT,
                check=True, capture_output=True,
            ).stdout
        self.assertEqual(
            committed_bytes(str(ACCEPTANCE_BASELINE_LOCK.relative_to(ROOT))),
            ACCEPTANCE_BASELINE_LOCK.read_bytes(),
        )
        for entry in json.loads(ACCEPTANCE_BASELINE_LOCK.read_bytes())["entries"]:
            self.assertEqual(
                entry["sha256"],
                "sha256:" + hashlib.sha256(committed_bytes(entry["path"])).hexdigest(),
            )

    def test_deployed_model_catalog_lock_keeps_committed_predecessor_bytes(self) -> None:
        revision = "bf55aac307481f62053cf126fa2910756c1eac0f"

        def committed_bytes(relative):
            return subprocess.run(
                ["git", "show", f"{revision}:{relative}"], cwd=ROOT,
                check=True, capture_output=True,
            ).stdout

        self.assertEqual(
            committed_bytes(str(MODEL_CATALOG_BASELINE_LOCK.relative_to(ROOT))),
            MODEL_CATALOG_BASELINE_LOCK.read_bytes(),
        )
        for entry in json.loads(MODEL_CATALOG_BASELINE_LOCK.read_bytes())["entries"]:
            self.assertEqual(
                entry["sha256"],
                "sha256:" + hashlib.sha256(committed_bytes(entry["path"])).hexdigest(),
            )

    def test_frozen_model_catalog_source_lock_keeps_tag_bytes(self) -> None:
        revision = "4fdcfbdf1b13d7e861ebf89d45aa6b10e5c1b1ba"

        def frozen_bytes(relative):
            return subprocess.run(
                ["git", "show", f"{revision}:{relative}"],
                cwd=ROOT,
                check=True,
                capture_output=True,
            ).stdout

        self.assertEqual(
            frozen_bytes(str(FROZEN_LAN_LOCK.relative_to(ROOT))),
            FROZEN_LAN_LOCK.read_bytes(),
        )
        for entry in json.loads(FROZEN_LAN_LOCK.read_bytes())["entries"]:
            self.assertEqual(
                entry["sha256"],
                "sha256:" + hashlib.sha256(frozen_bytes(entry["path"])).hexdigest(),
            )

    def test_base_metadata_registers_all_runtime_artifact_tables(self) -> None:
        self.assertTrue(EXPECTED_TABLES.issubset(Base.metadata.tables))
        script = (
            "from orbit_agent_control_plane.service_runtime.models import Base; "
            f"expected={EXPECTED_TABLES!r}; "
            "missing=expected-set(Base.metadata.tables); "
            "assert not missing, sorted(missing)"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            env={
                "PYTHONPATH": str(ROOT / "src"),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_wsl_successor_lock_remains_immutable_historical_evidence(self) -> None:
        value = json.loads(LOCK.read_text(encoding="utf-8"))
        self.assertEqual(
            {
                "lock_version",
                "lock_id",
                "base_revision",
                "scope",
                "status",
                "evidence_status",
                "synthetic_only",
                "entries",
                "authority_boundary",
                "source_set_digest",
            },
            set(value),
        )
        self.assertEqual("d0_candidate", value["status"])
        self.assertEqual("synthetic_d0", value["evidence_status"])
        self.assertTrue(value["synthetic_only"])
        self.assertTrue(
            all(item is False for item in value["authority_boundary"].values())
        )
        self.assertEqual(
            value["source_set_digest"],
            canonical_digest(
                {key: item for key, item in value.items() if key != "source_set_digest"}
            ),
        )
        paths = [entry["path"] for entry in value["entries"]]
        self.assertEqual(sorted(EXPECTED_PATHS), paths)
        self.assertEqual(len(paths), len(set(paths)))
        for entry in value["entries"]:
            self.assertEqual("orbit-agent-control-plane", entry["repository"])
            self.assertRegex(entry["sha256"], DIGEST)

    def test_lan_successor_lock_closes_current_candidate_bytes(self) -> None:
        value = json.loads(LAN_LOCK.read_text(encoding="utf-8"))
        self.assertEqual("d0_candidate", value["status"])
        self.assertEqual("synthetic_d0", value["evidence_status"])
        self.assertTrue(value["synthetic_only"])
        self.assertTrue(
            all(item is False for item in value["authority_boundary"].values())
        )
        self.assertEqual(
            value["source_set_digest"],
            canonical_digest(
                {key: item for key, item in value.items() if key != "source_set_digest"}
            ),
        )
        paths = [entry["path"] for entry in value["entries"]]
        self.assertEqual(sorted(paths), paths)
        self.assertEqual(len(paths), len(set(paths)))
        for entry in value["entries"]:
            self.assertEqual("orbit-agent-control-plane", entry["repository"])
            self.assertRegex(entry["sha256"], DIGEST)
            path = ROOT / entry["path"]
            self.assertTrue(path.is_file())
            self.assertFalse(path.is_symlink())
            self.assertEqual(
                entry["sha256"],
                "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()

