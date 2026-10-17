from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.full_chain_enablement import (
    create_full_chain_enablement_receipt,
    validate_full_chain_enablement_receipt,
)
from orbit_agent_control_plane.service_runtime.models import Base
from orbit_agent_control_plane.service_runtime.public_pilot_execution import (
    _validate_execution_enablement,
)
from scripts.prepare_full_chain_model_route import prepare

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence/full-chain-pilot/2026-08-29"


class FullChainEnablementTests(unittest.TestCase):
    def test_one_human_checkpoint_creates_five_nonconvertible_internal_scopes(
        self,
    ) -> None:
        review = EVIDENCE / "full-chain-pilot-review-package.json"
        artifact_set = EVIDENCE / "skill-artifact-set.json"
        approval_text = (EVIDENCE / "approval-prompt.zh-CN.md").read_text(
            encoding="utf-8"
        )
        with tempfile.TemporaryDirectory() as temporary:
            receipt_path = Path(temporary) / "full-chain-enablement.public.json"
            observation_path = Path(temporary) / "provider-observation.public.json"
            receipt = create_full_chain_enablement_receipt(
                review_package_path=review,
                artifact_set_path=artifact_set,
                approval_text=approval_text,
                approved_by_human_ref="human_local_os_owner_uid_501",
                receipt_path=receipt_path,
                provider_observation_path=observation_path,
                now=datetime.now(timezone.utc),
            )
            replay = validate_full_chain_enablement_receipt(
                review_package_path=review,
                artifact_set_path=artifact_set,
                receipt_path=receipt_path,
            )
            self.assertEqual(receipt, replay)
            self.assertEqual(
                receipt,
                _validate_execution_enablement(
                    receipt_path=receipt_path,
                    review_package_path=review,
                ),
            )
            self.assertEqual(0o600, os.stat(receipt_path).st_mode & 0o777)
            self.assertEqual(0o600, os.stat(observation_path).st_mode & 0o777)
            observation = observation_path.read_text(encoding="utf-8")
            self.assertIn("fixture-structured-v1-2026-07-09", observation)
            self.assertNotIn("api_key", observation.lower())
        self.assertEqual(5, len(receipt["internal_scopes"]))
        self.assertTrue(all(not item["convertible"] for item in receipt["internal_scopes"]))
        self.assertTrue(
            all(
                item["status"] == "approved_unconsumed"
                for item in receipt["internal_scopes"]
            )
        )
        self.assertFalse(receipt["release_authorization"])

    def test_approved_observation_produces_ready_deploy_preflight(self) -> None:
        review = EVIDENCE / "full-chain-pilot-review-package.json"
        artifact_set = EVIDENCE / "skill-artifact-set.json"
        approval_text = (EVIDENCE / "approval-prompt.zh-CN.md").read_text(
            encoding="utf-8"
        )
        route = ROOT / (
            "references/model-route-revisions/"
            "disease-r2-fixture-fixture-structured-v1.public.json"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret = root / "fixture-key"
            secret.write_text("offline-secret-not-used", encoding="utf-8")
            os.chmod(secret, 0o600)
            bindings = root / "bindings.json"
            bindings.write_text(
                json.dumps(
                    {
                        "binding_version": "orbit.model-route-secret-bindings/1",
                        "bindings": {
                            "secret://local/fixture/current": {
                                "path": str(secret),
                                "version": "test-current-v1",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(bindings, 0o600)
            receipt = root / "receipt.json"
            observation = root / "observation.json"
            create_full_chain_enablement_receipt(
                review_package_path=review,
                artifact_set_path=artifact_set,
                approval_text=approval_text,
                approved_by_human_ref="human_local_os_owner_uid_501",
                receipt_path=receipt,
                provider_observation_path=observation,
            )
            database_url = f"sqlite+pysqlite:///{root / 'state.sqlite3'}"
            database = Database(database_url)
            Base.metadata.create_all(database.engine)
            database.dispose()
            output = root / "preflight.json"
            result = prepare(
                database_url=database_url,
                route_path=route,
                observation_path=observation,
                secret_bindings_path=bindings,
                output_path=output,
            )
            self.assertEqual("ready", result["status"])
            self.assertEqual(0o600, output.stat().st_mode & 0o777)
            self.assertFalse(result["provider_execution_started"])


if __name__ == "__main__":
    unittest.main()

