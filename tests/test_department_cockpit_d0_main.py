from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from orbit_agent_control_plane.service_runtime.department_cockpit_d0_main import (
    _prepare_database_path,
    build_d0_app,
)


class DepartmentCockpitD0MainTests(unittest.TestCase):
    def test_loopback_harness_exposes_only_synthetic_scoped_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = build_d0_app(
                database_path=Path(temporary) / "cockpit.sqlite3",
                password_scrypt_n=2**10,
            )
            with TestClient(app) as client:
                health = client.get("/health/live")
                auth_status = client.get("/v1/auth/status")
                missing = client.get(
                    "/v1/department-cockpit/product_center/bootstrap"
                )
                no_origin_registration = client.post(
                    "/v1/auth/register",
                    json={
                        "username": "control.admin",
                        "password": "Stage1-Admin-Password!",
                        "display_name": "公司管理员",
                        "department_id": None,
                    },
                )
                registered = client.post(
                    "/v1/auth/register",
                    headers=_mutation_headers(),
                    json={
                        "username": "control.admin",
                        "password": "Stage1-Admin-Password!",
                        "display_name": "公司管理员",
                        "department_id": None,
                    },
                )
                login = client.post(
                    "/v1/auth/login",
                    headers=_mutation_headers(),
                    json={
                        "username": "control.admin",
                        "password": "Stage1-Admin-Password!",
                    },
                )
                me = client.get("/v1/auth/me")
                allowed = client.get(
                    "/v1/department-cockpit/product_center/bootstrap"
                )
                created = client.post(
                    "/v1/department-cockpit/product_center/sessions",
                    headers=_mutation_headers(),
                    json={
                        "message": "本地 D0 联调产品任务",
                        "artifact_refs": [],
                        "idempotency_key": "product:d0-browser:0001",
                    },
                )
                formal_security = client.get("/v1/security/status")
                governance_mutation = client.post(
                    "/v1/tool-registrations",
                    headers=_mutation_headers(),
                    json={},
                )
            app.state.runtime.database.dispose()

        self.assertEqual(200, health.status_code)
        self.assertTrue(health.json()["synthetic_only"])
        self.assertTrue(health.json()["planning_runtime_started"])
        self.assertFalse(health.json()["professional_runtime_started"])
        self.assertFalse(health.json()["live_model_enabled"])
        self.assertFalse(health.json()["release_authorization"])
        self.assertTrue(auth_status.json()["bootstrap_required"])
        self.assertEqual(401, missing.status_code)
        self.assertEqual(403, no_origin_registration.status_code)
        self.assertEqual(201, registered.status_code)
        self.assertEqual("role_control_plane_admin", registered.json()["role_ref"])
        self.assertEqual(200, login.status_code)
        self.assertIn("HttpOnly", login.headers["set-cookie"])
        self.assertIn("SameSite=strict", login.headers["set-cookie"])
        self.assertNotIn("Stage1-Admin-Password!", login.text)
        self.assertEqual("control.admin", me.json()["user"]["username"])
        self.assertTrue(me.json()["user"]["permissions"]["view_all_departments"])
        self.assertFalse(me.json()["user"]["permissions"]["confirm_tasks"])
        self.assertFalse(
            me.json()["user"]["permissions"]["select_department_model_route"]
        )
        self.assertFalse(
            me.json()["user"]["permissions"][
                "select_department_runtime_artifact"
            ]
        )
        self.assertEqual(200, allowed.status_code)
        self.assertEqual("d0_synthetic_only", allowed.json()["service_mode"])
        self.assertEqual(403, created.status_code)
        self.assertEqual(404, formal_security.status_code)
        self.assertEqual(404, governance_mutation.status_code)

    def test_database_must_be_owner_local_temporary_sqlite(self) -> None:
        with self.assertRaisesRegex(
            ValueError, "^department_cockpit_d0_database_path_invalid$"
        ):
            build_d0_app(database_path=Path("/var/empty/cockpit.sqlite3"))

    def test_database_path_environment_override_is_still_validated(self) -> None:
        with patch.dict(
            "os.environ",
            {"ORBIT_COCKPIT_D0_DATABASE_PATH": "/var/empty/cockpit.sqlite3"},
        ), self.assertRaisesRegex(
            ValueError, "^department_cockpit_d0_database_path_invalid$"
        ):
            build_d0_app()

    def test_database_can_be_placed_directly_under_shared_temporary_root(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".sqlite3") as database_file, patch(
            "orbit_agent_control_plane.service_runtime.department_cockpit_d0_main.os.chmod"
        ) as chmod:
            database_path = Path(database_file.name)
            _prepare_database_path(database_path)

        chmod.assert_called_once_with(database_path, 0o600)


def _mutation_headers() -> dict[str, str]:
    return {
        "Origin": "http://testserver",
        "X-Orbit-Request": "department-cockpit",
    }


if __name__ == "__main__":
    unittest.main()

