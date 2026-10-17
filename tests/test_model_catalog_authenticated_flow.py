"""Real LAN account/session gates in an isolated synthetic ASGI composition.

No external socket, provider credential, model, Runtime or central DB is used.
An explicit evidence directory retains test accounts and their local DB copy.
"""

import json
import os
import secrets
import shutil
import unittest
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from orbit_agent_control_plane.service_runtime.control_console import (
    ControlConsoleService,
)
from orbit_agent_control_plane.service_runtime.department_cockpit import (
    DepartmentCockpitService,
)
from orbit_agent_control_plane.service_runtime.governance_catalogs import (
    GovernanceCatalogService,
)
from orbit_agent_control_plane.service_runtime.lan_stage1 import (
    LanHumanIdentityService,
    LanNodeService,
    LanWorkloadIdentityService,
)
from orbit_agent_control_plane.service_runtime.lan_stage1_api import (
    CSRF_HEADER,
    create_human_app,
)
from orbit_agent_control_plane.service_runtime.model_route_credentials import (
    ModelRouteCredentialService,
)
from tests import test_model_catalog as fixture
from tests import test_model_catalog_integrity as requests_fixture
from tests.test_model_catalog_api_flow import SyntheticHealth

ADMIN = "role_control_plane_admin"
OWNER = "role_department_owner"
USER = "role_department_user"
ORIGIN = "https://test.catalog.invalid"
ROOT = Path(__file__).resolve().parents[1]


class ModelCatalogAuthenticatedFlowTests(unittest.TestCase):
    def setUp(self):
        fixture.ModelCatalogTests.setUp(self)
        self.now = fixture.NOW
        self.service.now = lambda: self.now
        routes = self.service.model_routes
        routes.now = lambda: self.now
        routes.secret_provider = SyntheticHealth()
        credentials = ModelRouteCredentialService(
            database=self.database,
            secret_provider=routes.secret_provider,
            now=lambda: self.now,
        )
        routes.credential_health_provider = credentials
        self.identity = LanHumanIdentityService(self.database, now=lambda: self.now)
        self.password = secrets.token_urlsafe(30)
        self.account_inventory = []
        self.identity.bootstrap_admin_cli_only(
            username="test.catalog.admin",
            password=self.password,
            display_name="test 合成公司管理员",
        )
        console = ControlConsoleService(
            database=self.database,
            model_routes=routes,
            grant_revocations=None,
            credentials=credentials,
            model_catalog=self.service,
            now=lambda: self.now,
        )
        self.app = create_human_app(
            identity=self.identity,
            workloads=LanWorkloadIdentityService(self.database, now=lambda: self.now),
            nodes=LanNodeService(self.database, now=lambda: self.now),
            allowed_origins=[ORIGIN],
            cockpit=DepartmentCockpitService(
                database=self.database, agent_proposals=self.service
            ),
            governance_catalogs=GovernanceCatalogService(
                database=self.database, repository_root=ROOT
            ),
            control_console=console,
        )
        self.clients = []
        self.sequence = 0
        self.admin = self.login("test.catalog.admin")

    def tearDown(self):
        for client in self.clients:
            client.close()
        destination = os.environ.get("ORBIT_AUTH_TEST_EVIDENCE_DIR")
        if destination:
            base = Path(destination)
            self.assertTrue(
                base.is_absolute() and base.is_dir() and not base.is_symlink()
            )
            output = base / self._testMethodName
            output.mkdir(mode=0o700)
            self.database.dispose()
            for source in Path(self.temporary.name).iterdir():
                if source.is_file():
                    target = output / source.name
                    shutil.copyfile(source, target)
                    target.chmod(0o600)
            inventory = {
                "test_only": True,
                "scope": "isolated_asgi_database",
                "accounts": self.account_inventory,
                "central_accounts_created": False,
                "provider_health": "synthetic_stub_no_secret_read",
                "model_called": False,
                "runtime_started": False,
            }
            for name, value in [
                ("accounts.test.json", inventory),
                (
                    "credentials.private.json",
                    {"test_only": True, "password": self.password},
                ),
            ]:
                file = output / name
                with file.open("x") as stream:
                    json.dump(value, stream, ensure_ascii=False, indent=2)
                file.chmod(0o600)
        fixture.ModelCatalogTests.tearDown(self)

    def key(self):
        self.sequence += 1
        return f"test:authenticated:{self.sequence:04d}"

    def client(self):
        client = TestClient(self.app, base_url=ORIGIN)
        self.clients.append(client)
        return client

    def send(self, client, path, body, expected=201, *, key=None, headers=None):
        values = {
            "Origin": ORIGIN,
            "Idempotency-Key": key or self.key(),
            CSRF_HEADER: client.headers.get(CSRF_HEADER, ""),
        }
        if headers is not None:
            values.update(headers)
        response = client.post(path, json=body, headers=values)
        self.assertEqual(expected, response.status_code, response.text)
        return response

    def login(self, username, *, reauth=False):
        client = self.client()
        response = self.send(
            client,
            "/v1/auth/login",
            {
                "username": username,
                "password": self.password,
            },
            expected=200,
        )
        cookie = response.headers["set-cookie"].lower()
        for flag in ("secure", "httponly", "samesite=strict"):
            self.assertIn(flag, cookie)
        client.headers[CSRF_HEADER] = response.headers[CSRF_HEADER]
        user = response.json()["user"]
        self.account_inventory.append(
            {
                key: user[key]
                for key in (
                    "account_id",
                    "username",
                    "role_refs",
                    "department_refs",
                )
            }
        )
        if reauth:
            self.reauth(client)
        return client

    def reauth(self, client):
        response = self.send(
            client, "/v1/auth/reauth", {"password": self.password}, expected=200
        )
        if CSRF_HEADER in response.headers:
            client.headers[CSRF_HEADER] = response.headers[CSRF_HEADER]

    def create_account(self, approver, department, role, username):
        invitation = self.send(
            approver,
            "/v1/auth/invitations",
            {
                "department_id": department,
                "role_ref": role,
            },
        ).json()
        pending_client = self.client()
        pending = self.send(
            pending_client,
            "/v1/auth/register",
            {
                "invite_code": invitation["invite_code"],
                "username": username,
                "password": self.password,
                "display_name": "test 合成验收账号",
            },
        ).json()["user"]
        self.send(
            pending_client,
            "/v1/auth/login",
            {
                "username": username,
                "password": self.password,
            },
            expected=401,
        )
        approval_key = self.key()
        path = "/v1/auth/accounts/" + pending["account_id"] + "/approve"
        self.send(approver, path, {}, expected=200, key=approval_key)
        return self.login(username, reauth=True), pending, path, approval_key

    def discovery_request(self):
        response = self.admin.get("/v1/control/model-provider-presets")
        self.assertEqual(200, response.status_code)
        preset = next(
            item
            for item in response.json()["items"]
            if item["provider_preset_id"] == "provider_preset_openai_codex"
        )
        return {
            "provider_preset_id": preset["provider_preset_id"],
            "provider_preset_revision_digest": preset["revision_digest"],
            "region_id": "global_service",
            "connection_alias": "Codex 公司连接",
            "idempotency_key": self.key(),
        }

    def test_real_session_reauth_origin_csrf_and_logout(self):
        path = "/v1/control/provider-model-discoveries"
        body = self.discovery_request()
        self.send(self.admin, path, body, expected=403)
        self.reauth(self.admin)
        self.send(
            self.admin,
            path,
            body,
            expected=403,
            headers={CSRF_HEADER: "wrong-test-csrf"},
        )
        self.send(
            self.admin,
            path,
            body,
            expected=403,
            headers={"Origin": "https://wrong.test.invalid"},
        )
        self.assertEqual([], self.service.list_catalog_entries()["items"])
        self.send(self.admin, path, body)
        self.now += timedelta(minutes=16)
        self.send(
            self.admin, path, {**body, "idempotency_key": self.key()}, expected=403
        )
        self.reauth(self.admin)
        self.send(self.admin, path, {**body, "idempotency_key": self.key()})
        self.send(self.admin, "/v1/auth/logout", {}, expected=204)
        self.assertEqual(
            401, self.admin.get("/v1/control/model-provider-presets").status_code
        )

    def test_account_approval_replay_is_bound_to_original_actor(self):
        self.reauth(self.admin)
        tech, _, _, _ = self.create_account(
            self.admin, "technology_center", OWNER, "test.technology.owner"
        )
        product, _, _, _ = self.create_account(
            self.admin, "product_center", OWNER, "test.product.owner"
        )
        _, _, path, key = self.create_account(
            tech, "technology_center", USER, "test.technology.user"
        )
        self.assertTrue(
            self.send(tech, path, {}, expected=200, key=key).json()["replayed"]
        )
        self.send(product, path, {}, expected=409, key=key)

    def test_authenticated_catalog_and_department_revision_exchange(self):
        self.reauth(self.admin)
        owner, principal, _, _ = self.create_account(
            self.admin, "technology_center", OWNER, "test.catalog.owner"
        )
        user, _, _, _ = self.create_account(
            owner, "technology_center", USER, "test.catalog.user"
        )
        discovery = self.send(
            self.admin,
            "/v1/control/provider-model-discoveries",
            self.discovery_request(),
        ).json()
        entry = self.send(
            self.admin,
            "/v1/control/model-catalog-entries",
            {
                "discovery_digest": discovery["discovery_digest"],
                "provider_model_key": discovery["models"][0]["provider_model_key"],
                "idempotency_key": self.key(),
            },
        ).json()
        base = "/v1/control/model-catalog-entries/" + entry["entry_id"]
        self.send(
            self.admin,
            base + "/credential-bindings",
            {
                "expected_entry_revision_digest": entry["entry_revision_digest"],
                "authentication_mode": "api_key_ref",
                "expected_binding_version": "synthetic-v1",
                "idempotency_key": self.key(),
            },
        )
        receipt = self.send(
            self.admin,
            base + "/availability-receipts",
            {
                "expected_entry_revision_digest": entry["entry_revision_digest"],
                "reason": "test 合成凭据版本与目录资格核验，不调用供应商",
                "idempotency_key": self.key(),
            },
        ).json()
        entry["entry_revision_digest"] = receipt["entry_revision_digest"]
        body = requests_fixture.ModelCatalogIntegrityTests.proposal_request(self, entry)
        body.pop("actor_ref")
        body.pop("department_id")
        body["agent_name"] = "test 技术评审 Agent"
        path = "/v1/department-cockpit/technology_center/agent-proposals"
        self.send(user, path, body, expected=403)
        self.send(
            owner,
            path.replace("technology_center", "product_center"),
            body,
            expected=403,
        )
        first = self.send(owner, path, body).json()
        review_path = (
            "/v1/control/department-agent-proposals/"
            + first["proposal_id"]
            + "/activation-decisions"
        )
        self.send(
            self.admin,
            review_path,
            {
                "decision_scope": "agent_activation",
                "expected_package_digest": first["package_digest"],
                "expected_agent_definition_digest": first["agent_binding"][
                    "agent_definition_digest"
                ],
                "decision": "revision_required",
                "reason": "test 补充合成输出的验收边界后重新提交",
                "idempotency_key": self.key(),
            },
        )
        second = self.send(
            owner,
            path,
            {
                **body,
                "task_scope": "test 仅评审合成输入，并提供明确的输出验收条件",
                "supersedes_package_digest": first["package_digest"],
                "idempotency_key": self.key(),
            },
        ).json()
        self.assertEqual(2, second["revision"])
        export = owner.get(path + "/" + second["package_digest"] + "/exchange")
        self.assertEqual(200, export.status_code, export.text)
        self.assertIn(principal["account_id"], json.dumps(export.json()))
        self.assertNotIn("secret://", export.text)
        self.assertFalse(second["execution_grant_issued"])
        self.assertFalse(second["agent_and_route_eligible"])

