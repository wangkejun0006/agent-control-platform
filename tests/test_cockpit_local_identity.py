from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sqlalchemy import select

from orbit_agent_control_plane.service_runtime.cockpit_local_identity import (
    ROLE_DEPARTMENT_OWNER,
    ROLE_DEPARTMENT_USER,
    CockpitLocalIdentityError,
    CockpitLocalIdentityService,
    ScryptPasswordHasher,
)
from orbit_agent_control_plane.service_runtime.cockpit_local_identity_models import (
    CockpitLocalAccountRow,
)
from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.models import Base


class CockpitLocalIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        database_path = Path(self.temporary.name) / "identity.sqlite3"
        self.database = Database(f"sqlite+pysqlite:///{database_path}")
        Base.metadata.create_all(self.database.engine)
        self.service = CockpitLocalIdentityService(
            self.database,
            password_hasher=ScryptPasswordHasher(n=2**10),
        )
        self.password = "Stage1-Identity-Password!"
        self.admin = self.service.register(
            username="control.admin",
            password=self.password,
            display_name="公司管理员",
            department_id=None,
        )
        _, self.admin_principal = self.service.login(
            username="control.admin", password=self.password
        )

    def tearDown(self) -> None:
        self.database.dispose()
        self.temporary.cleanup()

    def test_first_account_is_local_admin_and_hash_never_contains_password(self) -> None:
        self.assertEqual("role_control_plane_admin", self.admin["role_ref"])
        self.assertEqual("active", self.admin["status"])
        with self.database.session() as session:
            row = session.scalar(
                select(CockpitLocalAccountRow).where(
                    CockpitLocalAccountRow.account_id == self.admin["account_id"]
                )
            )
            assert row is not None
            self.assertTrue(row.password_hash.startswith("scrypt-v1$"))
            self.assertNotIn(self.password, row.password_hash)
        permissions = self.admin_principal["permissions"]
        self.assertTrue(permissions["view_all_departments"])
        self.assertTrue(permissions["manage_company_model_routes"])
        self.assertTrue(permissions["assign_department_owner"])
        self.assertFalse(permissions["confirm_tasks"])
        self.assertFalse(permissions["select_department_model_route"])
        self.assertFalse(permissions["select_department_runtime_artifact"])

    def test_registration_requires_approval_and_owner_cannot_cross_department(self) -> None:
        product = self.service.register(
            username="product.owner",
            password=self.password,
            display_name="产品负责人",
            department_id="product_center",
        )
        technology = self.service.register(
            username="technology.user",
            password=self.password,
            display_name="技术用户",
            department_id="technology_center",
        )
        with self.assertRaisesRegex(CockpitLocalIdentityError, "local_login_invalid"):
            self.service.login(username="product.owner", password=self.password)
        approved_owner = self.service.approve_account(
            requester=self.admin_principal,
            account_id=product["account_id"],
            role_ref=ROLE_DEPARTMENT_OWNER,
        )
        self.assertEqual("active", approved_owner["status"])
        _, product_principal = self.service.login(
            username="product.owner", password=self.password
        )
        self.assertTrue(product_principal["permissions"]["confirm_tasks"])
        self.assertTrue(
            product_principal["permissions"]["select_department_model_route"]
        )
        self.assertTrue(
            product_principal["permissions"][
                "select_department_runtime_artifact"
            ]
        )
        self.assertFalse(product_principal["permissions"]["view_all_departments"])
        with self.assertRaisesRegex(
            CockpitLocalIdentityError, "department_scope_not_allowed"
        ):
            self.service.approve_account(
                requester=product_principal,
                account_id=technology["account_id"],
                role_ref=ROLE_DEPARTMENT_USER,
            )
        self.assertEqual(
            [],
            self.service.pending_accounts(
                requester=product_principal, department_id="product_center"
            ),
        )

    def test_failed_logins_are_counted_and_session_logout_revokes_access(self) -> None:
        for _ in range(5):
            with self.assertRaisesRegex(
                CockpitLocalIdentityError, "local_login_invalid"
            ):
                self.service.login(
                    username="control.admin", password="Wrong-Password-Value!"
                )
        with self.database.session() as session:
            row = session.scalar(
                select(CockpitLocalAccountRow).where(
                    CockpitLocalAccountRow.account_id == self.admin["account_id"]
                )
            )
            assert row is not None
            self.assertEqual(5, row.failed_login_count)
            self.assertIsNotNone(row.locked_until)

        service = CockpitLocalIdentityService(
            self.database,
            password_hasher=ScryptPasswordHasher(n=2**10),
        )
        user = service.register(
            username="market.user",
            password=self.password,
            display_name="市场用户",
            department_id="market_center",
        )
        service.approve_account(
            requester=self.admin_principal,
            account_id=user["account_id"],
            role_ref=ROLE_DEPARTMENT_USER,
        )
        token, principal = service.login(
            username="market.user", password=self.password
        )
        self.assertEqual(["market_center"], principal["department_refs"])
        service.logout(token)
        with self.assertRaisesRegex(CockpitLocalIdentityError, "local_session_invalid"):
            service.authenticate(token)

