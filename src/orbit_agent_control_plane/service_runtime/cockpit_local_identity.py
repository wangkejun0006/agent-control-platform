"""Loopback-only local accounts for the stage-1 Department Cockpit.

These records authenticate a browser session for the D0 harness. They are not
the company Human Identity directory, do not authorize production work, and
never turn a local account into an Agent, Grant, or Approval authority source.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select

from .cockpit_local_identity_models import (
    CockpitLocalAccountRow,
    CockpitLocalSessionRow,
)
from .database import Database
from .models import AuditEventRow

DEPARTMENTS = ("product_center", "technology_center", "market_center")
ROLE_CONTROL_PLANE_ADMIN = "role_control_plane_admin"
ROLE_DEPARTMENT_OWNER = "role_department_owner"
ROLE_DEPARTMENT_USER = "role_department_user"
ALLOWED_APPROVAL_ROLES = frozenset(
    {ROLE_DEPARTMENT_OWNER, ROLE_DEPARTMENT_USER}
)

_USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
_ACCOUNT_ID = re.compile(r"^acct_local_[0-9a-f]{24}_syn$")
_SESSION_TTL = timedelta(hours=8)
_LOCKOUT_TTL = timedelta(minutes=5)
_MAX_FAILED_LOGINS = 5


class CockpitLocalIdentityError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class ScryptPasswordHasher:
    """Versioned scrypt password hashes with a unique random salt."""

    def __init__(
        self,
        *,
        n: int = 2**17,
        r: int = 8,
        p: int = 1,
        dklen: int = 32,
    ) -> None:
        if n < 2**10 or n & (n - 1) or r < 1 or p < 1 or dklen < 32:
            raise ValueError("cockpit_password_hasher_parameters_invalid")
        self.n = n
        self.r = r
        self.p = p
        self.dklen = dklen

    def hash(self, password: str) -> str:
        value = _password_bytes(password)
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(
            value,
            salt=salt,
            n=self.n,
            r=self.r,
            p=self.p,
            dklen=self.dklen,
            maxmem=256 * 1024 * 1024,
        )
        return "$".join(
            (
                "scrypt-v1",
                str(self.n),
                str(self.r),
                str(self.p),
                _b64(salt),
                _b64(digest),
            )
        )

    def verify(self, password: str, encoded: str) -> bool:
        try:
            marker, raw_n, raw_r, raw_p, raw_salt, raw_digest = encoded.split("$")
            if marker != "scrypt-v1":
                return False
            n, r, p = int(raw_n), int(raw_r), int(raw_p)
            if n < 2**10 or n > 2**18 or n & (n - 1) or r != 8 or p != 1:
                return False
            salt = _unb64(raw_salt)
            expected = _unb64(raw_digest)
            if len(salt) != 16 or len(expected) != self.dklen:
                return False
            actual = hashlib.scrypt(
                _password_bytes(password),
                salt=salt,
                n=n,
                r=r,
                p=p,
                dklen=len(expected),
                maxmem=256 * 1024 * 1024,
            )
        except (TypeError, ValueError):
            return False
        return hmac.compare_digest(actual, expected)


class CockpitLocalIdentityService:
    """Authenticate local accounts and project department-scoped principals."""

    def __init__(
        self,
        database: Database,
        *,
        password_hasher: ScryptPasswordHasher | None = None,
        session_ttl: timedelta = _SESSION_TTL,
    ) -> None:
        self.database = database
        self.password_hasher = password_hasher or ScryptPasswordHasher()
        self.session_ttl = session_ttl
        self._lock = threading.RLock()
        # Keep username misses on the same slow password-verification path.
        self._dummy_password_hash = self.password_hasher.hash(
            "local-d0-dummy-password-never-valid"
        )

    def public_status(self) -> dict[str, Any]:
        with self.database.session() as session:
            count = session.scalar(select(func.count(CockpitLocalAccountRow.id))) or 0
        return {
            "bootstrap_required": count == 0,
            "registration_mode": (
                "first_account_becomes_local_admin" if count == 0 else "approval_required"
            ),
            "departments": list(DEPARTMENTS),
            "identity_authority": "loopback_d0_local_account_only",
            "production_authorized": False,
        }

    def register(
        self,
        *,
        username: str,
        password: str,
        display_name: str,
        department_id: str | None,
    ) -> dict[str, Any]:
        normalized_username = _username(username)
        clean_display_name = _display_name(display_name)
        _password_bytes(password)
        if department_id is not None and department_id not in DEPARTMENTS:
            raise CockpitLocalIdentityError("local_account_department_invalid")
        now = _now()
        with self._lock, self.database.session() as session:
            if session.scalar(
                select(CockpitLocalAccountRow).where(
                    CockpitLocalAccountRow.username == normalized_username
                )
            ) is not None:
                raise CockpitLocalIdentityError("local_account_username_unavailable")
            count = session.scalar(select(func.count(CockpitLocalAccountRow.id))) or 0
            if count == 0:
                role_ref = ROLE_CONTROL_PLANE_ADMIN
                status = "active"
                effective_department = None
                approved_at = now
                approved_by_ref = "local_first_account_bootstrap"
            else:
                if department_id is None:
                    raise CockpitLocalIdentityError(
                        "local_account_department_required"
                    )
                role_ref = ROLE_DEPARTMENT_USER
                status = "pending_approval"
                effective_department = department_id
                approved_at = None
                approved_by_ref = None
            account_id, human_ref = _account_refs(normalized_username)
            row = CockpitLocalAccountRow(
                account_id=account_id,
                username=normalized_username,
                display_name=clean_display_name,
                local_human_ref=human_ref,
                password_hash=self.password_hasher.hash(password),
                role_ref=role_ref,
                department_id=effective_department,
                status=status,
                failed_login_count=0,
                locked_until=None,
                approved_by_ref=approved_by_ref,
                approved_at=approved_at,
                password_changed_at=now,
                created_at=now,
            )
            session.add(row)
            session.flush()
            self._add_audit(
                session=session,
                event_type="cockpit_local_account_registered",
                account=row,
                actor_ref=human_ref,
            )
            return self._public_account(row)

    def login(self, *, username: str, password: str) -> tuple[str, dict[str, Any]]:
        normalized_username = _username(username)
        now = _now()
        rejection = False
        with self._lock, self.database.session() as session:
            account = session.scalar(
                select(CockpitLocalAccountRow).where(
                    CockpitLocalAccountRow.username == normalized_username
                )
            )
            encoded = (
                self._dummy_password_hash if account is None else account.password_hash
            )
            password_valid = self.password_hasher.verify(password, encoded)
            locked = account is not None and _after(account.locked_until, now)
            active = account is not None and account.status == "active"
            if account is None or not password_valid or locked or not active:
                if account is not None and not locked:
                    account.failed_login_count += 1
                    if account.failed_login_count >= _MAX_FAILED_LOGINS:
                        account.locked_until = now + _LOCKOUT_TTL
                rejection = True
            else:
                account.failed_login_count = 0
                account.locked_until = None
                token = secrets.token_urlsafe(32)
                token_digest = _session_digest(token)
                session.add(
                    CockpitLocalSessionRow(
                        session_id=f"session_local_{secrets.token_hex(16)}_syn",
                        session_digest=token_digest,
                        account_id=account.account_id,
                        created_at=now,
                        expires_at=now + self.session_ttl,
                        revoked_at=None,
                    )
                )
                principal = self._principal(account)
        if rejection:
            raise CockpitLocalIdentityError("local_login_invalid")
        return token, principal

    def authenticate(self, token: str | None) -> dict[str, Any]:
        if not isinstance(token, str) or not 20 <= len(token) <= 128:
            raise CockpitLocalIdentityError("local_session_required")
        now = _now()
        with self.database.session() as session:
            session_row = session.scalar(
                select(CockpitLocalSessionRow).where(
                    CockpitLocalSessionRow.session_digest == _session_digest(token)
                )
            )
            if (
                session_row is None
                or session_row.revoked_at is not None
                or not _after(session_row.expires_at, now)
            ):
                raise CockpitLocalIdentityError("local_session_invalid")
            account = session.scalar(
                select(CockpitLocalAccountRow).where(
                    CockpitLocalAccountRow.account_id == session_row.account_id
                )
            )
            if account is None or account.status != "active":
                raise CockpitLocalIdentityError("local_session_invalid")
            return self._principal(account)

    def logout(self, token: str | None) -> None:
        if not isinstance(token, str):
            return
        with self.database.session() as session:
            row = session.scalar(
                select(CockpitLocalSessionRow).where(
                    CockpitLocalSessionRow.session_digest == _session_digest(token)
                )
            )
            if row is not None and row.revoked_at is None:
                row.revoked_at = _now()

    def pending_accounts(
        self, *, requester: Mapping[str, Any], department_id: str | None
    ) -> list[dict[str, Any]]:
        role = _single_role(requester)
        if role == ROLE_CONTROL_PLANE_ADMIN:
            selected_department = department_id
            if selected_department is not None and selected_department not in DEPARTMENTS:
                raise CockpitLocalIdentityError("local_account_department_invalid")
        elif role == ROLE_DEPARTMENT_OWNER:
            selected_department = requester["department_refs"][0]
            if department_id not in {None, selected_department}:
                raise CockpitLocalIdentityError("department_scope_not_allowed")
        else:
            raise CockpitLocalIdentityError("local_account_approval_not_allowed")
        with self.database.session() as session:
            statement = select(CockpitLocalAccountRow).where(
                CockpitLocalAccountRow.status == "pending_approval"
            )
            if selected_department is not None:
                statement = statement.where(
                    CockpitLocalAccountRow.department_id == selected_department
                )
            rows = tuple(session.scalars(statement.order_by(CockpitLocalAccountRow.id)))
        return [self._public_account(row) for row in rows]

    def approve_account(
        self,
        *,
        requester: Mapping[str, Any],
        account_id: str,
        role_ref: str,
    ) -> dict[str, Any]:
        if not _ACCOUNT_ID.fullmatch(account_id) or role_ref not in ALLOWED_APPROVAL_ROLES:
            raise CockpitLocalIdentityError("local_account_approval_invalid")
        requester_role = _single_role(requester)
        now = _now()
        with self._lock, self.database.session() as session:
            account = session.scalar(
                select(CockpitLocalAccountRow).where(
                    CockpitLocalAccountRow.account_id == account_id
                )
            )
            if account is None:
                raise CockpitLocalIdentityError("local_account_not_found")
            if account.status != "pending_approval" or account.department_id is None:
                raise CockpitLocalIdentityError("local_account_not_pending")
            if requester_role == ROLE_DEPARTMENT_OWNER:
                departments = requester.get("department_refs", [])
                if account.department_id not in departments:
                    raise CockpitLocalIdentityError("department_scope_not_allowed")
                if role_ref != ROLE_DEPARTMENT_USER:
                    raise CockpitLocalIdentityError(
                        "local_account_role_assignment_not_allowed"
                    )
            elif requester_role != ROLE_CONTROL_PLANE_ADMIN:
                raise CockpitLocalIdentityError("local_account_approval_not_allowed")
            account.role_ref = role_ref
            account.status = "active"
            account.approved_by_ref = str(requester["human_ref"])
            account.approved_at = now
            account.failed_login_count = 0
            account.locked_until = None
            self._add_audit(
                session=session,
                event_type="cockpit_local_account_approved",
                account=account,
                actor_ref=str(requester["human_ref"]),
            )
            return self._public_account(account)

    def change_password(
        self,
        *,
        requester: Mapping[str, Any],
        current_password: str,
        new_password: str,
    ) -> None:
        _password_bytes(new_password)
        with self._lock, self.database.session() as session:
            account = session.scalar(
                select(CockpitLocalAccountRow).where(
                    CockpitLocalAccountRow.account_id == requester["account_id"]
                )
            )
            if account is None or not self.password_hasher.verify(
                current_password, account.password_hash
            ):
                raise CockpitLocalIdentityError("local_current_password_invalid")
            if self.password_hasher.verify(new_password, account.password_hash):
                raise CockpitLocalIdentityError("local_new_password_unchanged")
            account.password_hash = self.password_hasher.hash(new_password)
            account.password_changed_at = _now()

    def _principal(self, row: CockpitLocalAccountRow) -> dict[str, Any]:
        departments = (
            list(DEPARTMENTS)
            if row.role_ref == ROLE_CONTROL_PLANE_ADMIN
            else ([] if row.department_id is None else [row.department_id])
        )
        return {
            "account_id": row.account_id,
            "human_ref": row.local_human_ref,
            "username": row.username,
            "display_name": row.display_name,
            "role_refs": [row.role_ref],
            "department_refs": departments,
            "permissions": {
                "view_all_departments": row.role_ref == ROLE_CONTROL_PLANE_ADMIN,
                "confirm_tasks": row.role_ref == ROLE_DEPARTMENT_OWNER,
                "select_department_model_route": row.role_ref
                == ROLE_DEPARTMENT_OWNER,
                "select_department_runtime_artifact": row.role_ref
                == ROLE_DEPARTMENT_OWNER,
                "approve_department_users": row.role_ref
                in {ROLE_CONTROL_PLANE_ADMIN, ROLE_DEPARTMENT_OWNER},
                "assign_department_owner": row.role_ref
                == ROLE_CONTROL_PLANE_ADMIN,
                "manage_company_model_routes": row.role_ref
                == ROLE_CONTROL_PLANE_ADMIN,
            },
            "identity_evidence": "loopback_d0_local_account_mapping",
            "production_authorized": False,
        }

    @staticmethod
    def _public_account(row: CockpitLocalAccountRow) -> dict[str, Any]:
        return {
            "account_id": row.account_id,
            "username": row.username,
            "display_name": row.display_name,
            "role_ref": row.role_ref,
            "department_id": row.department_id,
            "status": row.status,
            "created_at": row.created_at.isoformat(),
            "approved_at": (
                None if row.approved_at is None else row.approved_at.isoformat()
            ),
            "identity_authority": "loopback_d0_local_account_only",
            "production_authorized": False,
        }

    @staticmethod
    def _add_audit(
        *,
        session,
        event_type: str,
        account: CockpitLocalAccountRow,
        actor_ref: str,
    ) -> None:
        seed = f"{event_type}:{account.account_id}:{actor_ref}"
        audit_id = f"audit_local_identity_{hashlib.sha256(seed.encode()).hexdigest()[:32]}"
        session.add(
            AuditEventRow(
                audit_id=audit_id,
                correlation_id=account.account_id,
                event_type=event_type,
                actor_ref=actor_ref,
                payload={
                    "department_id": account.department_id,
                    "account_id": account.account_id,
                    "role_ref": account.role_ref,
                    "status": account.status,
                    "identity_authority": "loopback_d0_local_account_only",
                    "release_authorization": False,
                },
                recorded_at=_now(),
            )
        )


def _username(value: str) -> str:
    if not isinstance(value, str):
        raise CockpitLocalIdentityError("local_account_username_invalid")
    normalized = value.strip().lower()
    if not _USERNAME.fullmatch(normalized):
        raise CockpitLocalIdentityError("local_account_username_invalid")
    return normalized


def _display_name(value: str) -> str:
    if not isinstance(value, str):
        raise CockpitLocalIdentityError("local_account_display_name_invalid")
    normalized = " ".join(value.split())
    if not 2 <= len(normalized) <= 40 or any(ord(item) < 32 for item in normalized):
        raise CockpitLocalIdentityError("local_account_display_name_invalid")
    return normalized


def _password_bytes(value: str) -> bytes:
    if not isinstance(value, str) or not 12 <= len(value) <= 128:
        raise CockpitLocalIdentityError("local_account_password_invalid")
    encoded = value.encode("utf-8")
    if len(encoded) > 512:
        raise CockpitLocalIdentityError("local_account_password_invalid")
    return encoded


def _account_refs(username: str) -> tuple[str, str]:
    suffix = hashlib.sha256(username.encode()).hexdigest()[:24]
    return f"acct_local_{suffix}_syn", f"hum_local_{suffix}_syn"


def _session_digest(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode()).hexdigest()


def _single_role(principal: Mapping[str, Any]) -> str:
    roles = principal.get("role_refs")
    if not isinstance(roles, list) or len(roles) != 1 or not isinstance(roles[0], str):
        raise CockpitLocalIdentityError("local_principal_role_invalid")
    return roles[0]


def _after(value: datetime | None, boundary: datetime) -> bool:
    if value is None:
        return False
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value > boundary


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)

