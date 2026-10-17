"""Supported owner-gated start command for the local public Pilot stack."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .local_operator import LocalTrustedOperatorGuard


def run() -> None:
    root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--state-root", type=Path, default=root / ".local-state/service"
    )
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--validate-only", action="store_true")
    actions.add_argument("--fixture-up", action="store_true")
    actions.add_argument("--provider-up", action="store_true")
    actions.add_argument("--create-enablement-receipt", action="store_true")
    parser.add_argument("--enablement-receipt", type=Path)
    parser.add_argument("--review-package", type=Path)
    parser.add_argument("--approval-prompt", type=Path)
    args = parser.parse_args()
    state_root = args.state_root.resolve(strict=True)
    protected = [
        state_root / name
        for name in (
            "postgres-password",
            "database-url",
            "grant-signing-key.pem",
            "grant-signing-public.pem",
        )
    ]
    if args.provider_up:
        if (
            args.enablement_receipt is None
            or args.review_package is None
            or args.approval_prompt is not None
        ):
            raise SystemExit("local_pilot_enablement_missing")
        protected.extend((state_root / "fixture-api-key", args.enablement_receipt))
    elif args.create_enablement_receipt:
        if args.review_package is None or args.approval_prompt is None:
            raise SystemExit("local_pilot_enablement_missing")
        if args.enablement_receipt is None:
            args.enablement_receipt = (
                state_root / "pilot-enablement-receipt.public.json"
            )
        if args.enablement_receipt.resolve().parent != state_root:
            raise SystemExit("local_pilot_enablement_path_invalid")
    elif (
        args.enablement_receipt is not None
        or args.review_package is not None
        or args.approval_prompt is not None
    ):
        raise SystemExit("local_pilot_enablement_unexpected")
    principal = LocalTrustedOperatorGuard(
        owner_uid=os.geteuid(),
        state_root=state_root,
        protected_files=tuple(protected),
    ).verify_current_process()
    if args.provider_up:
        validate_pilot_enablement(
            receipt_path=args.enablement_receipt,
            review_package_path=args.review_package,
        )
    if args.create_enablement_receipt:
        receipt = create_pilot_enablement_receipt(
            receipt_path=args.enablement_receipt,
            review_package_path=args.review_package,
            approval_prompt_path=args.approval_prompt,
            approved_by_human_ref=principal.operator_ref,
        )
        print(json.dumps(receipt, sort_keys=True))
        return
    if args.validate_only:
        print(
            json.dumps(
                {
                    "status": "ready",
                    "profile": principal.profile,
                    "operator_ref": principal.operator_ref,
                    "production_authorization": False,
                    "release_authorization": False,
                },
                sort_keys=True,
            )
        )
        return
    compose_files = [root / "deploy/service/compose.local-pilot-fixture.yaml"]
    if args.provider_up:
        compose_files.append(root / "deploy/service/compose.local-pilot-provider.yaml")
    compose_args = [item for path in compose_files for item in ("-f", str(path))]
    os.execvp(
        "docker",
        (
            "docker",
            "compose",
            *compose_args,
            "up",
            "--build",
            "--detach",
        ),
    )


def validate_pilot_enablement(
    *, receipt_path: Path, review_package_path: Path
) -> dict[str, Any]:
    """Validate one owner-only local receipt against the committed review bytes."""
    receipt = _strict_json(receipt_path)
    review = _strict_json(review_package_path)
    receipt_fields = {
        "receipt_version",
        "status",
        "scope",
        "review_package_raw_digest",
        "review_package_digest",
        "automation_policy_digest",
        "approved_by_human_ref",
        "approval_text_digest",
        "activated_at",
        "expires_at",
        "single_pilot",
        "max_provider_attempts",
        "max_cost_usd",
        "max_cost_cny",
        "production_authorization",
        "release_authorization",
        "receipt_digest",
    }
    content = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    try:
        activated = _time(receipt["activated_at"])
        expires = _time(receipt["expires_at"])
        review_expires = _time(review["expires_at"])
        pilot_budget = review["pilot_budget"]
        max_provider_attempts = pilot_budget["max_provider_attempts"]
        max_cost_usd = pilot_budget["max_cost_usd"]
        max_cost_cny = pilot_budget["max_cost_cny"]
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit("local_pilot_enablement_invalid") from error
    now = datetime.now(timezone.utc)
    if (
        set(receipt) != receipt_fields
        or receipt["receipt_version"]
        != "orbit.local-public-pilot-enablement-receipt/1"
        or receipt["status"] != "active"
        or receipt["scope"] != "public_r2_pilot_enablement"
        or receipt["review_package_raw_digest"] != _file_digest(review_package_path)
        or receipt["review_package_digest"] != review.get("review_package_digest")
        or receipt["automation_policy_digest"]
        != review.get("automation_policy_digest")
        or not isinstance(receipt["approved_by_human_ref"], str)
        or not receipt["approved_by_human_ref"].startswith("human_")
        or not _is_digest(receipt["approval_text_digest"])
        or receipt["single_pilot"] is not True
        or receipt["max_provider_attempts"] != max_provider_attempts
        or receipt["max_cost_usd"] != max_cost_usd
        or receipt["max_cost_cny"] != max_cost_cny
        or receipt["production_authorization"] is not False
        or receipt["release_authorization"] is not False
        or receipt["receipt_digest"] != _digest(content)
        or not activated <= now < expires <= review_expires
    ):
        raise SystemExit("local_pilot_enablement_invalid")
    return receipt


def create_pilot_enablement_receipt(
    *,
    receipt_path: Path,
    review_package_path: Path,
    approval_prompt_path: Path,
    approved_by_human_ref: str,
) -> dict[str, Any]:
    """Create or idempotently reuse one exact owner-only local Receipt."""
    review = _strict_json(review_package_path)
    review_content = {
        key: value for key, value in review.items() if key != "review_package_digest"
    }
    try:
        review_digest = review["review_package_digest"]
        policy_digest = review["automation_policy_digest"]
        expires_at = review["expires_at"]
        pilot_budget = review["pilot_budget"]
    except (KeyError, TypeError) as error:
        raise SystemExit("local_pilot_review_invalid") from error
    prompt_digest = _file_digest(approval_prompt_path)
    prompt = approval_prompt_path.read_text(encoding="utf-8")
    review_raw = _file_digest(review_package_path)
    if (
        review_digest != _digest(review_content)
        or review.get("status") != "awaiting_human_pilot_enablement"
        or review.get("runtime_started") is not False
        or review.get("model_called") is not False
        or review.get("production_authorization") is not False
        or review.get("release_authorization") is not False
        or review_raw not in prompt
        or review_digest not in prompt
        or policy_digest not in prompt
        or not approved_by_human_ref.startswith("human_local_os_owner_uid_")
    ):
        raise SystemExit("local_pilot_review_invalid")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    if not now < _time(expires_at):
        raise SystemExit("local_pilot_review_expired")
    content = {
        "receipt_version": "orbit.local-public-pilot-enablement-receipt/1",
        "status": "active",
        "scope": "public_r2_pilot_enablement",
        "review_package_raw_digest": review_raw,
        "review_package_digest": review_digest,
        "automation_policy_digest": policy_digest,
        "approved_by_human_ref": approved_by_human_ref,
        "approval_text_digest": prompt_digest,
        "activated_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at,
        "single_pilot": True,
        "max_provider_attempts": pilot_budget["max_provider_attempts"],
        "max_cost_usd": pilot_budget["max_cost_usd"],
        "max_cost_cny": pilot_budget["max_cost_cny"],
        "production_authorization": False,
        "release_authorization": False,
    }
    receipt = {**content, "receipt_digest": _digest(content)}
    encoded = (
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode()
    if receipt_path.exists():
        existing = validate_pilot_enablement(
            receipt_path=receipt_path,
            review_package_path=review_package_path,
        )
        if (
            existing["review_package_raw_digest"] != review_raw
            or existing["approval_text_digest"] != prompt_digest
            or existing["approved_by_human_ref"] != approved_by_human_ref
        ):
            raise SystemExit("local_pilot_enablement_conflict")
        return existing
    descriptor = os.open(
        receipt_path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        written = 0
        while written < len(encoded):
            count = os.write(descriptor, encoded[written:])
            if count <= 0:
                raise SystemExit("local_pilot_enablement_write_failed")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return validate_pilot_enablement(
        receipt_path=receipt_path,
        review_package_path=review_package_path,
    )


def _strict_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: _reject_constant(),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit("local_pilot_enablement_invalid") from error
    if not isinstance(value, dict):
        raise SystemExit("local_pilot_enablement_invalid")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_key")
        value[key] = item
    return value


def _reject_constant() -> None:
    raise ValueError("nonfinite_number")


def _time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("time_invalid")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def _file_digest(path: Path) -> str:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4 * 1024 * 1024:
        raise SystemExit("local_pilot_enablement_invalid")
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value: Any) -> str:
    source = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return "sha256:" + hashlib.sha256(source).hexdigest()


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


if __name__ == "__main__":
    run()

