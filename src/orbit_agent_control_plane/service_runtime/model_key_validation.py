"""Explicit, budgeted API-key acceptance before saving a catalog credential.

Only the reviewed WeMeta Chat Completions profile is implemented. Ordinary
catalog reads and tests never call a model. Secrets stay in process memory until
one successful request; receipts contain hashes, bounded usage and reason codes.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .model_route import OwnerOnlyFileSecretProvider

ENDPOINT = "https://models.paper-orbit.invalid/v1/chat/completions"
MODEL = "fixture-structured-v1"
RESERVATION = 20480  # 2048 input at $6.25/M + 256 completion at $30/M.
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TOKEN = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")


class KeyTestError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise KeyTestError("model_key_test_" + reason)


def digest(value):
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                value, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        ).hexdigest()
    )


def utc(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None, "timestamp_invalid")
    return parsed.astimezone(timezone.utc)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    return json.loads(
        raw,
        object_pairs_hook=pairs,
        parse_constant=lambda _: require(False, "invalid_json_constant"),
    )


def owner_document(path):
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.getuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_size <= 1024 * 1024,
        "file_metadata_invalid",
    )
    return strict_json(path.read_bytes())


def validate_policy(policy, now):
    require(
        set(policy)
        == {
            "schema_version",
            "budget_id",
            "max_cost_microusd",
            "reservation_microusd",
            "price_observed_at",
            "expires_at",
            "endpoint",
            "model",
            "allowed_returned_models",
        },
        "policy_invalid",
    )
    require(
        policy["schema_version"] == "orbit.model-key-test-policy/1"
        and isinstance(policy["budget_id"], str)
        and TOKEN.fullmatch(policy["budget_id"]),
        "policy_invalid",
    )
    require(
        policy["endpoint"] == ENDPOINT and policy["model"] == MODEL,
        "profile_unconfigured",
    )
    allowed = policy["allowed_returned_models"]
    require(
        isinstance(allowed, list)
        and allowed
        and len(allowed) <= 4
        and all(
            isinstance(v, str)
            and re.fullmatch(re.escape(MODEL) + r"(?:-\d{4}-\d{2}-\d{2})?", v)
            for v in allowed
        ),
        "model_allowlist_invalid",
    )
    require(
        type(policy["max_cost_microusd"]) is int
        and 0 < policy["max_cost_microusd"] <= 300000
        and type(policy["reservation_microusd"]) is int
        and policy["reservation_microusd"] >= RESERVATION,
        "budget_invalid",
    )
    observed, expires = utc(policy["price_observed_at"]), utc(policy["expires_at"])
    require(
        observed <= now < expires <= observed + timedelta(hours=24), "policy_expired"
    )


def payload_bytes():
    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "system",
                "content": "This is an authorized synthetic connectivity test. Return only the requested JSON. No tools.",
            },
            {
                "role": "user",
                "content": "Synthetic fixture: calculate 2 + 3. Return status ok and sum 5.",
            },
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "synthetic_health",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "enum": ["ok"]},
                        "sum": {"type": "integer", "enum": [5]},
                    },
                    "required": ["status", "sum"],
                    "additionalProperties": False,
                },
            },
        },
        "max_completion_tokens": 256,
        "reasoning_effort": "low",
        "n": 1,
        "stream": False,
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode()
    require(len(raw) <= 1024, "input_too_large")
    return raw


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise KeyTestError("model_key_test_redirect_rejected")


def live_transport(raw, secret):
    raise KeyTestError("legacy_direct_model_transport_disabled_use_campaign_gateway")


def response_receipt(status, raw, allowed_models):
    http_reasons = {
        401: "authentication_failed",
        403: "access_denied",
        404: "model_unavailable",
        429: "quota_or_rate_limit",
        400: "protocol_rejected",
    }
    require(status == 200, http_reasons.get(status, "provider_unavailable"))
    require(len(raw) <= 65536, "response_too_large")
    value = strict_json(raw)
    require(isinstance(value, dict), "response_invalid")
    require(value.get("model") in allowed_models, "returned_model_mismatch")
    usage = value.get("usage")
    require(isinstance(usage, dict), "usage_missing")
    metrics = {
        k: usage.get(k) for k in ("prompt_tokens", "completion_tokens", "total_tokens")
    }
    require(all(type(v) is int and v >= 0 for v in metrics.values()), "usage_missing")
    require(
        metrics["prompt_tokens"] <= 2048
        and metrics["completion_tokens"] <= 256
        and metrics["total_tokens"]
        == metrics["prompt_tokens"] + metrics["completion_tokens"],
        "usage_exceeds_reservation",
    )
    choices = value.get("choices")
    require(
        isinstance(choices, list)
        and len(choices) == 1
        and isinstance(choices[0], dict),
        "output_invalid",
    )
    choice = choices[0]
    message = choice.get("message")
    require(
        isinstance(message, dict)
        and not message.get("tool_calls")
        and not message.get("function_call")
        and choice.get("finish_reason") == "stop",
        "output_invalid",
    )
    content = message.get("content")
    require(isinstance(content, str) and len(content) <= 4096, "output_invalid")
    answer = strict_json(content)
    require(
        answer == {"status": "ok", "sum": 5} and type(answer.get("sum")) is int,
        "output_invalid",
    )
    return {
        "returned_model_id": value["model"],
        "usage": metrics,
        "response_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "http_status": 200,
    }


class ModelKeyTestStore:
    def __init__(self, provider: OwnerOnlyFileSecretProvider, *, now=None):
        self.provider = provider
        self.path = provider.bindings_path.with_suffix(".api-tests.json")
        self.now = now or (lambda: datetime.now(timezone.utc))

    @contextmanager
    def _locked(self):
        info = self.path.parent.lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            "directory_invalid",
        )
        fd = os.open(
            self.path.with_suffix(".lock"),
            os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            info = os.fstat(fd)
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.getuid()
                and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600,
                "lock_invalid",
            )
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _read(self):
        if not self.path.exists() and not self.path.is_symlink():
            return {
                "schema_version": "orbit.model-key-test-store/1",
                "budgets": {},
                "attempts": {},
            }
        state = owner_document(self.path)
        require(
            set(state) == {"schema_version", "budgets", "attempts"}
            and state["schema_version"] == "orbit.model-key-test-store/1"
            and isinstance(state["budgets"], dict)
            and isinstance(state["attempts"], dict),
            "store_invalid",
        )
        return state

    def _write(self, state):
        fd, temporary = tempfile.mkstemp(prefix=".api-test-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w") as out:
                json.dump(state, out, sort_keys=True, allow_nan=False)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, self.path)
            fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def test_and_bind(
        self,
        *,
        logical_ref,
        version,
        secret,
        entry_revision_digest,
        policy,
        transport=live_transport,
    ):
        validate_policy(policy, self.now())
        require(
            re.fullmatch(
                r"secret://company/model-catalog/[a-z0-9_]{1,140}/current", logical_ref
            )
            and TOKEN.fullmatch(version)
            and DIGEST.fullmatch(entry_revision_digest),
            "binding_invalid",
        )
        require(
            isinstance(secret, bytes)
            and 12 <= len(secret) <= 4096
            and all(33 <= b <= 126 for b in secret),
            "key_format_invalid",
        )
        scope = {
            "logical_ref": logical_ref,
            "binding_version": version,
            "secret_fingerprint": "sha256:" + hashlib.sha256(secret).hexdigest(),
            "entry_revision_digest": entry_revision_digest,
            "endpoint": policy["endpoint"],
            "model": policy["model"],
        }
        attempt_id = digest(scope)
        with self._locked():
            state = self._read()
            budget = state["budgets"].get(policy["budget_id"])
            require(budget is None or budget == policy, "budget_policy_drift")
            attempt = state["attempts"].get(attempt_id)
            replay = attempt is not None
            if attempt is None:
                spent = sum(
                    a["reserved_cost_microusd"]
                    for a in state["attempts"].values()
                    if a["budget_id"] == policy["budget_id"]
                )
                require(
                    spent + policy["reservation_microusd"]
                    <= policy["max_cost_microusd"],
                    "budget_exceeded",
                )
                raw = payload_bytes()
                attempt = {
                    **scope,
                    "attempt_id": attempt_id,
                    "budget_id": policy["budget_id"],
                    "reserved_cost_microusd": policy["reservation_microusd"],
                    "status": "reserved_outcome_unknown",
                    "started_at": self.now().isoformat(),
                    "expires_at": policy["expires_at"],
                    "request_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                    "input_classification": "synthetic",
                    "model_request_may_have_been_sent": True,
                    "credential_saved": False,
                }
                state["budgets"][policy["budget_id"]] = policy
                state["attempts"][attempt_id] = attempt
                self._write(
                    state
                )  # Persist worst-case charge before the only network call.
                try:
                    attempt.update(
                        response_receipt(
                            *transport(raw, secret), policy["allowed_returned_models"]
                        )
                    )
                    attempt["status"] = "verified_not_saved"
                except (OSError, ValueError, TypeError, KeyError) as error:
                    code = (
                        str(error)
                        if isinstance(error, KeyTestError)
                        else (
                            "model_key_test_timeout"
                            if isinstance(error, TimeoutError)
                            else "model_key_test_outcome_unknown"
                        )
                    )
                    attempt.update(status="test_failed", reason_code=code)
                attempt["finished_at"] = self.now().isoformat()
                self._write(
                    state
                )  # A validated response is durable before credential persistence.
            require(
                attempt["expires_at"] == policy["expires_at"]
                and attempt["budget_id"] == policy["budget_id"],
                "attempt_policy_drift",
            )
            if attempt["status"] == "verified_not_saved":
                try:
                    require(self.now() < utc(attempt["expires_at"]), "policy_expired")
                    # Recover a completed write after a process crash without changing the key.
                    try:
                        current = self.provider.health(logical_ref)
                    except ValueError:
                        current = {}
                    if (
                        current.get("binding_version") != version
                        or current.get("secret_fingerprint")
                        != scope["secret_fingerprint"]
                    ):
                        self.provider.bind(logical_ref, secret, version=version)
                    attempt.update(status="verified_and_saved", credential_saved=True)
                    attempt.pop("reason_code", None)
                except (OSError, ValueError):
                    attempt["reason_code"] = "model_key_test_save_failed"
                self._write(state)
            return {
                **attempt,
                "idempotent_replay": replay,
                "new_model_request_sent": not replay,
                "secret_value_returned": False,
                "runtime_started": False,
            }

    def qualified_health(
        self,
        *,
        logical_ref,
        version,
        fingerprint,
        entry_revision_digest,
        endpoint,
        model,
    ):
        scope = {
            "logical_ref": logical_ref,
            "binding_version": version,
            "secret_fingerprint": fingerprint,
            "entry_revision_digest": entry_revision_digest,
            "endpoint": endpoint,
            "model": model,
        }
        attempt = self._read()["attempts"].get(digest(scope))
        require(
            attempt is not None
            and all(attempt.get(k) == v for k, v in scope.items())
            and attempt.get("status") == "verified_and_saved"
            and attempt.get("credential_saved") is True
            and utc(attempt["expires_at"]) > self.now(),
            "required",
        )
        return {**attempt, "receipt_digest": digest(attempt)}

    def latest_status(self, entry_revision_digest):
        matches = [
            a
            for a in self._read()["attempts"].values()
            if a["entry_revision_digest"] == entry_revision_digest
        ]
        if not matches:
            return {"status": "required"}
        attempt = max(matches, key=lambda a: a["started_at"])
        return {
            "status": attempt["status"]
            if utc(attempt["expires_at"]) > self.now()
            else "expired",
            "reason_code": attempt.get("reason_code"),
            "observed_at": attempt.get("finished_at", attempt["started_at"]),
        }

