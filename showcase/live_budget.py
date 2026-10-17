"""One explicit, durable campaign budget. Importing this module never loads keys.

Prices are immutable per campaign: historical 2/8 and new workbench 3/12
micro-CNY/token. Unknown requests retain their reservation. No network retries.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import signal
import ssl
import stat
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

MODEL = "deepseek-flash"
ENDPOINT = "https://api.deepseek.com/chat/completions"
MAX_INPUT = 8000
MAX_OUTPUT = 2048
RESERVATION = MAX_INPUT * 2 + MAX_OUTPUT * 8


class LiveError(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise LiveError(reason)


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate_json_key")
            value[key] = item
        return value

    try:
        return json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda _: require(False, "nonfinite_json"),
        )
    except (ValueError, TypeError):
        raise LiveError("invalid_json") from None


def encoded(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(encoded(value)).hexdigest()


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and info.st_nlink == 1
            and info.st_mode & 0o077 == 0,
            "private_file_permissions_invalid",
        )
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read(2_000_001)
    finally:
        os.close(fd)


def atomic_private(path, value):
    require(not path.is_symlink(), "private_file_symlink")
    temporary = path.with_name(path.name + ".pending")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def load_secret():
    """Read just one authorized key; never expose the ambient environment."""
    configured = os.environ.get("ORBIT_MODEL_CREDENTIAL_FILE")
    path = Path(configured) if configured else Path.home() / ".hermes/.env"
    require(path.is_absolute(), "credential_file_absolute_path_required")
    raw = private_read(path).decode()
    values = []
    for line in raw.splitlines():
        key, separator, value = line.strip().partition("=")
        if separator and key == "DEEPSEEK_API_KEY":
            values.append(value.strip().strip("\"'"))
    require(
        len(values) == 1
        and len(values[0]) >= 8
        and not any(c.isspace() for c in values[0]),
        "credential_unavailable",
    )
    return values[0]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise LiveError("redirect_rejected")


def provider_proxy():
    """Explicit direct mode or local proxy only; never inherit ambient proxy auth."""
    value = os.environ.get("ORBIT_MODEL_PROXY", "http://127.0.0.1:7897")
    if value == "direct":
        return {}
    parsed = urlsplit(value)
    require(
        parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "localhost"}
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
        and parsed.path in {"", "/"},
        "explicit_local_proxy_or_direct_required",
    )
    return {"https": value}


def _live_post(body):
    secret = load_secret()
    request = urllib.request.Request(
        ENDPOINT,
        data=body,
        method="POST",
        headers={
            "Authorization": "Bearer " + secret,
            "Content-Type": "application/json",
        },
    )
    opener = urllib.request.build_opener(
        # Explicit existing local proxy; never inherit arbitrary proxy URLs/auth.
        urllib.request.ProxyHandler(provider_proxy()),
        NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        with opener.open(request, timeout=55) as response:
            require(response.geturl() == ENDPOINT, "origin_drift")
            raw = response.read(131073)
            require(len(raw) <= 131072, "response_too_large")
            # Defensive redaction even if a provider unexpectedly echoes a header.
            raw = raw.replace(secret.encode(), b"[REDACTED]")
            return response.status, raw
    except urllib.error.HTTPError as error:
        return error.code, b""  # Provider error bodies and headers are not logged.
    except (urllib.error.URLError, TimeoutError, OSError):
        raise LiveError("transport_failed_or_unknown") from None
    finally:
        secret = None


def live_post(body):
    if threading.current_thread() is not threading.main_thread():
        # The explicit workbench broker runs in a thread; socket timeout remains
        # bounded in _live_post. Never install process signals in that thread.
        return _live_post(body)

    def deadline(_signum, _frame):
        raise LiveError("request_wall_deadline_exceeded")

    previous = signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, 90)
    try:
        return _live_post(body)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class Campaign:
    def __init__(self, root: Path, *, transport=None):
        self.root = Path(root)
        self.transport = transport  # Tests inject an offline transport.

    @classmethod
    def authorize(
        cls,
        root,
        *,
        authorization_ref,
        max_requests=24,
        max_cost_micros=2_000_000,
        transport=None,
        input_price=2,
        output_price=8,
    ):
        require(
            0 < max_requests <= 24 and 0 < max_cost_micros <= 2_000_000,
            "authorization_cap_invalid",
        )
        require(
            (input_price, output_price) in {(2, 8), (3, 12)}, "price_contract_invalid"
        )
        root = Path(root)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(
            not root.is_symlink() and root.stat().st_mode & 0o077 == 0,
            "campaign_directory_not_private",
        )
        campaign = cls(root, transport=transport)
        with campaign.lock():
            require(not campaign.path.exists(), "campaign_already_exists")
            atomic_private(
                campaign.path,
                {
                    "schema": "orbit.live-budget/1",
                    "authorization_ref": authorization_ref,
                    "max_requests": max_requests,
                    "max_cost_micros": max_cost_micros,
                    "closed": False,
                    "input_price": input_price,
                    "output_price": output_price,
                    "model": MODEL,
                    "attempts": [],
                    "events": [],
                },
            )
        return campaign

    @property
    def path(self):
        return self.root / "budget.json"

    @contextmanager
    def lock(self):
        require(
            not self.root.is_symlink() and self.root.stat().st_mode & 0o077 == 0,
            "campaign_directory_not_private",
        )
        fd = os.open(
            self.root / "budget.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def state(self):
        value = strict_json(private_read(self.path))
        require(
            value.get("schema") == "orbit.live-budget/1"
            and value.get("model") == MODEL
            and 0 < value.get("max_requests", 0) <= 24
            and 0 < value.get("max_cost_micros", 0) <= 2_000_000,
            "campaign_contract_invalid",
        )
        previous = "genesis"
        for index, event in enumerate(value["events"]):
            unsigned = {k: v for k, v in event.items() if k != "digest"}
            require(
                event.get("sequence") == index
                and event.get("previous") == previous
                and event.get("digest") == digest(unsigned),
                "campaign_event_chain_invalid",
            )
            previous = event["digest"]
        return value

    @staticmethod
    def charge(state):
        return sum(
            a.get("actual_cost_micros", a.get("reserved_micros", RESERVATION))
            for a in state["attempts"]
        )

    def event(self, kind, payload):
        with self.lock():
            state = self.state()
            previous = state["events"][-1]["digest"] if state["events"] else "genesis"
            event = {
                "kind": kind,
                "payload": payload,
                "previous": previous,
                "sequence": len(state["events"]),
            }
            event["digest"] = digest(event)
            state["events"].append(event)
            atomic_private(self.path, state)
            return event

    def close(self, reason):
        with self.lock():
            state = self.state()
            if state["closed"]:
                return  # Preserve a stronger close reason such as unknown usage.
            state.update(closed=True, close_reason=reason)
            atomic_private(self.path, state)

    def resume_remaining_authorization(self):
        """Explicit repair action, preserving EVERY attempt and its reservation.

        Never reopen completion, unknown usage, or an exhausted authorization.
        This is a CLI operator action, not a provider/SDK retry loop.
        """
        with self.lock():
            state = self.state()
            repairs = sum(
                e["kind"] == "authorized_repair_resume" for e in state["events"]
            )
            require(
                state["closed"]
                and state.get("close_reason")
                not in {
                    "completed_small_scale_validation",
                    "completed_sharing_validation",
                    "unverified_provider_usage",
                    "request_budget_exhausted",
                    "cost_budget_exhausted",
                },
                "campaign_not_resumable",
            )
            require(
                not any(a["status"] == "pending" for a in state["attempts"]),
                "unresolved_pending_request",
            )
            require(
                repairs < 6
                and len(state["attempts"]) < state["max_requests"]
                and self.charge(state)
                + MAX_INPUT * state.get("input_price", 2)
                + MAX_OUTPUT * state.get("output_price", 8)
                <= state["max_cost_micros"],
                "remaining_authorization_exhausted",
            )
            state.update(closed=False, close_reason=None)
            atomic_private(self.path, state)
        self.event(
            "authorized_repair_resume",
            {
                "repair": repairs + 1,
                "same_request_and_cost_caps": True,
                "prior_failures_preserved": True,
            },
        )

    def chat(
        self, *, key, phase, messages, tools=None, tool_choice=None, json_mode=False
    ):
        payload = {
            "model": MODEL,
            "messages": messages,
            "max_tokens": MAX_OUTPUT,
            "thinking": {"type": "disabled"},
            "stream": False,
            "temperature": 0,
        }
        if tools:
            payload.update(tools=tools, tool_choice=tool_choice or "auto")
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        raw = encoded(payload)
        require(len(raw) + 512 <= MAX_INPUT, "input_reservation_exceeded")
        request_digest = digest(payload)
        with self.lock():
            state = self.state()
            require(not state["closed"], "campaign_closed")
            input_price = state.get("input_price", 2)
            output_price = state.get("output_price", 8)
            reservation = MAX_INPUT * input_price + MAX_OUTPUT * output_price
            previous = next((a for a in state["attempts"] if a["key"] == key), None)
            if previous:
                require(
                    previous["request_digest"] == request_digest, "idempotency_conflict"
                )
                require(
                    previous["status"] == "succeeded", "previous_attempt_not_retryable"
                )
                return strict_json(private_read(self.root / previous["response_file"]))
            require(
                not any(a["status"] == "pending" for a in state["attempts"]),
                "unresolved_pending_request",
            )
            require(
                len(state["attempts"]) < state["max_requests"],
                "request_budget_exhausted",
            )
            require(
                self.charge(state) + reservation <= state["max_cost_micros"],
                "cost_budget_exhausted",
            )
            number = len(state["attempts"]) + 1
            attempt = {
                "number": number,
                "key": key,
                "phase": phase,
                "status": "pending",
                "request_digest": request_digest,
                "reserved_micros": reservation,
                "started_at": time.time(),
            }
            state["attempts"].append(attempt)
            atomic_private(
                self.path, state
            )  # Persist reservation BEFORE any key/network.
            try:
                status, response_raw = (self.transport or live_post)(raw)
                attempt["http_status"] = status
                require(status == 200, "provider_http_rejected")
                value = strict_json(response_raw)
                # Preserve contract failures too, without provider error bodies.
                response_file = f"response-{number:02d}.json"
                atomic_private(self.root / response_file, value)
                attempt["response_file"] = response_file
                require(
                    value.get("model") in {MODEL, "deepseek-v4-flash"},
                    "returned_model_not_allowed",
                )
                usage = value.get("usage", {})
                incoming, outgoing = (
                    usage.get("prompt_tokens"),
                    usage.get("completion_tokens"),
                )
                require(
                    type(incoming) is int
                    and 0 <= incoming <= MAX_INPUT
                    and type(outgoing) is int
                    and 0 <= outgoing <= MAX_OUTPUT,
                    "usage_missing_or_out_of_bounds",
                )
                attempt.update(
                    input_tokens=incoming,
                    output_tokens=outgoing,
                    actual_cost_micros=incoming * input_price + outgoing * output_price,
                    returned_model=value["model"],
                )
                require(
                    isinstance(value.get("choices"), list)
                    and len(value["choices"]) == 1,
                    "choice_contract_invalid",
                )
                choice = value["choices"][0]
                require(
                    choice.get("finish_reason") in {"stop", "tool_calls"}
                    and isinstance(choice.get("message"), dict),
                    "completion_incomplete",
                )
                attempt["status"] = "succeeded"
                return value
            except Exception as error:  # noqa: BLE001 - fail closed; never log provider exceptions
                attempt["status"] = "failed"
                attempt["reason"] = (
                    str(error)
                    if isinstance(error, LiveError)
                    else "transport_or_contract_failed"
                )
                # An unverified usage/identity must not permit another paid request.
                if (
                    attempt.get("http_status") == 200
                    and "actual_cost_micros" not in attempt
                ):
                    state.update(closed=True, close_reason="unverified_provider_usage")
                raise LiveError(attempt["reason"]) from None
            finally:
                attempt["finished_at"] = time.time()
                atomic_private(self.path, state)
