"""Catalog-only transaction boundary; no changes to other service sessions."""

from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from datetime import datetime
from functools import wraps
from inspect import signature

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, OperationalError

from ..qualification.automation import canonical_digest
from .model_catalog_models import ModelCatalogCommandRow


def _normalized(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _normalized(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalized(item) for item in value]
    return value


def catalog_write(method):
    """Replay accepted commands before current eligibility, after caller auth.

    Role/department/step-up checks remain at the API boundary on every request.
    Retry only database conflicts, with the whole transaction rolled back first.
    """

    @wraps(method)
    def write(self, **values):
        from .model_catalog import ModelCatalogError

        self._validate_idempotency(values["idempotency_key"])
        bound = signature(method).bind(self, **values)
        bound.apply_defaults()
        request = {
            key: value for key, value in bound.arguments.items() if key != "self"
        }
        digest = canonical_digest(
            {"operation": method.__name__, "request": _normalized(request)}
        )
        if self._active_session.get() is not None:
            return method(self, **values)
        for attempt in range(3):
            try:
                with self.database.session() as session:
                    token = self._active_session.set(session)
                    try:
                        command = session.scalar(
                            select(ModelCatalogCommandRow).where(
                                ModelCatalogCommandRow.idempotency_key
                                == values["idempotency_key"]
                            )
                        )
                        if command is not None:
                            if (
                                command.request_digest != digest
                                or command.actor_ref != values["actor_ref"]
                            ):
                                raise ModelCatalogError(
                                    "model_catalog_command_idempotency_conflict"
                                )
                            return {
                                **deepcopy(command.response),
                                "idempotent_replay": True,
                                "historical_receipt_only": True,
                            }
                        response = method(self, **values)
                        session.add(
                            ModelCatalogCommandRow(
                                idempotency_key=values["idempotency_key"],
                                operation=method.__name__,
                                actor_ref=values["actor_ref"],
                                request_digest=digest,
                                response=deepcopy(response),
                                recorded_at=self.now(),
                            )
                        )
                        session.flush()
                    finally:
                        self._active_session.reset(token)
                return response
            except (IntegrityError, OperationalError) as error:
                code = getattr(error.orig, "sqlstate", None)
                if not isinstance(error, IntegrityError) and code not in {
                    "40001",
                    "40P01",
                }:
                    raise
                if attempt == 2:
                    raise ModelCatalogError(
                        "model_catalog_concurrent_write_conflict"
                    ) from error
        raise AssertionError("unreachable")

    return write


class CatalogTransactionScope:
    def _init_transaction_scope(self):
        self._active_session = ContextVar("catalog_session", default=None)

    @contextmanager
    def _session(self):
        session = self._active_session.get()
        if session is not None:
            yield session
        else:
            with self.database.session() as session:
                yield session

