"""Service-mode adapters for the Orbit Agent Control Plane.

The package is deliberately separate from the local JSONL D0 adapters.  It
implements a PostgreSQL-backed modular-monolith candidate without promoting
local synthetic evidence into authoritative service state.
"""

from .api import create_app
from .config import ServiceSettings
from .database import Database
from .local_operator import LocalTrustedOperatorGuard
from .pipeline import GovernedReleasePipeline, PilotBudget
from .repositories import (
    SqlAlchemyPolicyActivationRepository,
    SqlAlchemyQualificationStore,
    SqlAuditExporter,
    SqlGrantRevocationRegistry,
    SqlOutboxPublisher,
    SqlWorkerLeaseCoordinator,
)
from .runtime_stage import SignedRuntimeStageHandler

__all__ = [
    "Database",
    "GovernedReleasePipeline",
    "LocalTrustedOperatorGuard",
    "PilotBudget",
    "ServiceSettings",
    "SignedRuntimeStageHandler",
    "SqlAlchemyPolicyActivationRepository",
    "SqlAlchemyQualificationStore",
    "SqlAuditExporter",
    "SqlGrantRevocationRegistry",
    "SqlOutboxPublisher",
    "SqlWorkerLeaseCoordinator",
    "create_app",
]

