"""Deterministic D0 task controls with no persistence or external effects."""

from __future__ import annotations

from dataclasses import replace

from .ids import deterministic_id
from .models import AuditEvent, ControlTransition, TaskControlSnapshot, TaskEnvelope


CONTROL_ACTIONS = frozenset({"pause", "revoke", "cancel", "takeover"})
TERMINAL_TASK_STATES = frozenset({"cancelled", "human_taken_over"})


def execution_block_reasons(snapshot: TaskControlSnapshot) -> tuple[str, ...]:
    """Return stable fail-closed reasons in deterministic priority order."""

    reasons: list[str] = []
    if snapshot.task_status == "paused":
        reasons.append("task_paused")
    elif snapshot.task_status == "cancelled":
        reasons.append("task_cancelled")
    elif snapshot.task_status == "human_taken_over":
        reasons.append("human_takeover_active")
    elif snapshot.task_status != "active":
        reasons.append("task_control_state_unknown")

    if snapshot.grant_status == "revoked":
        reasons.append("grant_revoked")
    elif snapshot.grant_status != "active":
        reasons.append("grant_control_state_unknown")

    if snapshot.owner_kind == "human_operator" and "human_takeover_active" not in reasons:
        reasons.append("human_takeover_active")
    elif snapshot.owner_kind not in {"control_plane", "human_operator"}:
        reasons.append("task_owner_unknown")
    return tuple(reasons)


class TaskController:
    """Pure state transition service; actor references are audit labels, not auth."""

    @staticmethod
    def initial(task: TaskEnvelope) -> TaskControlSnapshot:
        return TaskControlSnapshot(
            task_id=task.task_id,
            grant_id=task.grant_id,
            task_status="active",
            grant_status="active" if task.grant_active else "revoked",
            owner_kind="control_plane",
            revision=0,
        )

    def apply(
        self,
        snapshot: TaskControlSnapshot,
        action: str,
        *,
        actor_id: str,
    ) -> ControlTransition:
        if action not in CONTROL_ACTIONS:
            raise ValueError("unsupported_control_action")
        if not actor_id:
            raise ValueError("control_actor_required")

        applied, reason_code, changes = self._decide(snapshot, action)
        next_revision = snapshot.revision + 1 if applied else snapshot.revision
        event_id = deterministic_id(
            "control",
            snapshot.task_id,
            snapshot.grant_id,
            str(snapshot.revision),
            action,
            actor_id,
            reason_code,
        )
        event = AuditEvent(
            event_id=event_id,
            task_id=snapshot.task_id,
            event_type=f"task_control_{action}_{'applied' if applied else 'rejected'}",
            subject_ref=actor_id,
        )
        after = snapshot
        if applied:
            after = replace(
                snapshot,
                revision=next_revision,
                last_control_event_ref=event_id,
                **changes,
            )
        return ControlTransition(
            action=action,
            applied=applied,
            reason_code=reason_code,
            before=snapshot,
            after=after,
            audit_event=event,
        )

    @staticmethod
    def _decide(
        snapshot: TaskControlSnapshot,
        action: str,
    ) -> tuple[bool, str, dict[str, str]]:
        if snapshot.task_status in TERMINAL_TASK_STATES:
            if action == "cancel" and snapshot.task_status == "cancelled":
                return False, "already_cancelled", {}
            if action == "takeover" and snapshot.task_status == "human_taken_over":
                return False, "already_taken_over", {}
            return False, "terminal_task_state", {}

        if action == "pause":
            if snapshot.task_status == "paused":
                return False, "already_paused", {}
            if snapshot.task_status != "active":
                return False, "task_not_active", {}
            return True, "task_paused", {"task_status": "paused"}

        if action == "revoke":
            if snapshot.grant_status == "revoked":
                return False, "already_revoked", {}
            return True, "grant_revoked", {"grant_status": "revoked"}

        if action == "cancel":
            return True, "task_cancelled", {
                "task_status": "cancelled",
                "grant_status": "revoked",
            }

        return True, "human_takeover_active", {
            "task_status": "human_taken_over",
            "grant_status": "revoked",
            "owner_kind": "human_operator",
        }

