"""Shared owner-only JSONL storage for Agent and Tool lifecycle ledgers."""

from __future__ import annotations

import fcntl
import json
import os
import stat
from pathlib import Path
from typing import Any, Callable


ErrorFactory = Callable[[str, str], Exception]


def open_owner_only_ledger(
    path: Path,
    *,
    create: bool,
    exclusive: bool,
    error: ErrorFactory,
    label: str,
) -> int:
    if os.path.lexists(path):
        if stat.S_ISLNK(os.lstat(path).st_mode):
            raise error("ledger_symlink_forbidden", f"{label} may not be a symlink")
    elif not create:
        raise error("ledger_not_found", f"{label} does not exist")
    if not path.parent.is_dir():
        raise error("ledger_parent_missing", f"{label} parent is missing")
    flags = os.O_RDONLY if not create else os.O_RDWR | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except FileNotFoundError as cause:
        raise error("ledger_not_found", f"{label} does not exist") from cause
    except OSError as cause:
        raise error("ledger_open_failed", f"{label} cannot be opened") from cause
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise error("ledger_not_regular_file", f"{label} must be a regular file")
        if metadata.st_uid != os.geteuid():
            raise error("ledger_owner_mismatch", f"{label} owner differs")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise error(
                "ledger_permissions_too_broad", f"{label} must be owner-only"
            )
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        return fd
    except Exception:
        os.close(fd)
        raise


def close_ledger(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def read_jsonl_documents(
    fd: int,
    *,
    max_ledger_bytes: int,
    max_record_bytes: int,
    object_pairs_hook: Callable[[list[tuple[str, Any]]], dict[str, Any]],
    parse_constant: Callable[[str], Any],
    error: ErrorFactory,
    label: str,
) -> tuple[dict[str, Any], ...]:
    size = os.fstat(fd).st_size
    if size > max_ledger_bytes:
        raise error("ledger_too_large", f"{label} exceeds its size limit")
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(fd, min(remaining, 64 * 1024))
        if not chunk:
            raise error("ledger_read_incomplete", f"{label} read stopped")
        chunks.append(chunk)
        remaining -= len(chunk)
    source = b"".join(chunks)
    if not source:
        return ()
    if not source.endswith(b"\n"):
        raise error("truncated_record", f"{label} record is truncated")
    documents = []
    for line in source.splitlines():
        if not line:
            raise error("blank_record", f"{label} contains a blank record")
        if len(line) + 1 > max_record_bytes:
            raise error("record_too_large", f"{label} record exceeds its size limit")
        try:
            document = json.loads(
                line.decode("utf-8"),
                object_pairs_hook=object_pairs_hook,
                parse_constant=parse_constant,
            )
        except Exception as cause:
            if hasattr(cause, "reason_code"):
                raise
            raise error("invalid_json", f"{label} record is invalid JSON") from cause
        if not isinstance(document, dict):
            raise error("invalid_json", f"{label} record must be an object")
        documents.append(document)
    return tuple(documents)


def append_jsonl_document(
    fd: int,
    encoded: bytes,
    *,
    max_ledger_bytes: int,
    max_record_bytes: int,
    error: ErrorFactory,
    label: str,
) -> None:
    if len(encoded) > max_record_bytes:
        raise error("record_too_large", f"{label} record exceeds its size limit")
    if os.fstat(fd).st_size + len(encoded) > max_ledger_bytes:
        raise error("ledger_too_large", f"{label} exceeds its size limit")
    if os.write(fd, encoded) != len(encoded):
        raise error("ledger_short_write", f"{label} append was incomplete")
    os.fsync(fd)

