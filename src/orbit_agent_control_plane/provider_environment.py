"""Strict loader for an explicitly selected local provider environment file.

The file is parsed as data. Shell syntax, interpolation and automatic process
environment mutation are intentionally unsupported.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from .lifecycle_assurance import LifecycleAssuranceError


_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_SECRET_REFERENCE = re.compile(r"^env:([A-Z][A-Z0-9_]{2,63})$")
_MAX_ENV_FILE_BYTES = 32 * 1024
_PROVIDER_CONFIGURATION_KEYS = frozenset(
    {
        "ORBIT_MODEL_PROVIDER_ID",
        "ORBIT_MODEL_BASE_URL",
        "ORBIT_MODEL_ID",
        "ORBIT_MODEL_ALLOWED_RETURNED_IDS",
        "ORBIT_MODEL_SECRET_REF",
        "ORBIT_MODEL_CNY_PER_USD",
    }
)


def load_provider_environment_file(path: Path) -> dict[str, str]:
    """Load one owner-only regular file without executing its contents."""

    candidate = Path(path)
    try:
        initial = candidate.lstat()
    except OSError as error:
        raise LifecycleAssuranceError(
            "provider_environment_file_unavailable",
            "provider environment file is unavailable",
        ) from error
    _validate_file_metadata(initial)

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise LifecycleAssuranceError(
            "provider_environment_file_unavailable",
            "provider environment file could not be opened safely",
        ) from error
    try:
        opened = os.fstat(descriptor)
        _validate_file_metadata(opened)
        if (initial.st_dev, initial.st_ino) != (opened.st_dev, opened.st_ino):
            raise LifecycleAssuranceError(
                "provider_environment_file_changed",
                "provider environment file changed while opening",
            )
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(_MAX_ENV_FILE_BYTES + 1)
    finally:
        os.close(descriptor)

    if len(raw) > _MAX_ENV_FILE_BYTES:
        raise LifecycleAssuranceError(
            "provider_environment_file_too_large",
            "provider environment file exceeds the size limit",
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise LifecycleAssuranceError(
            "provider_environment_file_invalid",
            "provider environment file is not valid UTF-8",
        ) from error

    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line != line.strip() or "=" not in line:
            raise LifecycleAssuranceError(
                "provider_environment_file_invalid",
                "provider environment file contains unsupported syntax",
            )
        name, value = line.split("=", 1)
        if (
            not _ENV_NAME.fullmatch(name)
            or not value
            or value != value.strip()
            or value[0] in {"'", '"'}
            or value[-1] in {"'", '"'}
            or "$" in value
            or "`" in value
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise LifecycleAssuranceError(
                "provider_environment_file_invalid",
                "provider environment file contains an invalid entry",
            )
        if name in values:
            raise LifecycleAssuranceError(
                "provider_environment_file_duplicate_key",
                "provider environment file contains a duplicate key",
            )
        values[name] = value

    if not _PROVIDER_CONFIGURATION_KEYS.issubset(values):
        raise LifecycleAssuranceError(
            "provider_environment_configuration_missing",
            "provider environment file is missing required configuration",
        )
    secret_match = _SECRET_REFERENCE.fullmatch(values["ORBIT_MODEL_SECRET_REF"])
    if secret_match is None or secret_match.group(1) not in values:
        raise LifecycleAssuranceError(
            "provider_environment_secret_missing",
            "provider environment file does not contain its referenced secret",
        )
    allowed_keys = _PROVIDER_CONFIGURATION_KEYS | {secret_match.group(1)}
    if set(values) != allowed_keys:
        raise LifecycleAssuranceError(
            "provider_environment_unknown_key",
            "provider environment file contains an unapproved key",
        )
    return values


def _validate_file_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise LifecycleAssuranceError(
            "provider_environment_file_insecure",
            "provider environment file must be an owner-only regular file",
        )
    if metadata.st_size > _MAX_ENV_FILE_BYTES:
        raise LifecycleAssuranceError(
            "provider_environment_file_too_large",
            "provider environment file exceeds the size limit",
        )

