"""Materialize an isolated, content-addressed Dataset Agent runtime source.

Development repositories are discovery inputs only. Runtime execution uses an
independent local clone at the exact implementation lock revision, with a
detached HEAD and no configured remotes. The process adapter still verifies the
revision and clean worktree immediately before every invocation.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .dataset_agent_process import (
    DatasetAgentImplementationLock,
    DatasetAgentProcessError,
    load_dataset_agent_implementation_lock,
    verify_dataset_agent_implementation,
)


@dataclass(frozen=True)
class DatasetRuntimeSourceEvidence:
    repository_id: str
    implementation_revision: str
    runtime_source_name: str
    created: bool
    detached_head: bool
    remote_count: int
    clean: bool


class DatasetRuntimeSourceError(ValueError):
    """Fail-closed runtime-source error without local path disclosure."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class LockedRuntimeSourceSpec:
    repository_id: str
    implementation_commit: str
    required_paths: tuple[str, ...]


def materialize_locked_runtime_source(
    source_repository: Path | str,
    runtime_root: Path | str,
    spec: LockedRuntimeSourceSpec,
) -> DatasetRuntimeSourceEvidence:
    """Create an isolated runtime source for a framework-neutral repository lock."""

    source = _verify_locked_source_repository(source_repository, spec)
    root = _prepare_runtime_root(runtime_root, source)
    expected_name = _locked_runtime_source_name(spec)
    target = root / expected_name
    if target.exists() or target.is_symlink():
        return verify_locked_runtime_source(target, spec, created=False)

    git = _git_binary()
    try:
        with tempfile.TemporaryDirectory(prefix=".locked-runtime-source-", dir=root) as temporary:
            staging = Path(temporary) / expected_name
            _run_git(
                (
                    git,
                    "clone",
                    "--no-local",
                    "--no-checkout",
                    "--no-tags",
                    "--quiet",
                    str(source),
                    str(staging),
                ),
                timeout_seconds=30,
                reason_code="locked_runtime_source_clone_failed",
            )
            _run_git(
                (
                    git,
                    "-C",
                    str(staging),
                    "checkout",
                    "--detach",
                    "--quiet",
                    spec.implementation_commit,
                ),
                timeout_seconds=10,
                reason_code="locked_runtime_source_checkout_failed",
            )
            _run_git(
                (git, "-C", str(staging), "remote", "remove", "origin"),
                timeout_seconds=5,
                reason_code="locked_runtime_source_seal_failed",
            )
            verify_locked_runtime_source(staging, spec, created=True)
            try:
                staging.rename(target)
            except OSError as error:
                raise DatasetRuntimeSourceError(
                    "locked_runtime_source_publish_failed",
                    "locked runtime source could not be published",
                ) from error
    except DatasetRuntimeSourceError:
        raise
    except OSError as error:
        raise DatasetRuntimeSourceError(
            "locked_runtime_source_materialization_failed",
            "locked runtime source could not be materialized",
        ) from error
    return verify_locked_runtime_source(target, spec, created=True)


def verify_locked_runtime_source(
    runtime_source: Path | str,
    spec: LockedRuntimeSourceSpec,
    *,
    created: bool = False,
) -> DatasetRuntimeSourceEvidence:
    """Verify exact Revision, clean detached Git state, shape, and no Remote."""

    supplied = Path(runtime_source)
    if supplied.is_symlink():
        raise DatasetRuntimeSourceError(
            "locked_runtime_source_symlink_forbidden",
            "locked runtime source may not be a symbolic link",
        )
    try:
        root = supplied.resolve(strict=True)
    except OSError as error:
        raise DatasetRuntimeSourceError(
            "locked_runtime_source_unavailable",
            "locked runtime source is unavailable",
        ) from error
    if not root.is_dir() or root.name != _locked_runtime_source_name(spec):
        raise DatasetRuntimeSourceError(
            "locked_runtime_source_name_mismatch",
            "locked runtime source name does not match the Revision",
        )
    parent = root.parent.stat()
    if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
        raise DatasetRuntimeSourceError(
            "locked_runtime_source_parent_permissions_invalid",
            "locked runtime source parent must be owner-only",
        )
    git = _git_binary()
    top = _run_git(
        (git, "-C", str(root), "rev-parse", "--show-toplevel"),
        timeout_seconds=3,
        reason_code="locked_runtime_source_verification_failed",
    ).stdout.strip()
    revision = _run_git(
        (git, "-C", str(root), "rev-parse", "HEAD"),
        timeout_seconds=3,
        reason_code="locked_runtime_source_verification_failed",
    ).stdout.strip()
    status = _run_git(
        (git, "-C", str(root), "status", "--porcelain"),
        timeout_seconds=3,
        reason_code="locked_runtime_source_verification_failed",
    ).stdout.strip()
    if Path(top).resolve() != root or revision != spec.implementation_commit or status:
        raise DatasetRuntimeSourceError(
            "locked_runtime_source_revision_or_cleanliness_invalid",
            "locked runtime source Revision or cleanliness is invalid",
        )
    for relative in spec.required_paths:
        candidate = root / relative
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise DatasetRuntimeSourceError(
                "locked_runtime_source_shape_invalid",
                "locked runtime source is missing a required entrypoint",
            ) from error
        if root not in resolved.parents or not resolved.is_file():
            raise DatasetRuntimeSourceError(
                "locked_runtime_source_shape_invalid",
                "locked runtime source entrypoint is invalid",
            )
    symbolic_ref = _run_git(
        (git, "-C", str(root), "symbolic-ref", "-q", "HEAD"),
        timeout_seconds=3,
        reason_code="locked_runtime_source_head_verification_failed",
        allowed_returncodes=(0, 1),
    )
    remotes = _run_git(
        (git, "-C", str(root), "remote"),
        timeout_seconds=3,
        reason_code="locked_runtime_source_remote_verification_failed",
    ).stdout.splitlines()
    if symbolic_ref.returncode != 1 or symbolic_ref.stdout.strip() or any(remotes):
        raise DatasetRuntimeSourceError(
            "locked_runtime_source_not_sealed",
            "locked runtime source must be detached and have no Remote",
        )
    return DatasetRuntimeSourceEvidence(
        repository_id=spec.repository_id,
        implementation_revision=spec.implementation_commit,
        runtime_source_name=root.name,
        created=created,
        detached_head=True,
        remote_count=0,
        clean=True,
    )


def materialize_dataset_runtime_source(
    source_repository: Path | str,
    runtime_root: Path | str,
    *,
    implementation_lock: DatasetAgentImplementationLock | None = None,
) -> DatasetRuntimeSourceEvidence:
    """Create or verify an isolated clone for the locked implementation commit."""

    lock = implementation_lock or load_dataset_agent_implementation_lock()
    source = _verify_source_repository(source_repository, lock)
    root = _prepare_runtime_root(runtime_root, source)
    expected_name = _runtime_source_name(lock)
    target = root / expected_name
    if target.exists() or target.is_symlink():
        return verify_dataset_runtime_source(
            target,
            implementation_lock=lock,
            created=False,
        )

    git = _git_binary()
    try:
        with tempfile.TemporaryDirectory(
            prefix=".dataset-runtime-source-",
            dir=root,
        ) as temporary:
            staging = Path(temporary) / expected_name
            _run_git(
                (
                    git,
                    "clone",
                    "--no-local",
                    "--no-checkout",
                    "--no-tags",
                    "--quiet",
                    str(source),
                    str(staging),
                ),
                timeout_seconds=30,
                reason_code="dataset_runtime_source_clone_failed",
            )
            _run_git(
                (
                    git,
                    "-C",
                    str(staging),
                    "checkout",
                    "--detach",
                    "--quiet",
                    lock.implementation_commit,
                ),
                timeout_seconds=10,
                reason_code="dataset_runtime_source_checkout_failed",
            )
            _run_git(
                (git, "-C", str(staging), "remote", "remove", "origin"),
                timeout_seconds=5,
                reason_code="dataset_runtime_source_seal_failed",
            )
            verify_dataset_runtime_source(
                staging,
                implementation_lock=lock,
                created=True,
            )
            try:
                staging.rename(target)
            except OSError as error:
                raise DatasetRuntimeSourceError(
                    "dataset_runtime_source_publish_failed",
                    "isolated Dataset runtime source could not be published",
                ) from error
    except DatasetRuntimeSourceError:
        raise
    except DatasetAgentProcessError:
        raise
    except OSError as error:
        raise DatasetRuntimeSourceError(
            "dataset_runtime_source_materialization_failed",
            "isolated Dataset runtime source could not be materialized",
        ) from error

    return verify_dataset_runtime_source(
        target,
        implementation_lock=lock,
        created=True,
    )


def verify_dataset_runtime_source(
    runtime_source: Path | str,
    *,
    implementation_lock: DatasetAgentImplementationLock | None = None,
    created: bool = False,
) -> DatasetRuntimeSourceEvidence:
    """Verify revision, cleanliness, detached HEAD, and absence of remotes."""

    lock = implementation_lock or load_dataset_agent_implementation_lock()
    root = verify_dataset_agent_implementation(runtime_source, lock)
    if root.name != _runtime_source_name(lock):
        raise DatasetRuntimeSourceError(
            "dataset_runtime_source_name_mismatch",
            "Dataset runtime source name does not match the locked revision",
        )
    try:
        parent_metadata = root.parent.stat()
    except OSError as error:
        raise DatasetRuntimeSourceError(
            "dataset_runtime_source_parent_unavailable",
            "Dataset runtime source parent metadata is unavailable",
        ) from error
    if (
        not root.parent.is_dir()
        or parent_metadata.st_uid != os.getuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o077
    ):
        raise DatasetRuntimeSourceError(
            "dataset_runtime_source_parent_permissions_invalid",
            "Dataset runtime source parent must be owner-only",
        )
    git = _git_binary()
    symbolic_ref = _run_git(
        (git, "-C", str(root), "symbolic-ref", "-q", "HEAD"),
        timeout_seconds=3,
        reason_code="dataset_runtime_source_head_verification_failed",
        allowed_returncodes=(0, 1),
    )
    if symbolic_ref.returncode != 1 or symbolic_ref.stdout.strip():
        raise DatasetRuntimeSourceError(
            "dataset_runtime_source_not_detached",
            "Dataset runtime source must use a detached HEAD",
        )
    remote_result = _run_git(
        (git, "-C", str(root), "remote"),
        timeout_seconds=3,
        reason_code="dataset_runtime_source_remote_verification_failed",
    )
    remotes = tuple(line for line in remote_result.stdout.splitlines() if line.strip())
    if remotes:
        raise DatasetRuntimeSourceError(
            "dataset_runtime_source_remote_present",
            "Dataset runtime source must not retain a Git remote",
        )
    return DatasetRuntimeSourceEvidence(
        repository_id=lock.repository_id,
        implementation_revision=lock.implementation_commit,
        runtime_source_name=root.name,
        created=created,
        detached_head=True,
        remote_count=0,
        clean=True,
    )


def runtime_source_document(
    evidence: DatasetRuntimeSourceEvidence,
) -> dict[str, object]:
    return {
        "status": "ready",
        "evidence_status": "local_d0_runtime_source",
        "production_authorization": False,
        "repository_id": evidence.repository_id,
        "implementation_revision": evidence.implementation_revision,
        "runtime_source_name": evidence.runtime_source_name,
        "created": evidence.created,
        "detached_head": evidence.detached_head,
        "remote_count": evidence.remote_count,
        "clean": evidence.clean,
    }


def _verify_source_repository(
    source_repository: Path | str,
    lock: DatasetAgentImplementationLock,
) -> Path:
    supplied = Path(source_repository)
    if supplied.is_symlink():
        raise DatasetRuntimeSourceError(
            "dataset_runtime_source_repository_symlink_forbidden",
            "Dataset source repository may not be a symbolic link",
        )
    try:
        source = supplied.resolve(strict=True)
    except OSError as error:
        raise DatasetRuntimeSourceError(
            "dataset_runtime_source_repository_unavailable",
            "Dataset source repository is unavailable",
        ) from error
    if not source.is_dir():
        raise DatasetRuntimeSourceError(
            "dataset_runtime_source_repository_invalid",
            "Dataset source repository must be a directory",
        )
    git = _git_binary()
    top = _run_git(
        (git, "-C", str(source), "rev-parse", "--show-toplevel"),
        timeout_seconds=3,
        reason_code="dataset_runtime_source_repository_verification_failed",
    ).stdout.strip()
    if not top or Path(top).resolve() != source:
        raise DatasetRuntimeSourceError(
            "dataset_runtime_source_repository_root_mismatch",
            "Dataset source path must be the Git repository root",
        )
    revision = _run_git(
        (
            git,
            "-C",
            str(source),
            "rev-parse",
            "--verify",
            f"{lock.implementation_commit}^{{commit}}",
        ),
        timeout_seconds=3,
        reason_code="dataset_runtime_source_revision_unavailable",
    ).stdout.strip()
    if revision != lock.implementation_commit:
        raise DatasetRuntimeSourceError(
            "dataset_runtime_source_revision_mismatch",
            "Dataset source repository does not contain the locked commit",
        )
    return source


def _verify_locked_source_repository(
    source_repository: Path | str,
    spec: LockedRuntimeSourceSpec,
) -> Path:
    supplied = Path(source_repository)
    if supplied.is_symlink():
        raise DatasetRuntimeSourceError(
            "locked_runtime_source_repository_symlink_forbidden",
            "locked source repository may not be a symbolic link",
        )
    try:
        source = supplied.resolve(strict=True)
    except OSError as error:
        raise DatasetRuntimeSourceError(
            "locked_runtime_source_repository_unavailable",
            "locked source repository is unavailable",
        ) from error
    if not source.is_dir():
        raise DatasetRuntimeSourceError(
            "locked_runtime_source_repository_invalid",
            "locked source repository must be a directory",
        )
    git = _git_binary()
    top = _run_git(
        (git, "-C", str(source), "rev-parse", "--show-toplevel"),
        timeout_seconds=3,
        reason_code="locked_runtime_source_repository_verification_failed",
    ).stdout.strip()
    revision = _run_git(
        (
            git,
            "-C",
            str(source),
            "rev-parse",
            "--verify",
            f"{spec.implementation_commit}^{{commit}}",
        ),
        timeout_seconds=3,
        reason_code="locked_runtime_source_revision_unavailable",
    ).stdout.strip()
    if not top or Path(top).resolve() != source or revision != spec.implementation_commit:
        raise DatasetRuntimeSourceError(
            "locked_runtime_source_repository_mismatch",
            "locked source repository root or Revision is invalid",
        )
    return source


def _prepare_runtime_root(runtime_root: Path | str, source: Path) -> Path:
    supplied = Path(runtime_root)
    if supplied.is_symlink():
        raise DatasetRuntimeSourceError(
            "dataset_runtime_root_symlink_forbidden",
            "Dataset runtime root may not be a symbolic link",
        )
    if supplied.exists():
        try:
            root = supplied.resolve(strict=True)
        except OSError as error:
            raise DatasetRuntimeSourceError(
                "dataset_runtime_root_unavailable",
                "Dataset runtime root is unavailable",
            ) from error
    else:
        try:
            parent = supplied.parent.resolve(strict=True)
            parent_mode = stat.S_IMODE(parent.stat().st_mode)
        except OSError as error:
            raise DatasetRuntimeSourceError(
                "dataset_runtime_root_parent_unavailable",
                "Dataset runtime root parent is unavailable",
            ) from error
        if not parent.is_dir() or parent_mode & 0o002:
            raise DatasetRuntimeSourceError(
                "dataset_runtime_root_parent_unsafe",
                "Dataset runtime root parent is not a safe directory",
            )
        try:
            supplied.mkdir(mode=0o700)
            root = supplied.resolve(strict=True)
        except OSError as error:
            raise DatasetRuntimeSourceError(
                "dataset_runtime_root_create_failed",
                "Dataset runtime root could not be created",
            ) from error
    try:
        metadata = root.stat()
    except OSError as error:
        raise DatasetRuntimeSourceError(
            "dataset_runtime_root_unavailable",
            "Dataset runtime root metadata is unavailable",
        ) from error
    if (
        not root.is_dir()
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise DatasetRuntimeSourceError(
            "dataset_runtime_root_permissions_invalid",
            "Dataset runtime root must be owner-only",
        )
    if root == source or source in root.parents:
        raise DatasetRuntimeSourceError(
            "dataset_runtime_root_inside_source_forbidden",
            "Dataset runtime root may not be inside the development repository",
        )
    return root


def _git_binary() -> str:
    git = shutil.which("git")
    if git is None:
        raise DatasetRuntimeSourceError(
            "dataset_runtime_source_git_unavailable",
            "Git is required to materialize Dataset runtime source",
        )
    return git


def _runtime_source_name(lock: DatasetAgentImplementationLock) -> str:
    return f"{lock.repository_id}-{lock.implementation_commit[:12]}"


def _locked_runtime_source_name(spec: LockedRuntimeSourceSpec) -> str:
    return f"{spec.repository_id}-{spec.implementation_commit[:12]}"


def _run_git(
    argv: tuple[str, ...],
    *,
    timeout_seconds: float,
    reason_code: str,
    allowed_returncodes: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise DatasetRuntimeSourceError(
            reason_code,
            "Git operation for Dataset runtime source failed",
        ) from error
    if result.returncode not in allowed_returncodes:
        raise DatasetRuntimeSourceError(
            reason_code,
            "Git operation for Dataset runtime source failed",
        )
    return result

