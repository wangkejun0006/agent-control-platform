"""Owner-only local Pilot entry guard.

This is deliberately a process-start profile, not a replacement identity
provider.  The operator must be the configured local OS owner and all local
state/signing/provider files must remain regular, single-link, owner-only
files.  Pre-production replaces this adapter with OIDC and workload identity.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


class LocalOperatorError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class LocalOperatorPrincipal:
    operator_ref: str
    owner_uid: int
    profile: str = "local_trusted_operator"
    production_authorization: bool = False
    release_authorization: bool = False


class LocalTrustedOperatorGuard:
    def __init__(
        self,
        *,
        owner_uid: int,
        state_root: Path,
        protected_files: Sequence[Path] = (),
    ) -> None:
        if owner_uid < 0 or not state_root.is_absolute():
            raise LocalOperatorError("local_operator_configuration_invalid")
        self.owner_uid = owner_uid
        self.state_root = state_root
        self.protected_files = tuple(protected_files)

    def verify_current_process(self) -> LocalOperatorPrincipal:
        if os.geteuid() != self.owner_uid:
            raise LocalOperatorError("local_operator_uid_mismatch")
        root_info = self._lstat(self.state_root, "local_operator_state_root_invalid")
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != self.owner_uid
            or root_info.st_mode & 0o077
        ):
            raise LocalOperatorError("local_operator_state_root_invalid")
        for path in self.protected_files:
            info = self._lstat(path, "local_operator_protected_file_invalid")
            if (
                not path.is_absolute()
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != self.owner_uid
                or info.st_nlink != 1
                or info.st_mode & 0o077
                or not 1 <= info.st_size <= 256 * 1024
            ):
                raise LocalOperatorError("local_operator_protected_file_invalid")
        return LocalOperatorPrincipal(
            operator_ref=f"human_local_os_owner_uid_{self.owner_uid}",
            owner_uid=self.owner_uid,
        )

    @staticmethod
    def _lstat(path: Path, reason_code: str):
        try:
            return path.lstat()
        except OSError as error:
            raise LocalOperatorError(reason_code) from error

