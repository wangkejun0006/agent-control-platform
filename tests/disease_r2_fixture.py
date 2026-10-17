"""Self-contained synthetic fixtures for Disease R2 verification tests."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

_FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures/disease-r2/scope-decisions.fixture.synthetic.jsonl"
)
_SCOPE_LEDGER_DIRECTORY = tempfile.TemporaryDirectory(
    prefix="orbit-disease-r2-scope-ledger-"
)
SCOPE_LEDGER = Path(_SCOPE_LEDGER_DIRECTORY.name) / "scope-decisions.synthetic.jsonl"
shutil.copyfile(_FIXTURE, SCOPE_LEDGER)
SCOPE_LEDGER.chmod(0o600)

