"""Static-only Disease R2 Docker Harness description.

This module deliberately exposes no subprocess or Docker execution function.
"""

from __future__ import annotations

from pathlib import Path

from disease_r2_candidate import build_docker_command


def describe_harness(ephemeral_bundle_dir: Path) -> dict[str, object]:
    command = build_docker_command(ephemeral_bundle_dir)
    return {
        "harness_version": "orbit.disease-r2-docker-harness/1",
        "status": "command-construction-only",
        "command": list(command),
        "container_started": False,
        "docker_inspected": False,
        "external_network_used": False,
        "model_called": False,
        "nas_accessed": False,
        "release_authorization": False,
    }

