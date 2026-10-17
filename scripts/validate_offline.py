"""Declared offline validation scope; omitted integrations are reported, not passed."""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

EXCLUDED = {
    "test_dataset_agent_process": "Original locked Scientific repository is not bundled; new frozen-port tests cover offline execution.",
    "test_dataset_execution": "Original locked Scientific repository required; new end-to-end tests cover leases and cancellation.",
    "test_runtime_source": "Original private Git objects and detached source materialization required.",
    "test_watchlist_execution": "Two original locked domain repositories required.",
    "test_lifecycle_intake": "Original private domain release packages required.",
    "test_registration": "Original domain registration handoff package required.",
    "test_registration_cli": "Original domain registration handoff package required.",
}
for name in (
    "test_dataset_evidence_acceptance",
    "test_dataset_evidence_acceptance_cli",
    "test_dataset_tool_d0_evidence",
    "test_disease_r1_execution_evidence",
    "test_disease_r1_review",
    "test_public_pilot_review",
    "test_publication_baseline",
    "test_qualification_service_evidence",
    "test_runtime_artifact_source_lock",
):
    EXCLUDED[name] = (
        "Original historical approval or execution evidence intentionally excluded; no claim of public-demo verification."
    )
for name in (
    "test_cockpit_lan_build",
    "test_codex_cli_lan_distribution",
    "test_codex_receipt_release_binding",
    "test_company_model_runtime_d0",
    "test_department_device_quick_pilot",
    "test_department_discovery_forms",
    "test_disease_agent_e4_docker_runner",
    "test_lan_host_installation",
    "test_loopback_d0_assets",
    "test_technology_transport_upgrade",
):
    EXCLUDED[name] = (
        "Original installation scripts, device assets or organization forms are not part of the portable local demo."
    )
EXCLUDED["test_model_catalog_integrity"] = (
    "Cross-repository draft-schema exchange script is not ported."
)
for path in (ROOT / "tests").glob("test_*.py"):
    if path.stem.startswith(
        ("test_disease_", "test_full_chain_", "test_dataset_public_")
    ):
        EXCLUDED[path.stem] = (
            "Original domain-specific evidence, research corpus or private runtime is not bundled; public demo uses fictional stationery data."
        )
for name in (
    "test_department_first_install",
    "test_hermes_runtime_artifact_bundle",
    "test_lan_update_recovery",
    "test_public_pilot_execution",
    "test_qualification_service_provider_handler",
):
    EXCLUDED[name] = (
        "Original deployment or domain provider execution assets intentionally excluded."
    )

EXCLUDED_TESTS = {
    "test_model_route_reconciler.ModelRouteReconcilerTests.test_dataset_d0_frozen_evidence_remains_byte_exact": "Frozen historical execution evidence is not bundled.",
    "test_qualification_service_security.QualificationServiceSecurityTests.test_preproduction_profile_separates_human_ca_and_grant_keys": "Original preproduction Compose deployment is not bundled; key separation unit tests remain enabled.",
    "test_lan_stage1.FileDepartmentDeviceBundleResolverTests.test_reads_exact_department_release_and_rejects_permission_drift": "Original device installation bundle is not bundled.",
    "test_lan_stage1.LanStage1Tests.test_control_projection_matches_cockpit_contract_and_is_admin_only": "Original LAN deployment source-lock fixtures are not bundled.",
    "test_lan_stage1.LanStage1Tests.test_owner_downloads_only_current_department_device_bundle_with_receipt": "Original device installation bundle is not bundled.",
}


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists() or args.log.exists():
        parser.error(
            "fresh report and log paths required; historical reports are immutable"
        )
    original_connect = socket.socket.connect
    denied = []

    def local_connect(sock, address):
        if isinstance(address, tuple):
            try:
                local = ipaddress.ip_address(address[0]).is_loopback
            except ValueError:
                local = address[0] == "localhost"
            if not local:
                denied.append("external_socket_blocked")
                raise RuntimeError("external_network_forbidden_in_offline_validation")
        return original_connect(sock, address)

    socket.socket.connect = local_connect
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    included = []
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        if path.stem not in EXCLUDED:
            included.append(path.stem)
            loaded = loader.discover(str(ROOT / "tests"), pattern=path.name)
            suite.addTests(
                case for case in flatten(loaded) if case.id() not in EXCLUDED_TESTS
            )
    args.log.parent.mkdir(parents=True, exist_ok=True)
    stream = args.log.open("x")
    started = time.monotonic()
    try:
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    finally:
        socket.socket.connect = original_connect
        stream.close()
    report = {
        "scope": "portable_offline",
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "successful": result.wasSuccessful(),
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "external_network_attempts_blocked": len(denied),
        "model_calls_authorized": 0,
        "included_modules": included,
        "excluded_modules": EXCLUDED,
        "excluded_tests": EXCLUDED_TESTS,
        "failed_tests": [
            {"test": str(case), "traceback": message}
            for case, message in result.failures + result.errors
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x") as output:
        output.write(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "tests_run",
                    "failures",
                    "errors",
                    "skipped",
                    "successful",
                    "elapsed_seconds",
                )
            }
        )
    )
    if not result.wasSuccessful():
        print("\n".join(str(case) for case, _ in result.failures + result.errors))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
