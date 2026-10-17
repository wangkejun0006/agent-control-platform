from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import tarfile
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from orbit_agent_control_plane.service_runtime.runtime_artifacts import (
    _validate_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    ROOT
    / "deploy/lan-stage1/runtime-artifacts/build-hermes-runtime-artifact.py"
)
SPEC = importlib.util.spec_from_file_location("orbit_hermes_bundle", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
IMPORTER_PATH = (
    ROOT
    / "deploy/lan-stage1/department-device/runner/"
    "orbit_runtime_artifact_importer.py"
)
IMPORTER_SPEC = importlib.util.spec_from_file_location(
    "orbit_runtime_artifact_importer", IMPORTER_PATH
)
assert IMPORTER_SPEC is not None and IMPORTER_SPEC.loader is not None
IMPORTER = importlib.util.module_from_spec(IMPORTER_SPEC)
IMPORTER_SPEC.loader.exec_module(IMPORTER)


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def write_json(path: Path, value: object) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    path.write_bytes(raw)
    return raw


def oci_archive(path: Path) -> tuple[str, str]:
    config = b"{}"
    config_digest = digest(config)
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config),
            },
            "layers": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    manifest_digest = digest(manifest)
    index = json.dumps(
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": manifest_digest,
                    "size": len(manifest),
                    "platform": {"architecture": "amd64", "os": "linux"},
                }
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    entries = {
        "index.json": index,
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        f"blobs/sha256/{manifest_digest[7:]}": manifest,
        f"blobs/sha256/{config_digest[7:]}": config,
    }
    with tarfile.open(path, "w") as archive:
        for name, raw in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            import io

            archive.addfile(info, io.BytesIO(raw))
    return manifest_digest, config_digest


def manifest_template(path: Path) -> None:
    zero = "sha256:" + "0" * 64
    write_json(
        path,
        {
            "api_version": "company-ai-os/v1alpha3-draft",
            "kind": "RuntimeArtifactManifest",
            "metadata": {
                "artifact_id": "runtime_artifact_hermes_product_d0",
                "version": "0.21.0",
                "revision": 1,
                "evidence_status": "synthetic_d0",
                "synthetic_only": True,
                "created_at": "2026-09-03T08:00:00Z",
            },
            "spec": {
                "runtime_family": "hermes",
                "upstream_revision": "29112be",
                "runtime_source_lock_ref": {
                    "id": "runtime_source_lock_hermes_product_d0",
                    "version": "0.21.0-d0",
                    "digest": zero,
                },
                "runtime_source_digest": zero,
                "runtime_realization_ref": {
                    "id": "runtime_realization_hermes_product_d0",
                    "version": "0.21.0-d0",
                    "digest": zero,
                },
                "runtime_realization_digest": zero,
                "container_isolation_profile_ref": {
                    "id": "container_isolation_hermes_product_d0",
                    "version": "0.21.0-d0",
                    "digest": zero,
                },
                "container_isolation_profile_digest": zero,
                "runtime_adapter": {
                    "adapter_id": "runtime_adapter_hermes_product_d0",
                    "version": "0.21.0-d0",
                    "source_digest": zero,
                    "capability_report_ref": {
                        "id": "adapter_capability_hermes_product_d0",
                        "version": "0.21.0-d0",
                        "digest": zero,
                    },
                    "capability_report_digest": zero,
                },
                "build_inputs": {
                    "dockerfile_digest": zero,
                    "dependency_lock_digest": zero,
                    "base_image_digest": zero,
                    "build_arguments_contain_secrets": False,
                },
                "oci_image": {
                    "layout_media_type": "application/vnd.oci.layout.header.v1+json",
                    "manifest_digest": zero,
                    "config_digest": zero,
                    "archive_digest": zero,
                    "target_platform": "linux/amd64",
                    "floating_tag_allowed": False,
                },
                "evidence": {
                    "sbom_ref": "evidence://d0/hermes-product/sbom",
                    "sbom_digest": zero,
                    "build_provenance_ref": "evidence://d0/hermes-product/provenance",
                    "build_provenance_digest": zero,
                    "vulnerability_report_ref": "evidence://d0/hermes-product/vulnerability",
                    "vulnerability_report_digest": zero,
                    "license_report_ref": "evidence://d0/hermes-product/license",
                    "license_report_digest": zero,
                },
                "supported_scope": {
                    "agent_release_refs": [{
                        "id": "agent_release_product_hermes_d0",
                        "version": "0.21.0-d0",
                        "digest": "sha256:" + "5" * 64,
                    }],
                    "model_protocols": ["openai_responses"],
                    "tool_operations": [],
                    "data_classifications": ["synthetic", "public"],
                },
                "minimum_runner_capabilities": {
                    "os_family": "linux",
                    "wsl_distribution": "Ubuntu-22.04",
                    "container_engine": "rootless-docker",
                    "rootless_required": True,
                    "systemd_required": True,
                    "seccomp_required": True,
                    "cgroup_resource_limits_required": True,
                },
                "artifact_bundle": {
                    "bundle_ref": "bundle://d0/hermes-product/runtime-artifact",
                    "artifact_set_manifest_digest": zero,
                    "signature_bundle_digest": zero,
                    "verification_key_ref": "key://d0/runtime-artifact-verifier",
                },
                "lifecycle": {
                    "status": "candidate",
                    "revoked_at": None,
                    "superseding_artifact_ref": None,
                },
                "manifest_digest": zero,
            },
            "authority_boundary": {
                "agent_identity_created": False,
                "execution_grant_issued": False,
                "deployment_activated": False,
                "production_authorized": False,
                "release_authorization": False,
            },
        },
    )


class HermesRuntimeArtifactBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.payload = self.root / "payload"
        self.payload.mkdir()
        image_manifest_digest, image_config_digest = oci_archive(
            self.payload / "oci-image.tar"
        )
        write_json(
            self.payload / "runtime-source-lock.json",
            {
                "runtime_family": "hermes",
                "version": "0.21.0",
                "tag": "v2026.8.31",
                "commit": "29112be",
                "target_platform": "linux/amd64",
                "floating_tag_allowed": False,
                "source_digest": "sha256:" + "1" * 64,
                "oci_manifest_digest": image_manifest_digest,
                "oci_config_digest": image_config_digest,
                "local_image_ref": "orbit/hermes-agent:0.21.0-29112be",
                "qualification_probe_entrypoint": (
                    "/opt/orbit/bin/orbit-hermes-qualification-probe"
                ),
            },
        )
        for name in MODULE.REQUIRED_PAYLOADS:
            target = self.payload / name
            if not target.exists():
                write_json(target, {"evidence_status": "synthetic_d0"})
        write_json(
            self.payload / "runtime-realization.json",
            {
                "runtime_family": "hermes",
                "version": "0.21.0",
                "target_platform": "linux/amd64",
                "build_inputs": {
                    "dockerfile_digest": "sha256:" + "2" * 64,
                    "dependency_lock_digest": "sha256:" + "3" * 64,
                    "base_image_digest": "sha256:" + "4" * 64,
                    "build_arguments_contain_secrets": False,
                },
            },
        )
        write_json(
            self.payload / "runtime-adapter.json",
            {
                "runtime_family": "hermes",
                "version": "0.21.0",
                "qualification_probe_entrypoint": (
                    "/opt/orbit/bin/orbit-hermes-qualification-probe"
                ),
                "professional_task_runtime_started": False,
                "model_called": False,
            },
        )
        write_json(
            self.payload / "container-isolation-profile.json",
            {
                "target_platform": "linux/amd64",
                "rootless_required": True,
                "read_only_root": True,
                "network_mode": "none",
                "no_new_privileges": True,
                "cap_drop": ["ALL"],
                "seccomp_required": True,
                "cgroup_v2_required": True,
            },
        )
        self.template = self.root / "manifest-template.json"
        manifest_template(self.template)
        self.signing_key = self.root / "runtime-artifact-signing-key.pem"
        key = Ed25519PrivateKey.generate()
        self.signing_key.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.signing_key.chmod(0o600)
        self.output = self.root / "hermes-product.oci.tar"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_builds_fixed_signed_offline_bundle_without_starting_runtime(self) -> None:
        result = MODULE.build(
            Namespace(
                payload_root=self.payload,
                manifest_template=self.template,
                signing_key=self.signing_key,
                output=self.output,
            )
        )
        self.assertEqual("0.21.0", result["runtime_version"])
        self.assertEqual("v2026.8.31", result["runtime_tag"])
        self.assertEqual("29112be", result["runtime_commit"])
        self.assertEqual("linux/amd64", result["target_platform"])
        self.assertFalse(result["qualification_probe_executed"])
        self.assertFalse(result["professional_task_runtime_started"])
        self.assertEqual(digest(self.output.read_bytes()), result["bundle_digest"])
        with tarfile.open(self.output) as archive:
            names = set(archive.getnames())
            self.assertEqual(
                set(MODULE.REQUIRED_PAYLOADS)
                | {
                    "artifact-set-manifest.json",
                    "signature-bundle.json",
                    "runtime-artifact-manifest.json",
                },
                names,
            )
            artifact_set_raw = archive.extractfile(
                "artifact-set-manifest.json"
            ).read()
            signature = json.load(archive.extractfile("signature-bundle.json"))
            built_manifest = json.load(
                archive.extractfile("runtime-artifact-manifest.json")
            )
            _validate_manifest(built_manifest)
            public_key = serialization.load_pem_public_key(
                self.output.with_suffix(".tar.public.pem").read_bytes()
            )
            public_key.verify(
                base64.b64decode(signature["signature_base64"]),
                artifact_set_raw,
            )
        verified = IMPORTER.verify_bundle(
            bundle=self.output,
            assignment={
                "artifact_id": result["artifact_id"],
                "revision_digest": result["revision_digest"],
                "bundle_digest": result["bundle_digest"],
            },
            public_key=self.output.with_suffix(".tar.public.pem"),
            expected_key_digest=result["verification_public_key_digest"],
            working_root=self.root / "verified",
        )
        commands: list[tuple[str, ...]] = []

        def fake_run(*args: str, timeout: int = 120) -> str:
            del timeout
            commands.append(args)
            if args[:2] == ("docker", "info"):
                return json.dumps(
                    {
                        "SecurityOptions": ["name=rootless", "name=seccomp"],
                        "CgroupVersion": "2",
                    }
                )
            if args[:3] == ("docker", "image", "load"):
                return "Loaded image: orbit/hermes-agent:0.21.0-29112be"
            return json.dumps(
                {
                    "runtime_family": "hermes",
                    "version": "0.21.0",
                    "effective_uid_non_root": True,
                    "read_only_root": True,
                    "no_new_privileges": True,
                    "network_mode": "none",
                    "network_escape_detected": False,
                    "model_secret_present": False,
                    "adapter_entrypoint_verified": True,
                    "qualification_probe_executed": True,
                    "professional_task_runtime_started": False,
                }
            )

        probe = IMPORTER.import_and_probe(verified, run=fake_run)
        self.assertTrue(probe["qualification_probe_executed"])
        self.assertFalse(probe["professional_task_runtime_started"])
        docker_run = next(item for item in commands if item[:2] == ("docker", "run"))
        self.assertIn("none", docker_run)
        self.assertIn("--read-only", docker_run)
        self.assertIn("no-new-privileges=true", docker_run)
        self.assertNotIn("latest", docker_run)

    def test_probe_rejects_missing_rootless_seccomp_or_cgroup(self) -> None:
        def rootful(*_args: str, timeout: int = 120) -> str:
            del timeout
            return json.dumps(
                {"SecurityOptions": ["name=seccomp"], "CgroupVersion": "1"}
            )

        with self.assertRaisesRegex(
            IMPORTER.ArtifactImportError,
            "runtime_artifact_isolation_controls_missing",
        ):
            IMPORTER.import_and_probe(
                {"source_lock": {}, "working_root": self.root}, run=rootful
            )

    def test_rejects_floating_or_drifted_source_lock(self) -> None:
        source = json.loads(
            (self.payload / "runtime-source-lock.json").read_text()
        )
        source["tag"] = "latest"
        write_json(self.payload / "runtime-source-lock.json", source)
        with self.assertRaisesRegex(ValueError, "hermes_source_lock_invalid"):
            MODULE.build(
                Namespace(
                    payload_root=self.payload,
                    manifest_template=self.template,
                    signing_key=self.signing_key,
                    output=self.output,
                )
            )


if __name__ == "__main__":
    unittest.main()

