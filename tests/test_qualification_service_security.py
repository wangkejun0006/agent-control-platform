from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from orbit_agent_control_plane.service_runtime.security import (
    Ed25519EvaluationGrantSigner,
    FileSecretReferenceResolver,
    MtlsWorkloadIdentityVerifier,
    OidcHumanIdentityVerifier,
    ServiceSecurityError,
)

ROOT = Path(__file__).resolve().parents[1]


class QualificationServiceSecurityTests(unittest.TestCase):
    def test_preproduction_profile_separates_human_ca_and_grant_keys(self) -> None:
        profile = json.loads(
            (
                ROOT
                / "references/qualification-service-security-profile.candidate.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(profile["human_oidc"]["administrator_is_issuer"])
        self.assertEqual("orbit_control_plane", profile["human_oidc"]["audience"])
        self.assertEqual(2, profile["workload_mtls"]["ca_bundle_max_certificates"])
        self.assertEqual(
            "external_secret_mount", profile["grant_signing"]["key_custody"]
        )
        compose = (
            ROOT / "deploy/service/compose.preproduction.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("ORBIT_SERVICE_OIDC_AUDIENCE: orbit_control_plane", compose)
        self.assertIn("ORBIT_SERVICE_OIDC_ALLOWED_ROLES: control_plane_admin", compose)
        self.assertIn("ORBIT_SERVICE_OIDC_ADMIN_SUBJECT_DIGESTS:", compose)
        self.assertIn("external: true", compose)

    def test_oidc_verifies_signature_issuer_audience_role_and_expiry(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        verifier = OidcHumanIdentityVerifier(
            issuer="https://identity.orbit.example",
            audience="orbit_control_plane",
            public_key_pem=public_pem,
            required_key_id="oidc_admin_2026_08",
            allowed_subject_digests=(
                "sha256:" + hashlib.sha256(b"synthetic-owner").hexdigest(),
            ),
        )
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "iss": "https://identity.orbit.example",
                "aud": "orbit_control_plane",
                "sub": "synthetic-owner",
                "jti": "synthetic-token-001",
                "iat": now,
                "exp": now + timedelta(minutes=5),
                "roles": ["control_plane_admin"],
            },
            private_key,
            algorithm="EdDSA",
            headers={"kid": "oidc_admin_2026_08"},
        )
        principal = verifier.verify_oidc_assertion(
            token=token,
            expected_audience="orbit_control_plane",
        )
        self.assertTrue(principal["human_ref"].startswith("human_"))
        self.assertEqual(["role_control_plane_admin"], principal["role_refs"])
        with self.assertRaises(ServiceSecurityError):
            verifier.verify_oidc_assertion(
                token=token,
                expected_audience="wrong_audience",
            )
        wrong_subject_token = jwt.encode(
            {
                "iss": "https://identity.orbit.example",
                "aud": "orbit_control_plane",
                "sub": "unexpected-admin",
                "jti": "synthetic-token-002",
                "iat": now,
                "exp": now + timedelta(minutes=5),
                "roles": ["control_plane_admin"],
            },
            private_key,
            algorithm="EdDSA",
            headers={"kid": "oidc_admin_2026_08"},
        )
        with self.assertRaisesRegex(ServiceSecurityError, "oidc_subject_not_allowed"):
            verifier.verify_oidc_assertion(
                token=wrong_subject_token,
                expected_audience="orbit_control_plane",
            )

    def test_mtls_validates_ca_signature_client_usage_and_spiffe_identity(self) -> None:
        now = datetime.now(timezone.utc)
        ca_key = ed25519.Ed25519PrivateKey.generate()
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Orbit Test CA")])
        ca = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, algorithm=None)
        )
        leaf_key = ed25519.Ed25519PrivateKey.generate()
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "runner")])
        leaf = (
            x509.CertificateBuilder()
            .subject_name(leaf_name)
            .issuer_name(ca.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(minutes=55))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.UniformResourceIdentifier(
                            "spiffe://orbit.local/workload/r2_runner"
                        )
                    ]
                ),
                critical=False,
            )
            .sign(ca_key, algorithm=None)
        )
        verifier = MtlsWorkloadIdentityVerifier(
            ca_certificate_pem=ca.public_bytes(serialization.Encoding.PEM),
            trust_domain="orbit.local",
            allowed_workload_names=("r2_runner",),
        )
        principal = verifier.verify_mtls_peer(
            peer_certificate=leaf.public_bytes(serialization.Encoding.DER)
        )
        self.assertEqual("workload_r2_runner", principal["workload_identity"])

    def test_ed25519_signer_and_owner_only_secret_resolution(self) -> None:
        key = ed25519.Ed25519PrivateKey.generate()
        private_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        signer = Ed25519EvaluationGrantSigner(
            private_key_pem=private_pem,
            key_id="grant_signer_test",
        )
        grant = {
            "api_version": "company-ai-os/v1alpha1",
            "kind": "ExecutionGrant",
            "metadata": {
                "evidence_status": "synthetic",
                "expires_at": "2026-08-28T01:10:00Z",
                "issued_at": "2026-08-28T01:00:00Z",
                "status": "active",
                "synthetic_only": True,
            },
            "spec": {},
        }
        canonical_grant = json.dumps(
            grant,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        signature = signer.sign_grant(
            canonical_grant=canonical_grant,
            key_id="grant_signer_test",
        )
        self.assertTrue(signature)
        self.assertEqual("EdDSA", signer.public_metadata()["algorithm"])
        grant["metadata"]["expires_at"] = "2026-08-28T01:16:00Z"
        with self.assertRaisesRegex(ServiceSecurityError, "grant_lifetime_invalid"):
            signer.sign_grant(
                canonical_grant=json.dumps(
                    grant,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode(),
                key_id="grant_signer_test",
            )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "key.pem"
            path.write_bytes(private_pem)
            os.chmod(path, 0o600)
            resolver = FileSecretReferenceResolver(
                {"secret://control-plane/grant-signing-key": path},
                access_policy={
                    "secret://control-plane/grant-signing-key": (
                        "workload_control_plane_service",
                    )
                },
            )
            self.assertEqual(
                private_pem,
                resolver.resolve_for_workload(
                    logical_ref="secret://control-plane/grant-signing-key",
                    workload_identity="workload_control_plane_service",
                ),
            )
            with self.assertRaisesRegex(
                ServiceSecurityError, "secret_workload_not_allowed"
            ):
                resolver.resolve_for_workload(
                    logical_ref="secret://control-plane/grant-signing-key",
                    workload_identity="workload_untrusted_runner",
                )
            os.chmod(path, 0o644)
            with self.assertRaises(ServiceSecurityError):
                resolver.resolve_for_workload(
                    logical_ref="secret://control-plane/grant-signing-key",
                    workload_identity="workload_control_plane_service",
                )


if __name__ == "__main__":
    unittest.main()

