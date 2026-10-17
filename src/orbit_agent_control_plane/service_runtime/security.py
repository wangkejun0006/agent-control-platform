"""Identity, signing, and logical-secret adapters.

No adapter fetches keys over the network.  Bootstrap material is injected by a
deployment-specific SecretReferenceResolver and never enters Task or Agent
payloads.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import stat
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jwt
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID


class ServiceSecurityError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


_SECRET_REF = re.compile(r"^secret://[a-z0-9][a-z0-9/_-]{2,190}$")
_ROLE = re.compile(r"^[a-z][a-z0-9_]{2,95}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class FileSecretReferenceResolver:
    """Resolve an explicit logical-ref map to protected regular files."""

    def __init__(
        self,
        bindings: Mapping[str, Path],
        *,
        access_policy: Mapping[str, Sequence[str]],
    ) -> None:
        if not bindings or set(bindings) != set(access_policy):
            raise ServiceSecurityError("secret_bindings_missing")
        normalized: dict[str, Path] = {}
        normalized_policy: dict[str, frozenset[str]] = {}
        for logical_ref, path in bindings.items():
            if not _SECRET_REF.fullmatch(logical_ref):
                raise ServiceSecurityError("secret_ref_invalid")
            workloads = access_policy[logical_ref]
            if not workloads or any(
                not isinstance(item, str)
                or not item.startswith("workload_")
                or not _ROLE.fullmatch(item[len("workload_") :])
                for item in workloads
            ):
                raise ServiceSecurityError("secret_access_policy_invalid")
            normalized[logical_ref] = Path(path)
            normalized_policy[logical_ref] = frozenset(workloads)
        self._bindings = normalized
        self._access_policy = normalized_policy

    def resolve_for_workload(
        self, *, logical_ref: str, workload_identity: str
    ) -> bytes:
        if not workload_identity.startswith("workload_"):
            raise ServiceSecurityError("secret_workload_identity_invalid")
        path = self._bindings.get(logical_ref)
        if path is None:
            raise ServiceSecurityError("secret_ref_not_allowed")
        if workload_identity not in self._access_policy[logical_ref]:
            raise ServiceSecurityError("secret_workload_not_allowed")
        try:
            info = path.lstat()
        except OSError as error:
            raise ServiceSecurityError("secret_file_invalid") from error
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_mode & 0o077
            or not 1 <= info.st_size <= 64 * 1024
        ):
            raise ServiceSecurityError("secret_file_invalid")
        try:
            return path.read_bytes()
        except OSError as error:
            raise ServiceSecurityError("secret_file_invalid") from error


class OidcHumanIdentityVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        public_key_pem: bytes,
        required_key_id: str,
        allowed_subject_digests: Sequence[str],
        allowed_algorithms: Sequence[str] = ("EdDSA",),
        role_claim: str = "roles",
        allowed_roles: Sequence[str] = ("control_plane_admin",),
        max_token_lifetime_seconds: int = 900,
    ) -> None:
        if not issuer.startswith("https://") or not _ROLE.fullmatch(audience):
            raise ServiceSecurityError("oidc_configuration_invalid")
        if not allowed_algorithms or any(
            algorithm not in {"EdDSA", "RS256", "ES256"}
            for algorithm in allowed_algorithms
        ):
            raise ServiceSecurityError("oidc_algorithm_invalid")
        if not _ROLE.fullmatch(required_key_id):
            raise ServiceSecurityError("oidc_key_id_invalid")
        if (
            not allowed_subject_digests
            or any(not _DIGEST.fullmatch(item) for item in allowed_subject_digests)
        ):
            raise ServiceSecurityError("oidc_subject_configuration_invalid")
        if not _ROLE.fullmatch(role_claim) or not allowed_roles or any(
            not _ROLE.fullmatch(role) for role in allowed_roles
        ):
            raise ServiceSecurityError("oidc_role_configuration_invalid")
        if not 60 <= max_token_lifetime_seconds <= 900:
            raise ServiceSecurityError("oidc_token_lifetime_invalid")
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.public_key = public_key_pem
        self.required_key_id = required_key_id
        self.allowed_subject_digests = frozenset(allowed_subject_digests)
        self.algorithms = tuple(allowed_algorithms)
        self.role_claim = role_claim
        self.allowed_roles = frozenset(allowed_roles)
        self.max_token_lifetime_seconds = max_token_lifetime_seconds

    def verify_oidc_assertion(
        self, *, token: str, expected_audience: str
    ) -> Mapping[str, Any]:
        if expected_audience != self.audience or not token:
            raise ServiceSecurityError("oidc_assertion_invalid")
        try:
            header = jwt.get_unverified_header(token)
            if (
                header.get("kid") != self.required_key_id
                or header.get("alg") not in self.algorithms
            ):
                raise ServiceSecurityError("oidc_assertion_key_invalid")
            claims = jwt.decode(
                token,
                self.public_key,
                algorithms=list(self.algorithms),
                issuer=self.issuer,
                audience=self.audience,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "jti"]},
            )
        except jwt.PyJWTError as error:
            raise ServiceSecurityError("oidc_assertion_invalid") from error
        issued_at = _numeric_date(claims.get("iat"), "oidc_issued_at_invalid")
        expires_at = _numeric_date(claims.get("exp"), "oidc_expiry_invalid")
        if (
            expires_at <= issued_at
            or expires_at - issued_at > self.max_token_lifetime_seconds
        ):
            raise ServiceSecurityError("oidc_token_lifetime_invalid")
        roles_value = claims.get(self.role_claim)
        if not isinstance(roles_value, list) or any(
            not isinstance(item, str) for item in roles_value
        ):
            raise ServiceSecurityError("oidc_role_claim_invalid")
        roles = sorted(self.allowed_roles.intersection(roles_value))
        if not roles:
            raise ServiceSecurityError("oidc_role_not_allowed")
        subject = str(claims["sub"])
        subject_digest = "sha256:" + hashlib.sha256(subject.encode()).hexdigest()
        if subject_digest not in self.allowed_subject_digests:
            raise ServiceSecurityError("oidc_subject_not_allowed")
        human_ref = (
            "human_"
            + hashlib.sha256(f"{self.issuer}\x1f{subject}".encode()).hexdigest()[:20]
        )
        return {
            "human_ref": human_ref,
            "role_refs": [f"role_{role}" for role in roles],
            "issuer": self.issuer,
            "subject_digest": subject_digest,
            "token_id_digest": "sha256:"
            + hashlib.sha256(str(claims["jti"]).encode()).hexdigest(),
        }


class MtlsWorkloadIdentityVerifier:
    """Validate short-lived clients against a one-level rotating CA bundle."""

    def __init__(
        self,
        *,
        ca_certificate_pem: bytes,
        trust_domain: str,
        allowed_workload_names: Sequence[str],
        max_certificate_lifetime_seconds: int = 3600,
    ) -> None:
        if not _ROLE.fullmatch(trust_domain.replace(".", "_")):
            raise ServiceSecurityError("mtls_trust_domain_invalid")
        if not allowed_workload_names or any(
            not _ROLE.fullmatch(item) for item in allowed_workload_names
        ):
            raise ServiceSecurityError("mtls_workload_allowlist_invalid")
        if not 300 <= max_certificate_lifetime_seconds <= 86400:
            raise ServiceSecurityError("mtls_certificate_lifetime_invalid")
        try:
            certificates = x509.load_pem_x509_certificates(ca_certificate_pem)
        except ValueError as error:
            raise ServiceSecurityError("mtls_ca_invalid") from error
        if not 1 <= len(certificates) <= 2:
            raise ServiceSecurityError("mtls_ca_invalid")
        now = datetime.now(timezone.utc)
        for certificate in certificates:
            _validate_ca_certificate(certificate, now=now)
        fingerprints = {
            certificate.fingerprint(hashes.SHA256()) for certificate in certificates
        }
        if len(fingerprints) != len(certificates):
            raise ServiceSecurityError("mtls_ca_invalid")
        self.ca_certificates = tuple(certificates)
        self.trust_domain = trust_domain
        self.allowed_workload_names = frozenset(allowed_workload_names)
        self.max_certificate_lifetime_seconds = max_certificate_lifetime_seconds

    def verify_mtls_peer(self, *, peer_certificate: bytes) -> Mapping[str, Any]:
        try:
            certificate = x509.load_der_x509_certificate(peer_certificate)
        except ValueError as error:
            raise ServiceSecurityError("mtls_peer_invalid") from error
        now = datetime.now(timezone.utc)
        if certificate.not_valid_before_utc > now or certificate.not_valid_after_utc <= now:
            raise ServiceSecurityError("mtls_peer_invalid")
        if (
            certificate.not_valid_after_utc - certificate.not_valid_before_utc
        ).total_seconds() > self.max_certificate_lifetime_seconds:
            raise ServiceSecurityError("mtls_peer_lifetime_invalid")
        matching_ca = next(
            (
                ca
                for ca in self.ca_certificates
                if certificate.issuer == ca.subject
                and _certificate_signature_valid(certificate, ca)
            ),
            None,
        )
        if matching_ca is None:
            raise ServiceSecurityError("mtls_peer_signature_invalid")
        try:
            constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
            key_usage = certificate.extensions.get_extension_for_class(
                x509.KeyUsage
            ).value
            usages = certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
            names = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
        except x509.ExtensionNotFound as error:
            raise ServiceSecurityError("mtls_peer_invalid") from error
        if (
            constraints.ca
            or not key_usage.digital_signature
            or ExtendedKeyUsageOID.CLIENT_AUTH not in usages
        ):
            raise ServiceSecurityError("mtls_peer_invalid")
        prefix = f"spiffe://{self.trust_domain}/workload/"
        uris = tuple(
            str(uri)
            for uri in names.get_values_for_type(x509.UniformResourceIdentifier)
        )
        matches = tuple(uri for uri in uris if uri.startswith(prefix))
        if len(uris) != 1 or len(matches) != 1:
            raise ServiceSecurityError("mtls_workload_identity_invalid")
        workload_name = matches[0][len(prefix) :]
        if (
            not _ROLE.fullmatch(workload_name)
            or workload_name not in self.allowed_workload_names
        ):
            raise ServiceSecurityError("mtls_workload_identity_invalid")
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        return {
            "workload_identity": f"workload_{workload_name}",
            "spiffe_id": matches[0],
            "certificate_fingerprint": f"sha256:{fingerprint}",
            "trust_anchor_fingerprint": "sha256:"
            + matching_ca.fingerprint(hashes.SHA256()).hex(),
            "not_after": certificate.not_valid_after_utc.isoformat(),
        }


class Ed25519EvaluationGrantSigner:
    def __init__(self, *, private_key_pem: bytes, key_id: str) -> None:
        if not _ROLE.fullmatch(key_id):
            raise ServiceSecurityError("grant_signing_key_id_invalid")
        try:
            key = serialization.load_pem_private_key(private_key_pem, password=None)
        except (TypeError, ValueError) as error:
            raise ServiceSecurityError("grant_signing_key_invalid") from error
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise ServiceSecurityError("grant_signing_key_invalid")
        self._key = key
        self.key_id = key_id
        public_der = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key_digest = "sha256:" + hashlib.sha256(public_der).hexdigest()

    def sign_grant(self, *, canonical_grant: bytes, key_id: str) -> str:
        if key_id != self.key_id:
            raise ServiceSecurityError("grant_signing_request_invalid")
        _validate_short_lived_grant(canonical_grant)
        signature = self._key.sign(canonical_grant)
        return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")

    def public_metadata(self) -> Mapping[str, Any]:
        return {
            "algorithm": "EdDSA",
            "key_id": self.key_id,
            "public_key_digest": self.public_key_digest,
            "private_key_exportable_via_api": False,
        }

    def public_key_pem(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class Ed25519EvaluationGrantVerifier:
    """Verify the exact short-lived Grant envelope accepted by a Runner."""

    def __init__(self, *, public_key_pem: bytes, key_id: str) -> None:
        if not _ROLE.fullmatch(key_id):
            raise ServiceSecurityError("grant_signing_key_id_invalid")
        try:
            key = serialization.load_pem_public_key(public_key_pem)
        except (TypeError, ValueError) as error:
            raise ServiceSecurityError("grant_verification_key_invalid") from error
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise ServiceSecurityError("grant_verification_key_invalid")
        self._key = key
        self.key_id = key_id

    def verify_grant(
        self, *, canonical_grant: bytes, key_id: str, signature: str
    ) -> Mapping[str, Any]:
        if key_id != self.key_id or not isinstance(signature, str):
            raise ServiceSecurityError("grant_signature_invalid")
        _validate_short_lived_grant(canonical_grant)
        try:
            padding = "=" * (-len(signature) % 4)
            decoded = base64.urlsafe_b64decode(signature + padding)
            self._key.verify(decoded, canonical_grant)
        except (ValueError, InvalidSignature) as error:
            raise ServiceSecurityError("grant_signature_invalid") from error
        return json.loads(canonical_grant)


def _validate_short_lived_grant(canonical_grant: bytes) -> None:
    if not 1 <= len(canonical_grant) <= 256 * 1024:
        raise ServiceSecurityError("grant_signing_request_invalid")
    try:
        value = json.loads(
            canonical_grant,
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: _reject_json_constant(),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ServiceSecurityError("grant_signing_request_invalid") from error
    expected = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    metadata = value.get("metadata") if isinstance(value, dict) else None
    evidence_status = metadata.get("evidence_status")
    synthetic_only = metadata.get("synthetic_only")
    spec = value.get("spec")
    authority_valid = isinstance(spec, dict) and (
        (
            synthetic_only is True
            and evidence_status == "synthetic"
            and spec == {}
        )
        or (
            spec.get("production_authorization") is False
            and spec.get("release_authorization") is False
        )
    )
    if (
        expected != canonical_grant
        or value.get("kind") != "ExecutionGrant"
        or not isinstance(metadata, dict)
        or metadata.get("status") != "active"
        or evidence_status not in {"synthetic", "public"}
        or type(synthetic_only) is not bool
        or (synthetic_only is False and evidence_status != "public")
        or not authority_valid
    ):
        raise ServiceSecurityError("grant_signing_request_invalid")
    issued_at = _date_time(metadata.get("issued_at"), "grant_issued_at_invalid")
    expires_at = _date_time(metadata.get("expires_at"), "grant_expiry_invalid")
    lifetime = (expires_at - issued_at).total_seconds()
    if not 0 < lifetime <= 900:
        raise ServiceSecurityError("grant_lifetime_invalid")


def _numeric_date(value: Any, reason_code: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ServiceSecurityError(reason_code)
    return float(value)


def _date_time(value: Any, reason_code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ServiceSecurityError(reason_code)
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ServiceSecurityError(reason_code) from error


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_key")
        value[key] = item
    return value


def _reject_json_constant() -> None:
    raise ValueError("nonfinite_number")


def _validate_ca_certificate(
    certificate: x509.Certificate, *, now: datetime
) -> None:
    try:
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as error:
        raise ServiceSecurityError("mtls_ca_invalid") from error
    if (
        not constraints.ca
        or constraints.path_length != 0
        or not key_usage.key_cert_sign
        or certificate.not_valid_before_utc > now
        or certificate.not_valid_after_utc <= now
    ):
        raise ServiceSecurityError("mtls_ca_invalid")


def _certificate_signature_valid(
    certificate: x509.Certificate, ca_certificate: x509.Certificate
) -> bool:
    try:
        _verify_certificate_signature(certificate, ca_certificate)
    except ServiceSecurityError:
        return False
    return True


def _verify_certificate_signature(
    certificate: x509.Certificate, ca_certificate: x509.Certificate
) -> None:
    key = ca_certificate.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm),
            )
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(certificate.signature, certificate.tbs_certificate_bytes)
        else:
            raise ServiceSecurityError("mtls_ca_key_unsupported")
    except InvalidSignature as error:
        raise ServiceSecurityError("mtls_peer_signature_invalid") from error

