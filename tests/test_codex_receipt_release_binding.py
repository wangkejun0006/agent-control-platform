from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CODEX = ROOT / 'deploy/lan-stage1/codex-cli'
LOCK = 'sha256:' + 'a' * 64


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


class CodexReceiptReleaseBindingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binding = load('receipt_binding_test', CODEX / 'configure-receipt-release.py')
        self.plists = self.root / 'plists'
        self.plists.mkdir()
        self.web = self.root / 'web'
        self.release_root = self.web / 'bootstrap/codex-cli/0.153.0/x86_64-unknown-linux-musl'
        self.release_root.mkdir(parents=True)
        archive_name = 'codex-package-x86_64-unknown-linux-musl.tar.gz'
        archive = b'synthetic distribution test bytes; never executed'
        (self.release_root / archive_name).write_bytes(archive)
        manifest = {
            'schema_version': 'orbit.codex-cli-lan-release/0.1-draft',
            'version': '0.153.0', 'target': 'x86_64-unknown-linux-musl',
            'source': 'official_openai_release',
            'files': [{'name': archive_name, 'size': len(archive),
                       'sha256': 'sha256:' + hashlib.sha256(archive).hexdigest()}],
            'authority_boundary': {name: False for name in (
                'account_logged_in', 'execution_grant_issued', 'lease_issued',
                'model_called', 'production_authorization', 'release_authorization', 'runtime_started')},
        }
        manifest['manifest_digest'] = digest(manifest)
        (self.release_root / 'manifest.json').write_text(json.dumps(manifest))
        self.distribution = {
            'version': manifest['version'], 'target': manifest['target'],
            'release_manifest_digest': manifest['manifest_digest'],
            'archive_digest': manifest['files'][0]['sha256'],
            **{key: False for key in ('account_logged_in', 'runtime_started', 'model_called',
                                     'production_authorization', 'release_authorization')},
        }
        self.inputs = self.root / 'inputs.json'
        self.write_inputs()
        self.environment = self.binding.expected_environment(self.inputs, self.web)
        for surface in self.binding.SURFACES:
            label = 'com.orbit.control-plane-lan-' + surface
            value = {'Label': label, 'UserName': '_orbitcontrolplane',
                     'ProgramArguments': ['unchanged-entrypoint', 'serve', surface],
                     'EnvironmentVariables': {self.binding.LOCK_ENV: LOCK, 'UNRELATED': 'preserved'}}
            (self.plists / (label + '.plist')).write_bytes(plistlib.dumps(value))

    def write_inputs(self):
        value = {'codex_cli_distribution': self.distribution}
        value['inputs_digest'] = digest(value)
        self.inputs.write_text(json.dumps(value))

    def test_rejects_missing_binding_and_loaded_process_with_old_environment(self):
        with self.assertRaisesRegex(RuntimeError, 'missing_or_drifted'):
            self.binding.configure(self.plists, self.environment, LOCK)
        self.binding.configure(self.plists, self.environment, LOCK, apply=True)
        with self.assertRaisesRegex(RuntimeError, 'loaded_environment_drift'):
            self.binding.configure(self.plists, self.environment, LOCK, read_job=lambda _: '')
        output = '\n'.join('  ' + k + ' => ' + v for k, v in
                           {self.binding.LOCK_ENV: LOCK, **self.environment}.items())
        result = self.binding.configure(self.plists, self.environment, LOCK, read_job=lambda _: output)
        self.assertTrue(result['loaded_environment_verified'])

    def test_apply_preserves_unrelated_settings_and_repeats_without_drift(self):
        before = {p.name: plistlib.loads(p.read_bytes()) for p in self.plists.iterdir()}
        self.binding.configure(self.plists, self.environment, LOCK, apply=True)
        first = {p.name: p.read_bytes() for p in self.plists.iterdir()}
        self.binding.configure(self.plists, self.environment, LOCK, apply=True)
        self.assertEqual(first, {p.name: p.read_bytes() for p in self.plists.iterdir()})
        for name, value in before.items():
            value['EnvironmentVariables'].update(self.environment)
            self.assertEqual(value, plistlib.loads(first[name]))

    def test_second_plist_drift_refuses_all_writes(self):
        path = self.plists / 'com.orbit.control-plane-lan-workload.plist'
        value = plistlib.loads(path.read_bytes())
        value['EnvironmentVariables'][self.binding.LOCK_ENV] = 'sha256:' + 'b' * 64
        path.write_bytes(plistlib.dumps(value))
        before = {p.name: p.read_bytes() for p in self.plists.iterdir()}
        with self.assertRaisesRegex(RuntimeError, 'plist_invalid'):
            self.binding.configure(self.plists, self.environment, LOCK, apply=True)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.plists.iterdir()})

    def test_rejects_input_digest_duplicate_keys_and_release_drift(self):
        self.inputs.write_text('{"inputs_digest":"x","inputs_digest":"y"}')
        with self.assertRaisesRegex(RuntimeError, 'duplicate_key'):
            self.binding.expected_environment(self.inputs, self.web)
        self.inputs.write_text('{"inputs_digest":"changed"}')
        with self.assertRaisesRegex(RuntimeError, 'inputs_digest_invalid'):
            self.binding.expected_environment(self.inputs, self.web)
        self.distribution['archive_digest'] = 'sha256:' + 'c' * 64
        self.write_inputs()
        with self.assertRaisesRegex(RuntimeError, 'release_drift'):
            self.binding.expected_environment(self.inputs, self.web)

    def test_rejects_archive_tamper_and_enabled_authority(self):
        self.distribution['model_called'] = True
        self.write_inputs()
        with self.assertRaisesRegex(RuntimeError, 'distribution_invalid'):
            self.binding.expected_environment(self.inputs, self.web)
        self.distribution['model_called'] = False
        self.write_inputs()
        (self.release_root / 'codex-package-x86_64-unknown-linux-musl.tar.gz').write_bytes(b'drift')
        with self.assertRaisesRegex(RuntimeError, 'release_file_invalid'):
            self.binding.expected_environment(self.inputs, self.web)

    def test_unconfigured_receipt_is_retained_then_accepted_after_binding(self):
        from orbit_agent_control_plane.service_runtime.lan_stage1_main import _optional_digest
        fixture = load('receipt_service_fixture', ROOT / 'tests/test_codex_installation.py')
        service = fixture.make_service()
        self.addCleanup(service.database.dispose)
        service.approved_release_manifest_digest = None
        service.approved_archive_digest = None
        runner = load('receipt_binding_runner', ROOT / 'deploy/lan-stage1/department-device/runner/orbit-lan-runner.py')
        runner.CODEX_MANIFEST_DIGEST = self.environment[self.binding.MANIFEST_ENV]
        runner.CODEX_ARCHIVE_DIGEST = self.environment[self.binding.ARCHIVE_ENV]
        value = fixture.receipt(source='recovered_existing_receipt', intermediate=False)
        for key in ('receipt_id', 'attempt_id', 'predecessor_attempt_id', 'department_id',
                    'evidence_source', 'intermediate_events_available', 'observed_at'):
            value.pop(key)
        value.update(release_manifest_digest=runner.CODEX_MANIFEST_DIGEST,
                     archive_digest=runner.CODEX_ARCHIVE_DIGEST)
        state = self.root / 'state'
        state.mkdir(mode=0o700)
        receipt = state / 'codex-cli-installation.json'
        receipt.write_text(json.dumps(value))
        receipt.chmod(0o600)
        config = {'department': {'id': fixture.DEPARTMENT_ID}, 'node': {'node_id': fixture.NODE_ID}}
        runner.recover_existing_codex_receipt(state, config)
        class Client:
            def post(self, endpoint, body, key, timeout):
                result = service.record_receipt(node_id=fixture.NODE_ID, document=body['document'],
                                                idempotency_key=key, workload_identity='synthetic-test-workload')
                return 201, result
        item = next((state / 'codex-installation-events').glob('*.json'))
        queued = item.read_bytes()
        with self.assertRaisesRegex(fixture.CodexInstallationError, 'release_unconfigured'):
            runner.flush_codex_installation_queue(state, config, Client())
        self.assertEqual(queued, item.read_bytes())
        self.binding.configure(self.plists, self.environment, LOCK, apply=True)
        actual = plistlib.loads((self.plists / 'com.orbit.control-plane-lan-workload.plist').read_bytes())
        with patch.dict(os.environ, actual['EnvironmentVariables'], clear=True):
            service.approved_release_manifest_digest = _optional_digest(self.binding.MANIFEST_ENV)
            service.approved_archive_digest = _optional_digest(self.binding.ARCHIVE_ENV)
        self.assertEqual(1, runner.flush_codex_installation_queue(state, config, Client()))
        self.assertFalse(item.exists())
        self.assertEqual(0, runner.flush_codex_installation_queue(state, config, Client()))
        projection = service.projection(department_id=fixture.DEPARTMENT_ID)
        self.assertEqual('complete', projection['overall_status'])
        self.assertFalse(projection['evidence']['intermediate_events_available'])
        self.assertFalse(projection['evidence']['model_called'])

