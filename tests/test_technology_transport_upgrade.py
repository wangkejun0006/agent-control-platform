from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
DEVICE = ROOT / 'deploy/lan-stage1/department-device'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class TechnologyTransportUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.upgrade = module('technology_upgrade_test', DEVICE / 'wsl/upgrade-technology-transport.py')
        self.upgrade.DEVICE = root / 'device'
        self.upgrade.DEVICE.mkdir(mode=0o700)
        self.upgrade.UPDATES = root / 'updates'
        self.upgrade.RUNNER_LOG = root / 'runner.jsonl'
        self.upgrade.RUNNER_LOG.write_text('')
        self.upgrade.RUNNER_LOG.chmod(0o600)
        self.upgrade.require_stopped = lambda: None
        self.config = {
            'schema_version': 'orbit.department-device-pilot/0.1',
            'evidence_status': 'synthetic_lan_d0_candidate',
            'server': {'address': '192.168.21.22', 'human_origin': self.upgrade.ORIGIN,
                       'workload_origin': 'https://control-plane.orbit.local:9443'},
            'department': {'id': 'technology_center'},
            'node': {'node_id': 'node_technology_001',
                     'workload_identity': 'workload_node_technology_001',
                     'deployment_instance_ref': 'artifact://deployment-instances/technology_center-lan-d0',
                     'workload_scope': {'department_ids': ['technology_center'],
                                        'agent_bindings': [{
                                            'id': 'agent_binding_technology_professional_syn',
                                            'digest': 'sha256:' + '2' * 64}]}},
            'deployment_release_lock_digest': 'sha256:' + 'a' * 64,
            **{key: False for key in self.upgrade.FLAGS},
        }
        self.write_config(self.config)
        legacy = subprocess.check_output([
            'git', 'show', '9f9e4163d426:deploy/lan-stage1/department-device/runner/orbit-lan-runner.py'], cwd=ROOT)
        self.upgrade.atomic(self.upgrade.DEVICE / 'orbit-lan-runner.py', legacy, 0o555)
        self.before = {p.name: p.read_bytes() for p in self.upgrade.DEVICE.iterdir()}
        self.assets = {asset: (DEVICE / 'runner' / name).read_bytes()
                       for name, (asset, _, _) in self.upgrade.FILES.items()}

    def write_config(self, value):
        self.upgrade.atomic(self.upgrade.DEVICE / 'device-config.json',
                            json.dumps(value).encode(), 0o444)

    def prepare(self):
        return self.upgrade.prepare(self.assets.__getitem__)['update_id']

    def test_rejects_wrong_department_extra_scope_and_import_before_network(self):
        cases = [
            {**self.config, 'department': {'id': 'product_center'}},
            {**self.config, 'runtime_artifact_import': {**self.upgrade.DISABLED_IMPORT, 'enabled': True}},
            {**self.config, 'model_called': True},
            {**self.config, 'node': {**self.config['node'], 'workload_scope': {'department_ids': ['technology_center', 'product_center']}}},
        ]
        for value in cases:
            with self.subTest(value=value):
                self.write_config(value)
                with self.assertRaises(RuntimeError):
                    self.upgrade.prepare(lambda _: self.fail('network before validation'))
        self.assertFalse(self.upgrade.UPDATES.exists())

    def test_rejects_drift_without_replacing_current_files(self):
        with self.assertRaisesRegex(RuntimeError, 'payload_digest_mismatch'):
            self.upgrade.prepare(lambda _: b'changed source')
        self.assertEqual(self.before, {p.name: p.read_bytes() for p in self.upgrade.DEVICE.iterdir()})

    def test_rejects_symlink_duplicate_keys_and_unreviewed_runner(self):
        with self.assertRaisesRegex(RuntimeError, 'duplicate_json_key'):
            self.upgrade.compatible_config(b'{"a":1,"a":2}')
        runner = self.upgrade.DEVICE / 'orbit-lan-runner.py'
        runner.unlink()
        runner.symlink_to(self.upgrade.DEVICE / 'device-config.json')
        with self.assertRaisesRegex(RuntimeError, 'file_invalid'):
            self.prepare()
        runner.unlink()
        self.upgrade.atomic(runner, b'unreviewed', 0o555)
        with self.assertRaisesRegex(RuntimeError, 'not_reviewed'):
            self.prepare()

    def test_prepare_preserves_current_bytes_apply_is_disabled_and_repeat_is_noop(self):
        update_id = self.prepare()
        self.assertEqual(self.before, {p.name: p.read_bytes() for p in self.upgrade.DEVICE.iterdir()})
        with self.assertRaisesRegex(RuntimeError, 'unfinished'):
            self.prepare()
        self.upgrade.apply(update_id)
        config = json.loads((self.upgrade.DEVICE / 'device-config.json').read_bytes())
        self.assertEqual(self.upgrade.DISABLED_IMPORT, config.pop('runtime_artifact_import'))
        self.assertEqual(self.config, config)
        with self.assertRaisesRegex(RuntimeError, 'unfinished'):
            self.upgrade.prepare(lambda _: self.fail('no redundant download'))
        self.assertEqual('waiting_for_two_heartbeats', self.upgrade.verify(update_id)['status'])

    def test_refuses_apply_if_process_or_target_changed(self):
        update_id = self.prepare()
        self.upgrade.require_stopped = lambda: (_ for _ in ()).throw(RuntimeError('still_running'))
        with self.assertRaisesRegex(RuntimeError, 'still_running'):
            self.upgrade.apply(update_id)
        self.upgrade.require_stopped = lambda: None
        self.write_config({**self.config, 'evidence_status': 'changed'})
        with self.assertRaisesRegex(RuntimeError, 'changed_since_prepare'):
            self.upgrade.apply(update_id)

    def test_partial_swap_failure_restores_exact_bytes_and_modes(self):
        update_id = self.prepare()
        original = self.upgrade.atomic
        failed = False
        def fail_once(path, raw, mode=0o600):
            nonlocal failed
            if path == self.upgrade.DEVICE / 'device-config.json' and not failed:
                failed = True
                raise OSError('simulated disk failure')
            return original(path, raw, mode)
        with patch.object(self.upgrade, 'atomic', side_effect=fail_once):
            with self.assertRaisesRegex(OSError, 'simulated'):
                self.upgrade.apply(update_id)
        self.assertEqual('rolled_back', self.upgrade.load(update_id)['status'])
        self.assertEqual(self.before, {p.name: p.read_bytes() for p in self.upgrade.DEVICE.iterdir()})
        self.assertEqual(0o555, (self.upgrade.DEVICE / 'orbit-lan-runner.py').stat().st_mode & 0o777)

    def test_tampered_backup_or_concurrent_edit_is_not_silently_restored(self):
        update_id = self.prepare()
        self.upgrade.apply(update_id)
        backup = self.upgrade.UPDATES / update_id / 'before/orbit-lan-runner.py'
        backup.write_bytes(b'tampered')
        with self.assertRaisesRegex(RuntimeError, 'backup_digest_mismatch'):
            self.upgrade.rollback(update_id)
        backup.write_bytes(self.before['orbit-lan-runner.py'])
        self.write_config({**self.config, 'other_task': True})
        with self.assertRaisesRegex(RuntimeError, 'changed_before_rollback'):
            self.upgrade.rollback(update_id)

    def write_heartbeats(self, *, old=False, duplicate=False, model=False):
        start = datetime.now(timezone.utc) - timedelta(seconds=2 if not old else 500)
        values = []
        for index in range(2):
            values.append({'status': 'transport_ready', 'node_id': 'node_technology_001',
                           'observed_at': (start + timedelta(seconds=index)).isoformat(),
                           'heartbeat_sequence': 3000 + (0 if duplicate else index),
                           'transport_mode': 'heartbeat_only', 'lease_status': 'not_polled',
                           'runtime_started': False, 'model_called': model,
                           'production_authorization': False, 'release_authorization': False,
                           'qualification_probe_executed': False})
        self.upgrade.RUNNER_LOG.write_text(''.join(json.dumps(v) + '\n' for v in values))

    def test_commit_requires_two_new_fresh_increasing_heartbeats(self):
        update_id = self.prepare()
        self.upgrade.apply(update_id)
        record = self.upgrade.load(update_id)
        record['applied_at'] = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
        self.upgrade.save(record)
        for options in ({'old': True}, {'duplicate': True}, {'model': True}):
            self.write_heartbeats(**options)
            with self.assertRaisesRegex(RuntimeError, 'not_healthy'):
                self.upgrade.commit(update_id)
        self.write_heartbeats()
        self.assertEqual('complete', self.upgrade.commit(update_id)['status'])
        self.assertEqual('already_current', self.upgrade.prepare(lambda _: self.fail('no redundant download'))['status'])
        with self.assertRaisesRegex(RuntimeError, 'rollback_state_invalid'):
            self.upgrade.rollback(update_id)

    def test_failed_upload_keeps_recovered_receipt_and_retry_does_not_invent_stages(self):
        runner = module('technology_receipt_runner', DEVICE / 'runner/orbit-lan-runner.py')
        receipt = {'schema_version': 'orbit.codex-cli-installation-receipt/0.1-draft',
                   'status': 'codex_cli_installed', 'version': runner.CODEX_VERSION,
                   'target': runner.CODEX_TARGET, 'release_manifest_digest': runner.CODEX_MANIFEST_DIGEST,
                   'archive_digest': runner.CODEX_ARCHIVE_DIGEST,
                   **{key: False for key in ('credential_present', 'account_logged_in',
                       'execution_grant_issued', 'lease_issued', 'runtime_started', 'model_called',
                       'production_authorization', 'release_authorization')}}
        state = Path(self.temp.name) / 'state'
        state.mkdir(mode=0o700)
        path = state / 'codex-cli-installation.json'
        path.write_text(json.dumps(receipt))
        path.chmod(0o600)
        runner.recover_existing_codex_receipt(state, self.config)
        queue = state / 'codex-installation-events'
        item = next(queue.glob('*.json'))
        original = item.read_bytes()
        class Client:
            failed = True
            def post(self, endpoint, body, key, timeout):
                if self.failed:
                    raise OSError('synthetic connection lost')
                self.received = (endpoint, body, key)
                return 201, {'accepted': True}
        client = Client()
        with self.assertRaises(OSError):
            runner.flush_codex_installation_queue(state, self.config, client)
        self.assertEqual(original, item.read_bytes())
        runner.recover_existing_codex_receipt(state, self.config)
        self.assertEqual(1, len(list(queue.glob('*.json'))))
        client.failed = False
        self.assertEqual(1, runner.flush_codex_installation_queue(state, self.config, client))
        document = client.received[1]['document']
        self.assertEqual('recovered_existing_receipt', document['evidence_source'])
        self.assertFalse(document['intermediate_events_available'])
        self.assertFalse(item.exists())
        self.assertEqual(receipt, json.loads(path.read_bytes()))
        runner.recover_existing_codex_receipt(state, self.config)
        self.assertEqual([], list(queue.glob('*.json')))

    def test_powershell_updater_pins_helper_and_uses_only_dedicated_task(self):
        raw = (DEVICE / 'Update-OrbitTechnologyTransport.ps1').read_bytes()
        self.assertTrue(raw.startswith(b'\xef\xbb\xbf'))
        script = raw.decode('utf-8-sig')
        digest = hashlib.sha256((DEVICE / 'wsl/upgrade-technology-transport.py').read_bytes()).hexdigest()
        self.assertIn(digest, script)
        self.assertIn('"--distribution", $Distro', script)
        self.assertIn('$Task.Actions[0].Arguments.Trim() -ne $ExpectedArguments', script)
        self.assertIn('Wait-Transport', script)
        self.assertNotIn('Register-ScheduledTask', script)
        self.assertNotIn('SkipCertificateCheck', script)
        self.assertNotIn('codex login', script)

    def test_install_chain_and_published_payload_pins_must_match(self):
        gate = module('technology_pins', ROOT / 'deploy/lan-stage1/verify-transport-bootstrap.py')
        web = Path(self.temp.name) / 'bootstrap'
        web.mkdir()
        for relative, asset in gate.ASSETS.items():
            (web / asset).write_bytes((DEVICE / relative).read_bytes())
        self.assertEqual('transport_bootstrap_verified', gate.verify(ROOT, web)['status'])
        (web / 'orbit-lan-runner-v7.py').write_bytes(b'old version from previous release')
        with self.assertRaisesRegex(RuntimeError, 'served_payload_mismatch'):
            gate.verify(ROOT, web)
        source = Path(self.temp.name) / 'source'
        for relative in {item for script, _, payload in gate.LINKS for item in (script, payload)} | {
                'wsl/upgrade-technology-transport.py', 'runner/orbit_runtime_artifact_importer.py'}:
            target = source / gate.DEVICE / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((DEVICE / relative).read_bytes())
        target = source / gate.DEVICE / 'Install-OrbitWslRunner.ps1'
        target.write_bytes(target.read_bytes().replace(
            self.upgrade.FILES['orbit-lan-runner.py'][1].encode(), self.upgrade.LEGACY_RUNNER.encode()))
        with self.assertRaisesRegex(RuntimeError, 'pin_mismatch'):
            gate.verify(source)
        target.write_bytes((DEVICE / 'Install-OrbitWslRunner.ps1').read_bytes())
        writer = source / gate.DEVICE / 'wsl/write-bundle-file.py'
        original_digest = hashlib.sha256(writer.read_bytes()).hexdigest()
        writer.write_bytes(writer.read_bytes().replace(
            b'    "/opt/orbit-device-pilot/runtime-artifact-verification-public.pem": 0o444,\n', b''))
        target.write_bytes(target.read_bytes().replace(original_digest.encode(), hashlib.sha256(writer.read_bytes()).hexdigest().encode()))
        with self.assertRaisesRegex(RuntimeError, 'writer_target_missing'):
            gate.verify(source)

