"""Offline regression for delayed launchd removal and exact deployment readback."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import zipfile

from tests.test_lan_host_installation import create_ca

LAN = Path(__file__).resolve().parents[1] / 'deploy/lan-stage1'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), LAN / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


control = load('lan-surface-control')
verify = load('verify-lan-update')
OLD = 'sha256:' + 'a' * 64
NEW = 'sha256:' + 'b' * 64


class FakeHost:
    def __init__(self):
        self.clock = 0
        self.stopping = set()
        self.started = set()
        self.removed = []
        self.bootout_code = 0
        self.bootstrap_code = 0
        self.initially_absent = False
        self.digest = OLD

    def validate(self, surface, digests):
        pass

    def job(self, surface):
        if surface in self.started:
            return {'pid': 201, 'state': 'running', 'digest': self.digest}
        if self.initially_absent or surface in self.stopping and self.clock >= 5:
            return None
        return {'pid': 101 if surface == 'human' else 102, 'state': 'running', 'digest': OLD}

    def pid_alive(self, pid):
        return pid in (101, 102) and self.clock < 7

    def command(self, action, *args):
        surface = 'human' if 'human' in args[-1] else 'workload'
        if action == 'bootout':
            self.stopping.add(surface)
            return SimpleNamespace(returncode=self.bootout_code)
        if not self.bootstrap_code:
            self.started.add(surface)
        return SimpleNamespace(returncode=self.bootstrap_code)

    def remove_socket(self, surface):
        self.removed.append((surface, self.clock))

    def healthy(self, surface):
        return self.clock >= 3

    def pause(self):
        self.clock += 1


class LanSurfaceRecoveryTests(unittest.TestCase):
    def test_waits_for_both_job_removal_and_old_process_exit(self):
        host = FakeHost()
        saved = []
        control.stop(host, {OLD}, remember=lambda pids: saved.extend(pids))
        self.assertEqual([101, 102], saved)
        self.assertEqual([('human', 7), ('workload', 7)], host.removed)

    def test_timeout_does_not_unlink_live_sockets(self):
        host = FakeHost()
        with self.assertRaisesRegex(control.SurfaceError, 'stop_timeout'):
            control.stop(host, {OLD}, attempts=4)
        self.assertEqual([], host.removed)
        self.assertEqual(set(), host.started)

    def test_rollback_retains_pid_evidence_after_job_has_disappeared(self):
        host = FakeHost()
        host.initially_absent = True
        control.stop(host, {OLD}, retained_pids=[101, 102])
        self.assertEqual([('human', 7), ('workload', 7)], host.removed)

    def test_bootout_failure_is_not_suppressed(self):
        host = FakeHost()
        host.bootout_code = 5
        with self.assertRaisesRegex(control.SurfaceError, 'bootout_failed:workload:5'):
            control.stop(host, {OLD})
        self.assertEqual([], host.removed)

    def test_wrong_running_digest_is_rejected_before_stop(self):
        host = FakeHost()
        with self.assertRaisesRegex(control.SurfaceError, 'running_service_digest_drift'):
            control.stop(host, {NEW})
        self.assertEqual(set(), host.stopping)

    def test_start_needs_both_services_health_and_exact_digest(self):
        host = FakeHost()
        host.initially_absent = True
        host.digest = NEW
        control.start(host, NEW)
        self.assertEqual(3, host.clock)
        self.assertTrue(control.check(host, NEW))
        self.assertFalse(control.check(host, OLD))

    def test_bootstrap_failure_is_explicit_and_never_reports_started(self):
        host = FakeHost()
        host.initially_absent = True
        host.bootstrap_code = 5
        with self.assertRaisesRegex(control.SurfaceError, 'bootstrap_failed:human:5'):
            control.start(host, NEW)
        self.assertEqual(set(), host.started)


class Response(io.BytesIO):
    status = 200

    def __init__(self, url, body):
        super().__init__(body)
        self.url = url

    def geturl(self):
        return self.url


class LanUpdateReadbackTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.web = self.root / 'web'
        (self.web / 'assets').mkdir(parents=True)
        (self.web / 'index.html').write_text('<script src="/assets/new.js"></script><link rel="stylesheet" href="/assets/new.css">')
        script = b'export const title="new wording";'
        (self.web / 'assets/new.js').write_bytes(script)
        (self.web / 'assets/new.css').write_text('body { color: black; }')
        (self.web / 'orbit-build-evidence.json').write_text(json.dumps({
            'schema_version': 'orbit.cockpit-build-evidence/1', 'data_mode': 'bff',
            'entrypoints': ['assets/new.js'],
            'javascript': [{'path': 'assets/new.js', 'sha256': 'sha256:' + hashlib.sha256(script).hexdigest()}],
        }))
        self.ca = self.root / 'ca.pem'
        create_ca(self.ca, 'synthetic-update-test-ca')

    def opener(self, url, **kwargs):
        relative = url.removeprefix(verify.ORIGIN + '/')
        path = self.web / ('index.html' if relative == 'control' else relative)
        return Response(url, path.read_bytes())

    def test_new_copy_is_accepted_by_bytes_including_styles_not_wording(self):
        result = verify.verify_served(self.web, self.ca, self.opener)
        self.assertEqual(4, result['served_files_verified'])

    def test_old_script_or_stylesheet_is_rejected_even_with_healthy_http(self):
        for suffix in ('new.js', 'new.css'):
            def opener(url, **kwargs):
                return Response(url, b'old deployment') if url.endswith(suffix) else self.opener(url)
            with self.assertRaisesRegex(RuntimeError, 'served_frontend_bytes_mismatch'):
                verify.verify_served(self.web, self.ca, opener)

    def devices(self, lock, embedded=None):
        for department in verify.DEPARTMENTS:
            path = self.root / 'department-device' / department / lock[7:] / 'bundle.zip'
            path.parent.mkdir(parents=True, exist_ok=True)
            content = b'synthetic device script'
            manifest = {'department_id': department, 'deployment_release_lock_digest': embedded or lock,
                        'files': [{'path': 'setup.txt', 'size': len(content),
                                   'sha256': 'sha256:' + hashlib.sha256(content).hexdigest()}]}
            manifest.update({key: False for key in ('contains_secret', 'runtime_started', 'model_called',
                                                    'production_authorization', 'release_authorization')})
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('artifact-set-manifest.json', json.dumps(manifest))
                archive.writestr('setup.txt', content)

    def test_failed_candidate_bundles_do_not_replace_previous_release(self):
        self.devices(OLD)
        original = verify.verify_devices(self.root, OLD)
        self.devices(NEW)
        self.assertEqual(original, verify.verify_devices(self.root, OLD))
        self.assertEqual(3, len(verify.verify_devices(self.root, NEW)))

    def test_wrong_release_embedded_in_addressed_bundle_is_rejected(self):
        self.devices(OLD, embedded=NEW)
        with self.assertRaisesRegex(RuntimeError, 'device_bundle_release_mismatch'):
            verify.verify_devices(self.root, OLD)


if __name__ == '__main__':
    unittest.main()

