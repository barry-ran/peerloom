#!/usr/bin/env python3
import importlib.util
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('trust', ROOT / 'trust-fixture.py')
trust = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trust)


class TrustFixtureTest(unittest.TestCase):
    def test_scope_refuses_host_foreign_serial_and_avd(self):
        valid = dict(GITHUB_ACTIONS='true', RUNNER_TEMP='/tmp/ci', ANDROID_SERIAL='emulator-5580', PEERLOOM_AVD_NAME='peerloom-ci-4096')
        for key, wrong in [('GITHUB_ACTIONS', 'false'), ('RUNNER_TEMP', ''), ('ANDROID_SERIAL', 'physical-device'), ('PEERLOOM_AVD_NAME', 'other')]:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    trust.fingerprint('/not/read.apk', {**valid, key: wrong})

        with self.assertRaises(ValueError):
            trust.fingerprint('/not/read.apk', {'GITHUB_ACTIONS': 'true', 'RUNNER_TEMP': '/tmp/ci'})

    def test_cleanup_orders_exact_ca_before_admin_even_tls_failure(self):
        for cleanup_fails in (False, True):
            with self.subTest(cleanup_fails=cleanup_fails), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                scripts = root / 'bindings/android/scripts'
                scripts.mkdir(parents=True)
                for name in ('run-instrumentation.sh', 'trust-fixture.py', 'sanitize-diagnostics.py'):
                    (scripts / name).write_bytes((ROOT / name).read_bytes())
                dist = root / 'dist/android'
                dist.mkdir(parents=True)
                with zipfile.ZipFile(dist / 'library-debug-androidTest.apk', 'w') as apk:
                    apk.writestr('res/raw/peerloom_test_ca.pem', ssl.DER_cert_to_PEM_cert(b'public fixture'))
                commands = root / 'commands'
                adb = root / 'adb'
                adb.write_text('''#!/usr/bin/env python3
import os, sys
args=sys.argv[1:]
with open(os.environ['COMMANDS'], 'a') as out: out.write(' '.join(args)+'\\n')
if args[2:]==['emu','avd','name']: print('peerloom-ci-4096\\nOK')
elif 'getprop' in args: print('1')
elif 'instrument' in args:
 name=args[args.index('class')+1]
 failed=name.endswith('.TlsTest') or (name.endswith('TrustFixtureTest#remove') and os.environ['CLEANUP_FAIL']=='1')
 print('FAILURES!!!' if failed else 'OK (1 test)')
''')
                adb.chmod(0o755)
                env = {**os.environ, 'PATH': str(root)+os.pathsep+os.environ['PATH'], 'COMMANDS': str(commands), 'CLEANUP_FAIL': str(int(cleanup_fails)), 'GITHUB_ACTIONS': 'true', 'RUNNER_TEMP': temp, 'ANDROID_SERIAL': 'emulator-5580', 'PEERLOOM_AVD_NAME': 'peerloom-ci-4096'}
                result = subprocess.run(['bash', str(scripts / 'run-instrumentation.sh')], env=env, capture_output=True, timeout=20)
                self.assertNotEqual(result.returncode, 0)
                log = commands.read_text()
                self.assertIn('dpm set-device-owner --user 0 io.peerloom.sdk.test/io.peerloom.sdk.TestCertificateAdmin', log)
                self.assertIn('TrustFixtureTest#remove', log)
                if cleanup_fails:
                    self.assertNotIn('remove-active-admin', log)
                else:
                    self.assertLess(log.index('TrustFixtureTest#remove'), log.index('remove-active-admin'))
                    self.assertIn('TrustFixtureTest#verifyReleased', log)
                self.assertNotIn('uninstallAll', log)
                self.assertNotIn('adb root', log)


if __name__ == '__main__':
    unittest.main()
