#!/usr/bin/env python3
"""Validate disposable CI scope and derive exactly one APK fixture certificate digest."""
import hashlib
import os
from pathlib import Path
import ssl
import sys
import zipfile


def fingerprint(apk, env):
    if env.get('GITHUB_ACTIONS') != 'true' or not env.get('RUNNER_TEMP'):
        raise ValueError('temporary GitHub Actions runner required')
    scopes = {'emulator-5580': 'peerloom-ci-4096', 'emulator-5582': 'peerloom-ci-16384'}
    expected = scopes.get(env.get('ANDROID_SERIAL'))
    if expected is None or expected != env.get('PEERLOOM_AVD_NAME'):
        raise ValueError('refuse non-owned emulator scope')
    with zipfile.ZipFile(apk) as data:
        items = [item for item in data.infolist() if item.filename == 'res/raw/peerloom_test_ca.pem']
        if len(items) != 1 or items[0].file_size > 16384:
            raise ValueError('expected exactly one bounded fixture CA')
        der = ssl.PEM_cert_to_DER_cert(data.read(items[0]).decode('ascii'))
    return hashlib.sha256(der).hexdigest()


if __name__ == '__main__':
    print(fingerprint(Path(sys.argv[1]), os.environ))
