#!/usr/bin/env python3
"""仅控制本次 CI AVD/Compose 的有限断线与真实定向授权撤销；秘密不进入 APK。"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

PACKAGE = 'io.peerloom.sdk.test'
REQUEST = 'no_backup/acceptance-request'
REPLY = 'no_backup/acceptance-reply'
PHASES = ('network_pause', 'network_resume', 'revoke_grant')


def require(value, label):
    if not value:
        raise RuntimeError(label)


def private_pair(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == os.getuid(), 'pair must be current-user private regular file')
        data = stream.read(65537)
    require(len(data) <= 65536, 'pair exceeds bound')
    value = json.loads(data)
    return tuple(str(uuid.UUID(value[role]['device_id'])) for role in ('source', 'target'))


class Controller:
    def __init__(self, root, serial, avd, project, client, credential, pair, run=subprocess.run):
        require(os.environ.get('GITHUB_ACTIONS') == 'true', 'CI-only fixture')
        require(re.fullmatch(r'emulator-[0-9]{4,5}', serial), 'invalid owned serial')
        require(re.fullmatch(r'peerloom-[A-Za-z0-9_-]+', avd), 'invalid owned AVD')
        require(re.fullmatch(r'peerloom-android-[0-9]+-[0-9]+', project), 'invalid owned Compose project')
        self.root, self.serial, self.avd, self.project = root, serial, avd, project
        self.client, self.credential, self.pair, self.run = client, credential, pair, run
        self.paused = False
        self.pause_time = 0.0
        self.index = 0
        self.previous = ''

    def command(self, args, **kwargs):
        return self.run(args, check=True, timeout=20, capture_output=True, **kwargs)

    def owned(self):
        value = self.command(['adb', '-s', self.serial, 'emu', 'avd', 'name']).stdout.decode().splitlines()
        require(value and value[0].strip() == self.avd, 'foreign emulator refused')

    def adb(self, args, **kwargs):
        self.owned()
        return self.command(['adb', '-s', self.serial, *args], **kwargs)

    def compose(self, args):
        self.owned()
        return self.command(['docker', 'compose', '-p', self.project, '-f', str(self.root / 'infra/compose.yaml'),
                             '-f', str(self.root / 'infra/compose.ci.yaml'), *args])

    def reply(self, phase):
        require(phase in PHASES, 'unknown reply')
        self.adb(['shell', f"run-as {PACKAGE} sh -c 'umask 077; cat > {REPLY}'"], input=(phase + '\n').encode())

    def select(self, route):
        page = self.client.request('GET', '/v1/' + route + '?limit=100', 200, self.credential)
        require(not page.get('next_cursor'), 'fresh fixture unexpectedly exceeds one page')
        return [item for item in page['items'] if (item['source_device_id'], item['target_device_id']) == self.pair]

    def revoke(self):
        grants = [item for item in self.select('connection-grants') if item.get('revoked_at') is None]
        require(len(grants) == 1, 'expected exact directed active grant')
        grant = str(uuid.UUID(grants[0]['id']))
        sessions = [item for item in self.select('sessions') if item['state'] != 'closed']
        require(len(sessions) == 1 and sessions[0].get('grant_id') == grant, 'expected exact live authorized session')
        session = str(uuid.UUID(sessions[0]['id']))
        result = self.client.request('DELETE', '/v1/connection-grants/' + grant, 200, self.credential,
                                     key='android-revoke-' + uuid.uuid4().hex)
        require(result.get('revoked') is True, 'grant revocation not accepted')
        stored = self.client.request('GET', '/v1/connection-grants/' + grant, 200, self.credential)
        require(stored.get('revoked_at') is not None
                and (stored['source_device_id'], stored['target_device_id']) == self.pair,
                'grant revocation not persisted in exact scope')
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            state = self.client.request('GET', '/v1/sessions/' + session, 200, self.credential)
            require((state['source_device_id'], state['target_device_id']) == self.pair
                    and state.get('grant_id') == grant, 'session scope mismatch')
            if state['state'] == 'closed':
                require(state.get('close_reason') == 'GRANT_REVOKED', 'session closed for a different reason')
                return
            time.sleep(0.1)
        raise RuntimeError('revoked session did not close')

    def step(self, phase):
        if phase in ('', self.previous):
            return
        require(self.index < len(PHASES) and phase == PHASES[self.index], 'unexpected marker phase')
        if phase == 'network_pause':
            # Mark before attempting the mutation: even a command timeout requires restoration.
            self.paused = True
            self.compose(['stop', '-t', '1', 'gateway'])
            self.pause_time = time.monotonic()
        elif phase == 'network_resume':
            time.sleep(max(0, 3 - (time.monotonic() - self.pause_time)))
            self.compose(['start', 'gateway'])
            self.paused = False
        else:
            self.revoke()
        self.reply(phase)
        self.previous = phase
        self.index += 1

    def execute(self):
        deadline = time.monotonic() + 150
        try:
            while self.index < len(PHASES):
                require(time.monotonic() < deadline, 'acceptance controller deadline')
                value = self.adb(['shell', f'run-as {PACKAGE} head -c 33 {REQUEST}']).stdout
                require(len(value) <= 32, 'marker exceeds bound')
                self.step(value.decode().strip())
                if self.paused:
                    require(time.monotonic() - self.pause_time < 12, 'control-plane outage exceeds bound')
                time.sleep(0.1)
            print('Android owned control-plane outage and exact grant/session revocation verified')
        finally:
            if self.paused:
                self.compose(['start', 'gateway'])
                self.paused = False


def install_shutdown_handlers():
    def interrupted(_signum, _frame):
        # The first signal initiates finally; another must not interrupt bounded restoration.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise RuntimeError('controller interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'serial', 'avd', 'project', 'admin-fixture', 'pair-fixture'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    root = Path(args.root).resolve()
    spec = importlib.util.spec_from_file_location('management', root / 'scripts/test-management.py')
    management = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(management)
    install_shutdown_handlers()
    try:
        Controller(root, args.serial, args.avd, args.project, management.Client('http://127.0.0.1:18080'),
                   management.read_fixture(args.admin_fixture), private_pair(args.pair_fixture)).execute()
        return 0
    except Exception:
        print('Android acceptance controller failed; secret details suppressed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
