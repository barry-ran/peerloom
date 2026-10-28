#!/usr/bin/env python3
"""Only fault the caller's verified disposable Compose services; never delete volumes."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
FILES = ('infra/compose.yaml', 'infra/compose.ci.yaml', 'infra/compose.ci-relay.yaml')


def run(args, **kw):
    return subprocess.run(args, check=True, timeout=45, cwd=ROOT,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)


def compose(project):
    if not re.fullmatch(r'peerloom-test-[0-9]+-[0-9]+', project):
        raise ValueError('not a disposable project')
    args = ['docker', 'compose', '-p', project]
    for file in FILES:
        args += ['-f', file]
    return args


def verify_owner(command, project, service):
    if service not in ('device-server', 'redis'):
        raise ValueError('unsupported fault service')
    ids = run(command + ['ps', '-a', '-q', service]).stdout.decode().split()
    if len(ids) != 1 or not re.fullmatch('[a-f0-9]{12,64}', ids[0]):
        raise ValueError('expected one owned container')
    data = json.loads(run(['docker', 'inspect', ids[0]]).stdout)
    labels = data[0]['Config']['Labels']
    if labels.get('com.docker.compose.project') != project or labels.get('com.docker.compose.service') != service:
        raise ValueError('container ownership mismatch')
    return ids[0]


def wait_marker(directory, name, process, seconds):
    deadline = time.monotonic() + seconds
    while not (directory / name).is_file():
        if process.poll() is not None:
            raise RuntimeError('SDK test exited before fault handshake')
        if time.monotonic() >= deadline:
            raise TimeoutError('fault handshake deadline')
        time.sleep(0.05)


def reap(process):
    if process is not None and process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def scenario(command, project, service, base_url, admin, directory):
    fixture = directory / 'pair.json'
    run([sys.executable, 'scripts/prepare-lifecycle-fixture.py', '--base-url', base_url,
         '--admin-fixture', admin, '--pair-output', str(fixture)])
    verify_owner(command, project, service)
    env = dict(os.environ, TEST_IDENTITY_BASE_URL=base_url,
               TEST_SIGNAL_FIXTURE_FILE=str(fixture), TEST_LEASE_ADMIN_FIXTURE=admin,
               TEST_CONTROL_FAULT=service, TEST_CONTROL_DIRECTORY=str(directory))
    env.pop('TEST_MANAGED_RELAY', None)
    process = None
    touched = False
    try:
        process = subprocess.Popen(['cargo', 'test', '--manifest-path', 'src/device-sdk/Cargo.toml',
                                    '-p', 'device-core', '--test', 'sdk_control_recovery', '--locked',
                                    '--', '--ignored', '--nocapture'], cwd=ROOT, env=env, start_new_session=True)
        wait_marker(directory, 'ready', process, 180)
        verify_owner(command, project, service)
        # A timeout can be an uncertain stop; mark ownership before invoking it.
        touched = True
        run(command + ['stop', '-t', '1', service])
        (directory / 'down').write_text('down')
        if service == 'device-server':
            wait_marker(directory, 'expired', process, 110)
        else:
            time.sleep(10)  # one controlled outage, not retrying a failed SDK assertion
        run(command + ['up', '-d', '--no-deps', '--wait', service])
        (directory / 'up').write_text('up')
        if process.wait(timeout=100) != 0:
            raise RuntimeError('real SDK recovery assertion failed')
    finally:
        try:
            reap(process)
        finally:
            if touched:
                # Restore even if child cleanup failed; never down/wipe.
                verify_owner(command, project, service)
                run(command + ['up', '-d', '--no-deps', '--wait', service])


def install_interrupt_handlers():
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    def interrupted(_signal, _frame):
        # The first cancellation enters finally; repeated cancellations cannot bypass cleanup.
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        raise InterruptedError('fault controller interrupted')
    for sig in previous:
        signal.signal(sig, interrupted)
    return previous


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True)
    parser.add_argument('--base-url', required=True, choices=['http://127.0.0.1:18080'])
    parser.add_argument('--admin-fixture', required=True)
    args = parser.parse_args()
    command = compose(args.project)
    admin = Path(args.admin_fixture).absolute()
    if admin.is_symlink() or not admin.is_file() or admin.stat().st_mode & 0o777 != 0o600:
        raise ValueError('private admin fixture required')
    for service in ('device-server', 'redis'):
        with tempfile.TemporaryDirectory(prefix='peerloom-control-fault-') as temporary:
            scenario(command, args.project, service, args.base_url, str(admin), Path(temporary))
        print('PASS owned control dependency scenario: ' + service)


if __name__ == '__main__':
    previous = install_interrupt_handlers()
    try:
        main()
    except Exception:
        print('Control recovery acceptance failed; credential/network details withheld.', file=sys.stderr)
        sys.exit(1)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
