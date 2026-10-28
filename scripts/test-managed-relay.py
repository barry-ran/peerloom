#!/usr/bin/env python3
"""真实Go管理夹具→SDK自动ICE→隔离coturn；仅Linux loopback测试入口。"""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('turn_refresh', Path(__file__).with_name('test-turn-refresh.py'))
TURN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TURN)


class Failure(Exception):
    """Messages contain only fixed nonsecret diagnostics."""


def private_bytes(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.getuid()):
            raise Failure('fixture requires a current-user-owned regular 0600 file')
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise Failure('fixture exceeds size limit')
    return data


def validate_origin(origin):
    parsed = urllib.parse.urlsplit(origin)
    try:
        loopback = ipaddress.ip_address(parsed.hostname or '').is_loopback
        port = parsed.port
    except ValueError:
        raise Failure('base URL requires numeric loopback origin') from None
    if (not loopback or parsed.scheme not in ('http', 'https') or parsed.username is not None
            or parsed.password is not None or parsed.path not in ('', '/') or parsed.query
            or parsed.fragment or port == 0):
        raise Failure('base URL requires plain numeric loopback origin')


def validate_pair(data):
    value = json.loads(data)
    if not isinstance(value, dict):
        raise Failure('pair fixture must be an object')
    for role in ('source', 'target'):
        device = value[role]
        uuid.UUID(device['application_id'])
        uuid.UUID(device['device_id'])
        if not re.fullmatch(r'dev_[A-Za-z0-9_-]{43}', device['device_credential']):
            raise Failure('pair fixture requires device audience')
        if not isinstance(device['expires_at'], str) or len(device['expires_at']) > 64:
            raise Failure('pair fixture expiry missing')


def run_sdk(fixture, origin):
    environment = {**os.environ, 'TEST_MANAGED_RELAY': '1',
                   'TEST_SIGNAL_FIXTURE_FILE': str(fixture), 'TEST_IDENTITY_BASE_URL': origin}
    command = ['cargo', 'test', '-p', 'device-core', '--test', 'sdk_service', '--locked',
               '--', '--ignored', '--nocapture']
    process = subprocess.Popen(command, cwd=ROOT / 'src/device-sdk', env=environment,
                               start_new_session=True)
    try:
        if process.wait(timeout=180):
            raise Failure('managed RelayOnly SDK integration failed')
    finally:
        # Cargo may own a still-running test child on timeout/cancellation.
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


def run(args):
    if not sys.platform.startswith('linux') or os.getuid() == 0:
        raise Failure('managed relay integration requires a non-root Linux caller')
    validate_origin(args.base_url)
    shared = private_bytes(args.shared_secret_file, 256)
    if not 32 <= len(shared) <= 256 or any(byte < 0x21 or byte > 0x7e for byte in shared):
        raise Failure('shared secret must be exact printable ASCII bytes without newline')
    pair = private_bytes(args.pair_fixture, 65536)
    validate_pair(pair)
    # Refuse to accidentally exercise another local TURN server.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 53478))
    with tempfile.TemporaryDirectory(prefix='peerloom-managed-relay-') as directory:
        path = Path(directory)
        TURN.private_file(path / 'pair.json', pair.decode('utf-8'))
        config = ['listening-ip=127.0.0.1', 'relay-ip=127.0.0.1', 'listening-port=53478',
                  'min-port=55000', 'max-port=55031', 'use-auth-secret',
                  'static-auth-secret=' + shared.decode('ascii'), 'realm=peerloom.test',
                  'fingerprint', 'no-tcp', 'no-tls', 'no-dtls', 'no-tcp-relay',
                  'no-multicast-peers',
                  '# Isolated loopback test exception; never copy to production.',
                  'allow-loopback-peers', 'cli=0', 'relay-threads=1', 'user-quota=8',
                  'total-quota=16', 'max-bps=1048576', 'stale-nonce=600',
                  'no-software-attribute', 'log-file=stdout', 'simple-log',
                  'pidfile=' + ('/tmp/turn.pid' if args.container_image else str(path / 'turn.pid')),
                  'userdb=' + ('/tmp/turndb' if args.container_image else str(path / 'turndb'))]
        TURN.private_file(path / 'turn.conf', '\n'.join(config) + '\n')
        TURN.private_file(path / 'turn.log', '')
        name = 'peerloom-managed-relay-' + secrets.token_hex(8) if args.container_image else None
        command = (TURN.container_command(args.container_image, name, path) if args.container_image
                   else [args.turnserver, '-c', str(path / 'turn.conf')])
        with (path / 'turn.log').open('a') as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            try:
                ready = False
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    probe.settimeout(.1)
                    for _ in range(50):
                        if process.poll() is not None:
                            raise Failure('isolated TURN exited before readiness')
                        transaction = secrets.token_bytes(12)
                        probe.sendto(TURN.packet(1, transaction, []), ('127.0.0.1', 53478))
                        try:
                            response, address = probe.recvfrom(8192)
                            kind, _ = TURN.parse(response, transaction)
                            if address == ('127.0.0.1', 53478) and kind == 0x0101:
                                ready = True
                                break
                        except TimeoutError:
                            time.sleep(.1)
                if not ready:
                    raise Failure('isolated TURN readiness timeout')
                run_sdk(path / 'pair.json', args.base_url)
                if process.poll() is not None:
                    raise Failure('isolated TURN exited during SDK integration')
            finally:
                TURN.stop_server(process, name)
    print('PASS: actual SDK session-scoped managed ICE, RelayOnly selected candidate, '
          'bidirectional data, credential rotation, lease renewal and close')


def interrupted(_signal, _frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--container-image')
    mode.add_argument('--turnserver')
    parser.add_argument('--shared-secret-file', required=True)
    parser.add_argument('--pair-fixture', required=True)
    parser.add_argument('--base-url', required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    try:
        run(args)
    except KeyboardInterrupt:
        print('Managed relay integration interrupted; owned resources cleaned')
        return 130
    except Failure as error:
        print('Managed relay integration failed:', error)
        return 1
    except RuntimeError as error:
        print("Managed relay integration failed:", error)
        return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # Never print native logs, raw requests, fixture content or subprocess env.
        print('Managed relay integration failed: local fixture, process or service unavailable')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
