#!/usr/bin/env python3
"""本地 coturn REST 到期/Refresh 真实协议回归，不模拟生产撤销语义。"""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
COOKIE = 0x2112A442


def attribute(kind, value):
    return struct.pack('!HH', kind, len(value)) + value + b'\0' * (-len(value) % 4)


def packet(kind, transaction, values, key=None):
    body = b''.join(attribute(k, v) for k, v in values)
    header = struct.pack('!HHI', kind, len(body) + (24 if key else 0), COOKIE) + transaction
    if key:
        body += attribute(0x0008, hmac.digest(key, header + body, 'sha1'))
    return header + body


def parse(data, transaction):
    if len(data) < 20 or data[8:20] != transaction:
        raise RuntimeError('invalid local TURN transaction')
    kind, size, magic = struct.unpack('!HHI', data[:8])
    if magic != COOKIE or size != len(data) - 20:
        raise RuntimeError('invalid local TURN response framing')
    values = {}
    offset = 20
    while offset < len(data):
        if offset + 4 > len(data):
            raise RuntimeError('truncated local TURN attribute')
        key, length = struct.unpack('!HH', data[offset:offset + 4])
        end = offset + 4 + length
        if end > len(data):
            raise RuntimeError('truncated local TURN value')
        values[key] = (data[offset + 4:end], offset)
        offset = end + (-length % 4)
    return kind, values


def error_code(values):
    value = values.get(0x0009, (b'', 0))[0]
    return (value[2] & 7) * 100 + value[3] if len(value) >= 4 else None


def verify_integrity(data, values, key):
    digest, offset = values.get(0x0008, (b'', 0))
    if len(digest) != 20:
        raise RuntimeError('authenticated TURN response has no integrity')
    header = data[:2] + struct.pack('!H', offset + 24 - 20) + data[4:20]
    expected = hmac.digest(key, header + data[20:offset], 'sha1')
    if not hmac.compare_digest(expected, digest):
        raise RuntimeError('local TURN response integrity mismatch')


class Allocation:
    def __init__(self, address, credential):
        self.address = address
        self.credential = credential
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(2)
        self.realm = self.nonce = self.key = None

    def close(self):
        self.socket.close()

    def request(self, kind, values, authenticated=False):
        transaction = secrets.token_bytes(12)
        if authenticated:
            values = values + [(0x0006, self.credential['username'].encode()),
                               (0x0014, self.realm), (0x0015, self.nonce)]
        data = packet(kind, transaction, values, self.key if authenticated else None)
        self.socket.sendto(data, self.address)
        received, peer = self.socket.recvfrom(8192)
        if peer != self.address:
            raise RuntimeError('unexpected local TURN responder')
        response, attrs = parse(received, transaction)
        if authenticated and not (response & 0x0010):
            verify_integrity(received, attrs, self.key)
        return response, attrs

    def allocate(self):
        values = [(0x0019, bytes([17, 0, 0, 0])), (0x000D, struct.pack('!I', 60))]
        kind, attrs = self.request(0x0003, values)
        if kind != 0x0113 or error_code(attrs) != 401:
            raise RuntimeError('TURN did not require long-term authentication')
        self.realm = attrs[0x0014][0]
        self.nonce = attrs[0x0015][0]
        # RFC long-term MESSAGE-INTEGRITY key, not a production password hash.
        self.key = hashlib.md5(self.credential['username'].encode() + b':' + self.realm +
                               b':' + self.credential['credential'].encode()).digest()
        return self.request(0x0003, values, True)

    def refresh(self):
        return self.request(0x0004, [(0x000D, struct.pack('!I', 60))], True)


def private_file(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(content)


def container_command(image, name, path):
    if os.name != "posix" or os.getuid() == 0:
        raise RuntimeError("container TURN regression requires non-root Linux operator")
    return ["docker", "run", "--rm", "--pull", "never", "--name", name,
            "--network", "host", "--user", f"{os.getuid()}:{os.getgid()}",
            "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--tmpfs", "/var/lib/coturn:rw,noexec,nosuid,size=1m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", "64", "--memory", "128m", "--cpus", "2", "--stop-timeout", "10",
            "--mount", f"type=bind,src={path / 'turn.conf'},dst=/etc/coturn/turnserver.conf,readonly",
            "--entrypoint", "/usr/bin/turnserver", image, "-c", "/etc/coturn/turnserver.conf"]


def run(binary=None, image=None):
    # Refuse to test somebody else's listener if the fixed isolated port is busy.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 53478))
    with tempfile.TemporaryDirectory(prefix='peerloom-turn-refresh-') as directory:
        path = Path(directory)
        secret = secrets.token_hex(32)
        private_file(path / 'shared-secret', secret)
        config = ['listening-ip=127.0.0.1', 'relay-ip=127.0.0.1', 'listening-port=53478',
                  'min-port=55000', 'max-port=55031', 'use-auth-secret',
                  'static-auth-secret=' + secret, 'realm=peerloom.test', 'fingerprint',
                  'no-tcp', 'no-tls', 'no-dtls', 'no-tcp-relay', 'no-multicast-peers',
                  'cli=0', 'relay-threads=1', 'user-quota=4', 'total-quota=8',
                  'max-bps=1048576', 'stale-nonce=600', 'no-software-attribute',
                  'log-file=stdout', 'simple-log',
                  'pidfile=' + ('/tmp/turn.pid' if image else str(path / 'turn.pid')),
                  'userdb=' + ('/tmp/turndb' if image else str(path / 'turndb'))]
        private_file(path / 'turn.conf', '\n'.join(config) + '\n')
        private_file(path / 'turn.log', '')
        with (path / 'turn.log').open('a') as log:
            container_name = 'peerloom-turn-refresh-' + secrets.token_hex(8) if image else None
            command = container_command(image, container_name, path) if image else [binary, '-c', str(path / 'turn.conf')]
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            clients = []
            try:
                for _ in range(40):
                    if process.poll() is not None:
                        raise RuntimeError('isolated TURN exited before readiness')
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                        probe.settimeout(.1)
                        transaction = secrets.token_bytes(12)
                        probe.sendto(packet(1, transaction, []), ('127.0.0.1', 53478))
                        try:
                            response, _ = probe.recvfrom(8192)
                            kind, _ = parse(response, transaction)
                            if kind == 0x0101:
                                break
                        except TimeoutError:
                            pass
                    time.sleep(.1)
                else:
                    raise RuntimeError('isolated TURN readiness timeout')
                subprocess.run(['go', 'test', '-tags=integration', './internal/relay', '-run',
                                '^TestEmitLocalTURNFixture$', '-count=1'],
                               cwd=ROOT / 'src/device-server',
                               env={**os.environ, 'TEST_RELAY_FIXTURE_DIRECTORY': directory},
                               timeout=45, check=True)
                if process.poll() is not None:
                    raise RuntimeError('isolated TURN exited during fixture creation')
                soon = json.loads((path / 'soon.json').read_text())
                fresh = json.loads((path / 'credentials.json').read_text())
                current = Allocation(('127.0.0.1', 53478), soon)
                clients.append(current)
                kind, attrs = current.allocate()
                if kind != 0x0103 or 0x0016 not in attrs:
                    raise RuntimeError('initial valid allocation failed')
                expiry = int(soon['username'].split(':', 1)[0])
                delay = expiry - time.time() + 1.2
                if not 0 < delay < 12:
                    raise RuntimeError('short-expiry fixture timing outside bounds')
                time.sleep(delay)
                kind, attrs = current.refresh()
                if kind != 0x0104 or struct.unpack('!I', attrs[0x000D][0])[0] <= 0:
                    raise RuntimeError('existing allocation rejected post-expiry Refresh')
                rejected = Allocation(('127.0.0.1', 53478), soon)
                clients.append(rejected)
                kind, attrs = rejected.allocate()
                if kind != 0x0113 or error_code(attrs) != 401:
                    raise RuntimeError('expired credential authenticated new allocation')
                positive = Allocation(('127.0.0.1', 53478), fresh)
                clients.append(positive)
                kind, attrs = positive.allocate()
                if kind != 0x0103 or 0x0016 not in attrs:
                    raise RuntimeError('fresh control allocation failed after rejection')
                print('PASS: authenticated existing allocation Refresh after REST expiry; '
                      'same expired credential new 5-tuple rejected 401; fresh credential accepted')
            finally:
                for client in clients:
                    client.close()
                stop_server(process, container_name)


def stop_server(process, container_name):
    cleanup_error = None
    if container_name:
        # A Docker client exit alone does not stop its server-side container.
        try:
            result = subprocess.run(["docker", "rm", "-f", "-v", container_name],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            if result.returncode:
                exists = subprocess.run(["docker", "inspect", "--format", "{{.State.Running}}", container_name],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                if exists.returncode == 0:
                    cleanup_error = RuntimeError("owned TURN container cleanup failed")
        except (OSError, subprocess.SubprocessError):
            cleanup_error = RuntimeError("owned TURN container cleanup could not be verified")
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    if cleanup_error:
        raise cleanup_error



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--turnserver')
    mode.add_argument('--container-image', help='already-built pinned coturn image with filecap removed; never pulled')
    args = parser.parse_args()
    try:
        run(args.turnserver, args.container_image)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        # Never print request bytes, TURN responses, log files or credentials.
        print('TURN Refresh regression failed:', str(error) if isinstance(error, RuntimeError) else type(error).__name__)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
