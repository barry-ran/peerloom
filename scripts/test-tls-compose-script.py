#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""本机真实 TLS/WSS 夹具和无 Docker 编排回归；不能代替 nginx/Go Compose 验收。"""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('tls_compose', ROOT / 'scripts/test-tls-compose.py')
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)


class TLSComposeTests(unittest.TestCase):
    def test_tool_diagnostics_keep_exit_category_but_not_private_output(self):
        result = subprocess.CompletedProcess(['docker'], 42, b'secret stdout', b'postgresql://user:secret@private/db')
        with mock.patch.object(m.subprocess, 'run', return_value=result) as run:
            with self.assertRaisesRegex(m.ToolFailure, 'command=docker; exit_code=42') as error:
                m.invoke(['docker', 'private-argument'], data=b'private password', capture=True)
            self.assertNotIn('secret', str(error.exception))
            self.assertNotIn('private', str(error.exception))
            self.assertEqual(run.call_args.kwargs['stderr'], subprocess.DEVNULL)
        with mock.patch.object(m.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['docker', 'private-argument'], 1, output=b'private secret')):
            with self.assertRaisesRegex(m.ToolFailure, 'command=docker; outcome=timeout') as error:
                m.invoke(['docker', 'private-argument'])
            self.assertNotIn('private', str(error.exception))

    def test_configuration_ports_secret_scope_and_production_cookie_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config, image = m.configuration(ROOT, directory, 'peerloom-tls-ci-unit')
            self.assertEqual(config['services']['gateway']['ports'], ['127.0.0.1:18443:8443'])
            server = config['services']['device-server']['environment']
            self.assertEqual(server['ADMIN_ORIGIN'], m.ORIGIN)
            self.assertEqual(server['ADMIN_DEVELOPMENT_LOOPBACK'], '')
            self.assertNotIn('ca.key', json.dumps(config))
            for item in config['secrets'].values():
                self.assertTrue(Path(item['file']).is_relative_to(directory))
            self.assertEqual(config['services']['gateway']['secrets'], ['tls_certificate', 'tls_private_key'])
            self.assertEqual(config['services']['device-server']['image'], image)

    def test_refuses_unexpected_existing_database_publish(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'infra').mkdir()
            config = yaml.safe_load((ROOT / 'infra/compose.yaml').read_text())
            config['services']['postgres']['ports'] = ['0.0.0.0:5432:5432']
            (root / 'infra/compose.yaml').write_text(yaml.safe_dump(config))
            with self.assertRaises(m.Failure):
                m.configuration(root, root, 'unit')

    def test_actual_merged_config_must_not_publish_extra_or_public_ports(self):
        good = {'services': {'gateway': {'ports': [{'host_ip': '127.0.0.1', 'published': '18443', 'target': 8443}]},
                'device-server': {'environment': {'ADMIN_ORIGIN': m.ORIGIN, 'ADMIN_DEVELOPMENT_LOOPBACK': ''}}}}
        m.validate_rendered(json.dumps(good))
        for change in (lambda value: value['services']['gateway']['ports'][0].update(host_ip='0.0.0.0'),
                       lambda value: value['services']['gateway']['ports'].append({'target': 8080}),
                       lambda value: value['services']['device-server'].update(ports=[{'target': 8080}]),
                       lambda value: value['services']['device-server']['environment'].update(ADMIN_DEVELOPMENT_LOOPBACK='true')):
            bad = json.loads(json.dumps(good)); change(bad)
            with self.assertRaises(m.Failure):
                m.validate_rendered(json.dumps(bad))

    def test_remote_docker_daemon_is_never_contacted_for_deployment(self):
        with mock.patch.dict(os.environ, {'DOCKER_HOST': 'ssh://operator@production'}), mock.patch.object(m, 'invoke') as invoke:
            with self.assertRaises(m.Failure): m.require_local_docker()
            invoke.assert_not_called()
        with mock.patch.dict(os.environ, {'DOCKER_HOST': ''}), mock.patch.object(m, 'invoke', return_value=b'"tcp://remote:2376"'):
            with self.assertRaises(m.Failure): m.require_local_docker()

    def test_client_frame_mask_and_127_byte_server_payload(self):
        stream = io.BytesIO()
        value = {'message': '中文' * 90}
        m.send_frame(stream, value)
        data = stream.getvalue()
        self.assertEqual(data[:2], b'\x81\xfe')
        count = struct.unpack('!H', data[2:4])[0]
        mask = data[4:8]
        self.assertEqual(json.loads(bytes(v ^ mask[i % 4] for i, v in enumerate(data[8:]))), value)
        self.assertEqual(count, len(data) - 8)
        payload = json.dumps('x' * 125).encode()
        self.assertEqual(len(payload), 127)
        self.assertEqual(m.receive_frame(io.BytesIO(b'\x81\x7e\x00\x7f' + payload)), 'x' * 125)
        for bad in (b'', b'\x81\x7f', b'\x81\xfe', b'\x01\x01x', b'\x81\x7e\xff\xff'):
            with self.assertRaises(m.Failure):
                m.receive_frame(io.BytesIO(bad))

    def test_no_authenticated_redirect_or_header_injection(self):
        with self.assertRaises(m.Failure):
            m.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://foreign.invalid')
        with self.assertRaises(m.Failure):
            m.verify_wss('dev_private\r\nInjected: yes', Path('/nonexistent'))

    def test_cleanup_owns_only_new_project_and_never_leaks_password(self):
        for fail in (False, True, "tool"):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); (root / 'infra').mkdir(); (root / 'scripts').mkdir()
                shutil.copy(ROOT / 'infra/compose.yaml', root / 'infra/compose.yaml')
                shutil.copy(ROOT / 'scripts/generate-dev-secrets.py', root / 'scripts/generate-dev-secrets.py')
                (root / '.secrets').mkdir(); sentinel = root / '.secrets/operator'
                sentinel.write_text('leave untouched')
                calls, directories = [], []
                def certificates(path):
                    path.mkdir(mode=0o700)
                    for name in ('ca.crt', 'server.crt', 'server.key'):
                        (path / name).write_text('synthetic placeholder for mock only')
                    return path / 'ca.crt'
                def invoke(args, **kwargs):
                    calls.append(args)
                    if args[:3] == ['docker', 'context', 'inspect']:
                        return b'"unix:///var/run/docker.sock"'
                    if args[0] == 'curl':
                        self.assertIn('--cacert', args); self.assertNotIn('-k', args)
                        return b''
                    if args[:3] == ['docker', 'image', 'rm']:
                        self.assertTrue(args[3].startswith('peerloom-tls-ci-')); return b''
                    project = args[args.index('-p') + 1]
                    self.assertTrue(project.startswith('peerloom-tls-ci-'))
                    directory = Path(args[args.index('-f') + 1]).parent
                    directories.append(directory)
                    self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                    self.assertEqual(stat.S_IMODE((directory / 'compose.yaml').stat().st_mode), 0o600)
                    self.assertIn(str(root / 'infra/compose.tls.yaml'), args)
                    self.assertTrue(kwargs['env']['TLS_PRIVATE_KEY_FILE'].startswith(str(directory)))
                    if 'config' in args:
                        return json.dumps({'services': {'gateway': {'ports': [{'host_ip': '127.0.0.1', 'published': '18443', 'target': 8443}]},
                            'device-server': {'environment': {'ADMIN_ORIGIN': m.ORIGIN, 'ADMIN_DEVELOPMENT_LOOPBACK': ''}}}}).encode()
                    if '--pair' in args:
                        self.assertIn('device-server', args)
                        return b'{"source":{"device_credential":"dev_synthetic"}}'
                    if 'device-bootstrap' in args:
                        return b'{"tenant_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}'
                    if 'device-admin-user' in args:
                        password = kwargs['data'].decode().strip()
                        self.assertNotIn(password, str(args))
                        return b'{"status":"created"}'
                    return b''
                out = io.StringIO()
                with mock.patch.object(m, 'certificates', side_effect=certificates), \
                     mock.patch.object(m, 'invoke', side_effect=invoke), \
                     mock.patch.object(m, 'verify_default_trust_rejects'), \
                     mock.patch.object(m, 'verify_https', side_effect=m.ToolFailure('command=docker; exit_code=42') if fail == 'tool' else m.Failure('secret payload') if fail else None), \
                     mock.patch.object(m, 'verify_wss') as wss, contextlib.redirect_stdout(out):
                    if fail:
                        with self.assertRaisesRegex(m.Failure, 'secret details withheld') as error:
                            m.execute(root)
                        self.assertNotIn('secret payload', str(error.exception))
                        if fail == 'tool': self.assertIn('exit_code=42', str(error.exception))
                        wss.assert_not_called()
                    else:
                        m.execute(root); wss.assert_called_once()
                self.assertTrue(any('down' in args and '--volumes' in args for args in calls))
                self.assertTrue(any(args[:3] == ['docker', 'image', 'rm'] for args in calls))
                self.assertTrue(all(not path.exists() for path in directories))
                self.assertEqual(sentinel.read_text(), 'leave untouched')
                self.assertNotIn('dev_synthetic', out.getvalue())

    def test_real_tls_default_rejects_explicit_ca_verifies_and_wss_heartbeat(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            ca = m.certificates(root / 'tls')
            self.assertEqual(stat.S_IMODE((root / 'tls/ca.key').stat().st_mode), 0o600)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / 'tls/server.crt', root / 'tls/server.key')
            listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(3); listener.settimeout(8)
            port = listener.getsockname()[1]
            errors, observed = [], []
            def serve():
                try:
                    for _ in range(3):
                        plain, _ = listener.accept()
                        try:
                            connection = context.wrap_socket(plain, server_side=True)
                        except ssl.SSLError:
                            plain.close(); observed.append('rejected'); continue
                        with connection, connection.makefile('rwb') as stream:
                            headers = {}
                            self.assertEqual(stream.readline(), b'GET /v1/device-signal HTTP/1.1\r\n')
                            while (line := stream.readline()) != b'\r\n':
                                name, value = line.decode().split(':', 1); headers[name.lower()] = value.strip()
                            self.assertEqual(headers['authorization'], 'Bearer dev_synthetic')
                            self.assertNotIn('origin', headers)
                            accept = base64.b64encode(hashlib.sha1((headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
                            stream.write(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n'); stream.flush()
                            for expected in ('hello', 'presence.heartbeat'):
                                first, second = m.read_exact(stream, 2)
                                self.assertEqual(first, 0x81); self.assertTrue(second & 0x80)
                                size = second & 127
                                if size == 126: size = struct.unpack('!H', m.read_exact(stream, 2))[0]
                                self.assertLess(size, 4097)
                                mask = m.read_exact(stream, 4); data = m.read_exact(stream, size)
                                value = json.loads(bytes(v ^ mask[i % 4] for i, v in enumerate(data)))
                                self.assertEqual(value['type'], expected)
                                if expected == 'presence.heartbeat':
                                    self.assertEqual(value['fencing_token'], 'synthetic-fence')
                                    self.assertEqual(value['seq'], 1)
                                reply = json.dumps({'type': 'hello.ack' if expected == 'hello' else 'presence.ack',
                                    'request_id': value['id'], 'connection_generation': 1, 'fencing_token': 'synthetic-fence'}).encode()
                                stream.write(b'\x81\x7e' + struct.pack('!H', len(reply)) + reply); stream.flush()
                                observed.append(expected)
                except Exception as error:
                    errors.append(error)
                finally:
                    listener.close()
            thread = threading.Thread(target=serve, daemon=True); thread.start()
            try:
                m.verify_default_trust_rejects(port)
                with socket.create_connection(('127.0.0.1', port), timeout=4) as raw:
                    with self.assertRaises(ssl.SSLCertVerificationError):
                        ssl.create_default_context(cafile=str(ca)).wrap_socket(raw, server_hostname='wrong.example')
                m.verify_wss('dev_synthetic', ca, port)
            finally:
                thread.join(10)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(observed, ['rejected', 'rejected', 'hello', 'presence.heartbeat'])


if __name__ == '__main__':
    unittest.main()
