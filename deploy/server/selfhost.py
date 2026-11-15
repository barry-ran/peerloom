#!/usr/bin/env python3
"""发布包的自建部署入口；仅本机回环，不打开公网或管理后台。"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

class SelfhostError(ValueError):
    """A fixed diagnostic that never includes secret input."""


SECRET_NAMES = ('postgres_password', 'database_url', 'redis_password', 'redis_config', 'replay_key')


def invoke(command, *, capture=False):
    # Never include command output in errors: administration output may contain secrets.
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.DEVNULL if capture else None, timeout=600, check=False)
    if result.returncode:
        raise RuntimeError('command failed; retained state, do not delete secrets or database volumes')
    if capture and len(result.stdout) > 65536:
        raise RuntimeError('command output exceeds limit')
    return result.stdout if capture else b''


def validate_file(path, mode, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != mode or info.st_size < 1 or info.st_size > limit):
            raise SelfhostError('unsafe or incomplete local state')
        data = stream.read(limit + 1)
        if len(data) != info.st_size:
            raise SelfhostError('local state changed during read')
        return data


def validate_private(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise SelfhostError('unsafe private directory')


def load_json(path):
    return json.loads(validate_file(path, 0o600))


def create_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(value, stream)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    # Persist the directory entry too, not only the file contents. Leave the file
    # in place on an fsync failure; a subsequent run must validate retained state.
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def compose(package, project):
    return ['docker', 'compose', '--project-directory', str(package / 'deploy'), '--project-name', project,
            '-f', str(package / 'deploy/compose.yaml'),
            '-f', str(package / '.operator/selfhost.compose.json')]


def admin(package, project, args):
    return compose(package, project) + ['--profile', 'tools', 'run', '--rm', '-T',
        '--user', f'{os.geteuid()}:{os.getegid()}', '--volume', str(package / '.operator') + ':/operator',
        '--entrypoint', 'device-admin', 'migrate'] + args


def key_status(package, project, run):
    value = load_json(package / '.operator/connection.json')
    tenant = str(uuid.UUID(value['tenant_id']))
    credential = str(uuid.UUID(value['credential_id']))
    str(uuid.UUID(value['application_id']))
    response = json.loads(run(admin(package, project, ['setup-verify', '--offline', '--input',
                                     '/operator/connection.json']), capture=True))
    # Whitelist nonsecret fields; never print an arbitrary CLI object or connection.json.
    if (response.get('tenant_id') != tenant or response.get('credential_id') != credential
            or response.get('application_id') != value['application_id']):
        raise SelfhostError('credential status mismatch')
    return {name: response.get(name) for name in ('tenant_id', 'application_id', 'credential_id', 'scope', 'expires_at', 'revoked_at', 'expired', 'tenant_active')}


def check_resources(package, project, run, existing):
    ids = run(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project], capture=True).decode().split()
    volumes = run(['docker', 'volume', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + project], capture=True).decode().split()
    networks = run(['docker', 'network', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + project], capture=True).decode().split()
    if (ids or volumes or networks) and not existing:
        raise SelfhostError('project already exists; choose a new project name, do not adopt foreign resources')
    for identifier in ids:
        if not re.fullmatch('[a-f0-9]{12,64}', identifier):
            raise SelfhostError('invalid container identifier')
        raw = run(['docker', 'inspect', '--format', '{{json .Config.Labels}}', identifier], capture=True)
        labels = json.loads(raw)
        if labels.get('com.docker.compose.project.working_dir') != str(package / 'deploy'):
            raise SelfhostError('project resource belongs to another installation')


def check_overlay(package, project, create=False):
    overlay = package / '.operator/selfhost.compose.json'
    expected = {'services': {name: {'image': 'peerloom-selfhost-' + project + ':runtime'}
                             for name in ('device-server', 'migrate')}}
    if create and not os.path.lexists(overlay):
        create_json(overlay, expected)
    elif load_json(overlay) != expected:
        raise SelfhostError('runtime image override changed')


def up(package, project, tenant, application, initializer, run=invoke):
    private = package / '.operator'
    marker = private / 'selfhost.json'
    existing = marker.exists()
    if existing:
        state = load_json(marker)
        if state != {'version': 1, 'project': project, 'tenant_name': tenant, 'application_name': application}:
            raise SelfhostError('installation settings differ; refusing implicit adoption or rename')
    check_resources(package, project, run, existing)
    if not existing:
        # Existing secrets belong to an installation not created by this entry point.
        if os.path.lexists(package / '.secrets') or os.path.lexists(private / 'connection.json'):
            raise SelfhostError('existing installation requires explicit operator review; no automatic adoption')
        create_json(marker, {'version': 1, 'project': project, 'tenant_name': tenant, 'application_name': application})
    check_overlay(package, project, create=True)
    secrets = package / '.secrets'
    if not os.path.lexists(secrets):
        initializer.generate(package)
    validate_private(secrets)
    if set(p.name for p in secrets.iterdir()) != set(SECRET_NAMES):
        raise SelfhostError('incomplete secrets; retain state for operator repair')
    for name in SECRET_NAMES:
        validate_file(secrets / name, 0o444)
    base = compose(package, project)
    run(base + ['config', '--quiet'])
    run(base + ['build'])
    run(base + ['up', '-d', '--wait', 'postgres', 'redis'])
    run(base + ['run', '--rm', '-T', 'migrate'])
    connection = private / 'connection.json'
    if not os.path.lexists(connection):
        run(admin(package, project, ['setup', '--offline', '--tenant-name', tenant,
              '--application-name', application, '--ttl', '720h', '--output', '/operator/connection.json']))
    identity = load_json(connection)
    if identity.get('tenant_name') != tenant or identity.get('application_name') != application:
        raise SelfhostError('saved identity names differ from installation')
    result = key_status(package, project, run)
    if result.get('expired') is not False or result.get('revoked_at') or result.get('tenant_active') is not True:
        raise SelfhostError('credential requires operator renewal')
    run(base + ['up', '-d', '--wait', 'device-server', 'gateway'])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('up', 'status'))
    parser.add_argument('--project-name', required=True, help='exclusive Docker Compose project name; reuse on every run')
    parser.add_argument('--tenant-name', default='default')
    parser.add_argument('--application-name', default='default')
    args = parser.parse_args()
    if not re.fullmatch('[a-z0-9][a-z0-9_-]{0,62}', args.project_name):
        parser.error('invalid project name')
    if sys.platform != 'linux':
        parser.error('run on the Linux server release package')
    import fcntl
    package = Path(os.path.abspath(__file__)).parent.parent
    spec = importlib.util.spec_from_file_location('initializer', package / 'deploy/init-private.py')
    initializer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(initializer)
    os.umask(0o077)
    try:
        parent = initializer.open_directory(package)
        os.close(parent)
        if not (package / 'bin/device-admin').is_file():
            raise SelfhostError('release package required, not the source checkout')
        private = package / '.operator'
        if args.command == 'up' and not os.path.lexists(private):
            private.mkdir(mode=0o700)
        validate_private(private)
        lock = os.open(private / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(lock, 'r+') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                raise SelfhostError('unsafe lock file')
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.command == 'up':
                result = up(package, args.project_name, args.tenant_name, args.application_name, initializer)
            else:
                state = load_json(private / 'selfhost.json')
                if state.get('project') != args.project_name:
                    raise SelfhostError('project does not match saved installation')
                check_overlay(package, args.project_name)
                check_resources(package, args.project_name, invoke, True)
                invoke(compose(package, args.project_name) + ['ps'])
                result = key_status(package, args.project_name, invoke)
        print(json.dumps(result, ensure_ascii=False))
        print('Local loopback deployment only. Connection secret remains in .operator/connection.json; never copy it to clients.')
    except SelfhostError as error:
        raise SystemExit('Self-host operation refused: ' + str(error) + '. Existing state retained.') from None
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError):
        raise SystemExit('Self-host operation failed. Existing state retained; inspect local Docker status without deleting secrets or volumes.') from None


if __name__ == '__main__':
    main()
