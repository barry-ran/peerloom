#!/usr/bin/env python3
"""Isolated three-SDK exclusive-session acceptance; no downloads or system changes."""
import argparse
import base64
import contextlib
import shutil
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import uuid

TEST = 'prepared_target_competition_renewal_fence_and_handoff'

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

def create_output(path, cap):
    # Exclusive creation: never adopt a pre-existing directory or symbolic link.
    path.mkdir(mode=0o700)
    output = path.resolve(strict=True)
    metadata = output.stat()
    cap.require(metadata.st_uid == os.getuid() and metadata.st_mode & 0o777 == 0o700,
                'private output required')
    return output

def finish_cleanup(cap, children, logs, result):
    try:
        cap.cleanup(children, logs)
    except (cap.Failure, OSError, subprocess.SubprocessError):
        result.update(status='failed', failure_stage='cleanup', failure_type='CleanupFailure')
    result['owned_processes_reaped'] = all(p.poll() is not None for p in children)
    if not result['owned_processes_reaped']:
        result.update(status='failed', failure_stage='cleanup', failure_type='CleanupFailure')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'pg-bin', 'redis-bin', 'server-bin', 'sdk-test', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    root, pg, redis, binaries, sdk = (p.resolve(strict=True) for p in (args.root,args.pg_bin,args.redis_bin,args.server_bin,args.sdk_test))
    cap = module('exclusive_dependencies', root/'scripts/test-capacity.py')
    management = module('exclusive_http', root/'scripts/test-management.py')
    cap.require(os.getuid()!=0, 'unprivileged fixture required')
    out=create_output(args.output, cap)
    cap.versions(pg,redis)
    cap.require(cap.run([str(sdk),'--list']).decode().splitlines().count(TEST+': test')==1,'exact SDK test required')
    env=cap.clean_env();children=[];logs=[];stage='setup';result={'status':'failed','case':'exclusive','sdk_test_sha256':cap.digest(sdk),'binary_sha256':{n:cap.digest(binaries/n) for n in ('device-server','device-admin','device-migrate')},'physical_android_devices':False}
    @contextlib.contextmanager
    def private_runtime():
        private=out/'private';private.mkdir(mode=0o700)
        try: yield private
        finally:
            if result['status']=='passed' and result.get('owned_processes_reaped'):
                shutil.rmtree(private)
    cap.install_interrupt_handlers()
    with private_runtime() as private:
        def launch(command,label,selected_env=env):
            stream=(private/(label+'.log')).open('xb');os.fchmod(stream.fileno(),0o600);logs.append(stream)
            child=subprocess.Popen(command,env=selected_env,stdout=stream,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,start_new_session=True);children.append(child);return child
        try:
            ports=set()
            while len(ports)<3: ports.add(cap.free_port())
            pp,rp,hp=sorted(ports);pw=secrets.token_urlsafe(32);rw=secrets.token_urlsafe(32)
            cap.private(private/'pg-password',pw);cap.private(private/'redis-password',rw)
            cap.private(private/'database-url',f'postgres://peerloom_exclusive:{pw}@127.0.0.1:{pp}/postgres?sslmode=disable')
            cap.private(private/'replay-key',base64.b64encode(secrets.token_bytes(32)))
            env.update(DATABASE_URL_FILE=str(private/'database-url'),REPLAY_KEY_FILE=str(private/'replay-key'),REDIS_PASSWORD_FILE=str(private/'redis-password'),REDIS_ADDRESS=f'127.0.0.1:{rp}',LISTEN_ADDRESS=f'127.0.0.1:{hp}')
            stage='dependencies'
            cap.run([str(pg/'initdb'),'-D',str(private/'pgdata'),'-U','peerloom_exclusive','--auth-host=scram-sha-256','--auth-local=reject','--pwfile='+str(private/'pg-password'),'--no-locale','--encoding=UTF8'],env=env)
            postgres=launch([str(pg/'postgres'),'-D',str(private/'pgdata'),'-h','127.0.0.1','-p',str(pp),'-k',''],'postgres')
            cap.private(private/'redis.conf',f'bind 127.0.0.1\nport {rp}\nprotected-mode yes\nrequirepass {rw}\nsave ""\nappendonly no\ndir {private}\n')
            cache=launch([str(redis/'redis-server'),str(private/'redis.conf')],'redis');deadline=time.monotonic()+30
            while True:
                cap.require(postgres.poll() is None and cache.poll() is None,'dependency exited')
                try:
                    cap.run([str(pg/'pg_isready'),'-h','127.0.0.1','-p',str(pp)],env=env,timeout=3)
                    cap.require(cap.redis_command(rp,rw,'PING')==b'+PONG\r\n','Redis readiness');break
                except (OSError,cap.Failure):
                    cap.require(time.monotonic()<deadline,'dependency readiness timeout');time.sleep(.1)
            stage='migrate'
            cap.run([str(binaries/'device-migrate'),'--dir',str(root/'infra/migrations'),'up'],env=env)
            admin=json.loads(cap.run([str(binaries/'device-admin'),'bootstrap','--offline','--tenant-name','exclusive-fixture','--scope','admin'],env=env))['service_credential']
            server=launch([str(binaries/'device-server')],'server');origin=f'http://127.0.0.1:{hp}/';http=management.Client(origin);deadline=time.monotonic()+30
            while True:
                cap.require(server.poll() is None,'server exited')
                try:http.request('GET','/v1/applications',200,admin);break
                except (OSError,management.CheckFailure):
                    cap.require(time.monotonic()<deadline,'server readiness timeout');time.sleep(.1)
            stage='registrations';regs=[]
            for i in range(3):
                app=http.request('POST','/v1/applications',201,admin,{'name':f'exclusive-fixture-{i}','exclusive_target':i==2},str(uuid.uuid4()))
                grant=http.request('POST','/v1/registration-grants',201,admin,{'application_id':app['id'],'expires_in_seconds':600},str(uuid.uuid4()))
                regs.append({'application_id':app['id'],'grant':grant['grant']})
            cap.private(private/'fixture.json',json.dumps({'origin':origin,'service_credential':admin,'registrations':regs}))
            stage='real-sdk';test_env=cap.clean_env();test_env['TEST_EXCLUSIVE_FIXTURE']=str(private/'fixture.json')
            process=launch([str(sdk),'--ignored','--exact',TEST,'--nocapture'],'sdk',test_env);started=time.monotonic()
            while process.poll() is None:
                cap.require(all(p.poll() is None for p in (postgres,cache,server)),'dependency exited during acceptance')
                cap.require(time.monotonic()-started<300,'acceptance deadline');time.sleep(.2)
            cap.require(process.returncode==0,'SDK acceptance failed')
            result.update(status='passed',elapsed_seconds=round(time.monotonic()-started,3),registered_sdk_identities=3,lease_hold_seconds=65,new_wss_deadline_fallback=True)
        except (cap.Failure,management.CheckFailure,OSError,ValueError,KeyError) as error:
            result['failure_stage']=stage;result['failure_type']=type(error).__name__
        finally:
            finish_cleanup(cap, children, logs, result)
    cap.evidence(out/'exclusive-result.json',result)
    print(json.dumps(result,sort_keys=True))
    return 0 if result['status']=='passed' and result['owned_processes_reaped'] else 1
if __name__=='__main__':raise SystemExit(main())
