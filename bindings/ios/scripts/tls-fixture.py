#!/usr/bin/env python3
"""仅本机负向验收：受控自签 TLS，不读取 HTTP/payload，不安装任何信任根。"""
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys

root = Path(sys.argv[1])
if not root.is_dir() or root.stat().st_mode & 0o077:
    raise SystemExit('需要0700测试目录')
os.umask(0o077)
(root / 'openssl.cnf').write_text('[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=127.0.0.1\n[ext]\nsubjectAltName=IP:127.0.0.1\n')
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-config',str(root/'openssl.cnf'),'-keyout',str(root/'test-only.key'),'-out',str(root/'test-only.crt')],
               check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(root/'test-only.crt',root/'test-only.key')
context.minimum_version=ssl.TLSVersion.TLSv1_2
listener=socket.socket()
listener.bind(('127.0.0.1',0));listener.listen(8);listener.settimeout(0.5)
state={'accepted_tcp':0,'rejected_handshakes':0,'accepted_handshakes':0,
       'handshake_timeout':0,'other_io_error':0,'origin':'https://127.0.0.1:'+str(listener.getsockname()[1])+'/'}
def save():
    temporary=root/'state.tmp'
    temporary.write_text(json.dumps(state)+'\n')
    temporary.replace(root/'state.json')
save()
running=True
def stop(*_):
    global running
    running=False
signal.signal(signal.SIGTERM,stop)
try:
    while running:
        try: raw,_=listener.accept()
        except socket.timeout: continue
        state['accepted_tcp']+=1
        save()
        raw.settimeout(4)
        try:
            with context.wrap_socket(raw,server_side=True): state['accepted_handshakes']+=1
        except ssl.SSLError: state['rejected_handshakes']+=1
        except socket.timeout: state['handshake_timeout']+=1
        except OSError: state['other_io_error']+=1
        finally: raw.close();save()
finally: listener.close()
