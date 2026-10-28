#!/usr/bin/env python3
"""只验证派生镜像wrapper的隔离/清理；实际RelayOnly仍须容器CI。"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

MOCK = r'''import os, pathlib, sys
root=pathlib.Path(os.environ['MOCK_ROOT'])
if pathlib.Path(sys.argv[0]).name=='docker':
    if 'build' in sys.argv:
        recipe=sys.stdin.read()
        image=sys.argv[sys.argv.index('--tag')+1]
        assert image.startswith('peerloom-managed-turn-test:')
        assert '--network' in sys.argv and sys.argv[sys.argv.index('--network')+1]=='none'
        assert '@sha256:bbefd3e1fdfdc0d58770fe01b581fd8b00d9f3a5580d00acb77cf719a6bc78e3' in recipe
        assert 'sha256sum /usr/bin/turnserver' in recipe and 'cat /usr/bin/turnserver >' in recipe
        assert 'USER nobody:nogroup' in recipe
        (root/'image').write_text(image)
        sys.exit(8 if os.environ['FAIL']=='build' else 0)
    assert sys.argv[1:3]==['image','rm']
    assert sys.argv[3]==(root/'image').read_text()
    (root/'cleaned').touch()
else:
    assert sys.argv[1:3]==['scripts/test-managed-relay.py','--container-image']
    assert sys.argv[3]==(root/'image').read_text()
    assert '--shared-secret-file' in sys.argv and '--pair-fixture' in sys.argv
    assert not (root/'cleaned').exists()
    (root/'invoked').touch()
    sys.exit(7 if os.environ['FAIL']=='helper' else 0)
'''

class WrapperTest(unittest.TestCase):
    def exercise(self, failure, code):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            (root/'scripts').mkdir();(root/'bin').mkdir();(root/'tmp').mkdir()
            shutil.copyfile(Path(__file__).with_name('test-managed-relay.sh'),root/'scripts/test-managed-relay.sh')
            secret='private-test-secret-not-for-log'
            (root/'secret').write_text(secret);(root/'pair').write_text('{}')
            for name in ('docker','python3'):
                p=root/'bin'/name;p.write_text('#!'+sys.executable+'\n'+MOCK);p.chmod(0o700)
            env={**os.environ,'PATH':str(root/'bin')+os.pathsep+os.environ['PATH'],'TMPDIR':str(root/'tmp'),'MOCK_ROOT':str(root),'FAIL':failure}
            result=subprocess.run(['bash','-x',str(root/'scripts/test-managed-relay.sh'),'--shared-secret-file',str(root/'secret'),'--pair-fixture',str(root/'pair'),'--base-url','http://127.0.0.1:18080'],env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,code,result.stderr)
            self.assertTrue((root/'cleaned').exists())
            self.assertEqual(list((root/'tmp').iterdir()),[])
            self.assertEqual((root/'invoked').exists(),failure!='build')
            self.assertNotIn(secret,result.stdout+result.stderr)
            self.assertTrue((root/'secret').exists()) # caller owns input cleanup
    def test_success(self):self.exercise('',0)
    def test_build_failure(self):self.exercise('build',8)
    def test_helper_failure(self):self.exercise('helper',7)

if __name__=='__main__':unittest.main()
