#!/usr/bin/env python3
"""发布前及 CI 核对 Git 索引的入口模式，不以本机 chmod 成功冒充远端元数据。"""
from pathlib import Path
import subprocess
import os
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def index_modes(root, env=None):
    raw = subprocess.check_output(['git', '-C', str(root), 'ls-files', '--stage', '-z'], env=env)
    modes = {}
    for record in raw.split(b'\0'):
        if not record:
            continue
        metadata, name = record.split(b'\t', 1)
        mode, _, stage = metadata.decode('ascii').split()
        if stage != '0':
            raise ValueError('unmerged index is not publishable')
        modes[name.decode('utf-8')] = mode
    return modes


def require_shell_entrypoints(modes):
    # Repository-owned shell files are directly callable entrypoints. Third-party
    # source modes must remain upstream evidence, not be rewritten by this policy.
    invalid = [name for name, mode in modes.items()
               if name.endswith('.sh') and not name.startswith('third_party/') and mode != '100755']
    if invalid:
        raise ValueError('non-executable Git shell entrypoints: ' + ', '.join(sorted(invalid)))


def require_preserved_executables(current, parent):
    lost = [name for name, mode in parent.items()
            if mode == '100755' and name in current and current[name] != mode]
    if lost:
        raise ValueError('parent executable mode lost: ' + ', '.join(sorted(lost)))


class ScriptModeTests(unittest.TestCase):
    def test_repository_index_preserves_executable_entrypoints(self):
        require_shell_entrypoints(index_modes(ROOT))

    def test_index_mode_loss_is_rejected_even_if_worktree_is_executable(self):
        with tempfile.TemporaryDirectory(prefix='peerloom-mode-test-') as temporary:
            root = Path(temporary)
            env = {key: value for key, value in os.environ.items() if key not in ('GIT_INDEX_FILE', 'GIT_DIR', 'GIT_WORK_TREE')}
            subprocess.run(['git', 'init', '-q', str(root)], check=True, env=env)
            entry = root / 'entry.sh'
            entry.write_text('#!/bin/sh\nexit 0\n')
            entry.chmod(0o755)
            subprocess.run(['git', '-C', str(root), 'add', '--chmod=+x', 'entry.sh'], check=True, env=env)
            require_shell_entrypoints(index_modes(root, env))
            subprocess.run(['git', '-C', str(root), 'update-index', '--chmod=-x', 'entry.sh'], check=True, env=env)
            with self.assertRaises(ValueError):
                require_shell_entrypoints(index_modes(root, env))

    def test_parent_executable_mode_is_preserved_for_non_shell_entrypoints(self):
        with self.assertRaises(ValueError):
            require_preserved_executables({'probe.py': '100644'}, {'probe.py': '100755'})
        require_preserved_executables({'probe.py': '100755'}, {'probe.py': '100755'})

    def test_new_non_executable_entrypoint_is_rejected(self):
        with self.assertRaises(ValueError):
            require_shell_entrypoints({'scripts/new.sh': '100644'})


if __name__ == '__main__':
    unittest.main()
