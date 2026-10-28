#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""Parse the actual Swift package from inside/outside cwd; never creates a fake binary."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def verify(packaged, source):
    packaged = Path(packaged).resolve(strict=True)
    source = Path(source).resolve(strict=True)
    relative = 'Artifacts/CPeerloom.xcframework'
    if not (packaged / relative).is_dir() or (source / relative).exists():
        raise ValueError('expected real built package and unbundled source package')
    if (packaged / 'Package.swift').read_bytes() != (source / 'Package.swift').read_bytes():
        raise ValueError('packaged manifest must match canonical source')
    with tempfile.TemporaryDirectory(prefix='peerloom-package-cwd-') as unrelated:
        for package, expected in ((packaged, 'binary'), (source, 'system')):
            for cwd in (package, Path(unrelated)):
                result = subprocess.run(['swift', 'package', '--package-path', str(package), 'dump-package'],
                                        cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, timeout=35)
                if result.returncode:
                    raise ValueError('swift package dump-package failed with exit ' + str(result.returncode))
                if len(result.stdout) > 1024 * 1024:
                    raise ValueError('unexpected manifest output size')
                manifest = json.loads(result.stdout)
                native = [target for target in manifest['targets'] if target['name'] == 'CPeerloom']
                if len(native) != 1 or native[0]['type'] != expected:
                    raise ValueError('CPeerloom target kind depends on caller cwd or artifact selection is wrong')
                if expected == 'binary' and native[0].get('path') != relative:
                    raise ValueError('binary target path must remain package-relative')
    print('Actual Swift manifest parsed in 4 cwd/package combinations: binary release, system source')


if __name__ == '__main__':
    try:
        if len(sys.argv) != 3:
            raise ValueError('built and source package paths required')
        verify(sys.argv[1], sys.argv[2])
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        label = str(error) if isinstance(error, ValueError) else type(error).__name__
        print('Swift package resolution failed: ' + label, file=sys.stderr)
        raise SystemExit(1)
