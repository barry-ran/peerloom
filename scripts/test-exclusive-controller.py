#!/usr/bin/env python3
"""Controller safety tests; these do not substitute actual SDK acceptance."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location('exclusive', Path(__file__).with_name('test-exclusive.py'))
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)


class Failure(Exception):
    pass


class ControllerTests(unittest.TestCase):
    def cap(self):
        value = Mock()
        value.Failure = Failure
        value.require.side_effect = lambda good, label: None if good else (_ for _ in ()).throw(Failure(label))
        return value

    def test_new_output_is_private(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'proof'
            self.assertEqual(controller.create_output(path, self.cap()), path.resolve())
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_existing_output_is_never_adopted(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(FileExistsError):
                controller.create_output(Path(root), self.cap())

    def test_symbolic_link_is_never_adopted(self):
        with tempfile.TemporaryDirectory() as root:
            link = Path(root) / 'link'
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(FileExistsError):
                controller.create_output(link, self.cap())

    def test_cleanup_failure_cannot_pass(self):
        cap = self.cap()
        cap.cleanup.side_effect = Failure('owned process')
        result = {'status': 'passed'}
        controller.finish_cleanup(cap, [], [], result)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['failure_stage'], 'cleanup')

    def test_live_child_cannot_pass(self):
        result = {'status': 'passed'}
        controller.finish_cleanup(self.cap(), [Mock(poll=lambda: None)], [], result)
        self.assertFalse(result['owned_processes_reaped'])
        self.assertEqual(result['status'], 'failed')

    def test_reaped_children_preserve_actual_result(self):
        for state in ('passed', 'failed'):
            result = {'status': state}
            controller.finish_cleanup(self.cap(), [Mock(poll=lambda: 0)], [], result)
            self.assertTrue(result['owned_processes_reaped'])
            self.assertEqual(result['status'], state)


if __name__ == '__main__':
    unittest.main()
