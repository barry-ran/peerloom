#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('diagnostics', Path(__file__).with_name('sanitize-diagnostics.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DiagnosticsTest(unittest.TestCase):
    def test_classes_and_frames_drop_message(self):
        self.assertEqual(module.sanitize('E/AndroidRuntime: java.lang.IllegalStateException: dev_SECRET reg_SECRET'), 'exception_class=java.lang.IllegalStateException')
        self.assertEqual(module.sanitize('E/AndroidRuntime: at io.peerloom.sdk.StoreProcessTest.test(StoreProcessTest.kt:42) dev_SECRET'), 'at io.peerloom.sdk.StoreProcessTest.test(StoreProcessTest.kt:42)')

    def test_system_reason_is_only_boolean(self):
        self.assertEqual(module.sanitize('I/ActivityManager: Killing 123:io.peerloom.sdk.test/u0a: instrumentation finished dev_SECRET'), 'process_killed pid=123 instrumentation_reason=True')
        self.assertEqual(module.sanitize('I/ActivityManager: Process io.peerloom.sdk.test:storeProbe (pid 456) has died: dev_SECRET'), 'process_died name=io.peerloom.sdk.test:storeProbe pid=456')

    def test_unstructured_and_other_processes_rejected(self):
        for line in ['Authorization: Bearer dev_SECRET', 'payload=private', 'Process other.app (pid 12) has died', 'Abort message: private']:
            self.assertIsNone(module.sanitize(line))

    def test_instrumented_process_identity(self):
        self.assertEqual(module.sanitize('Crash of app io.peerloom.sdk.test running instrumentation secret'), 'instrumented_process_crashed name=io.peerloom.sdk.test')
        self.assertEqual(module.sanitize('Crash of app io.peerloom.sdk.test:storeProbe running instrumentation secret'), 'instrumented_process_crashed name=io.peerloom.sdk.test:storeProbe')

    def test_native_and_checkjni_categories(self):
        self.assertEqual(module.sanitize('Fatal signal 6 (SIGABRT), code -1, secret'), 'native fatal signal=6 category=SIGABRT')
        self.assertEqual(module.sanitize('JNI DETECTED ERROR IN APPLICATION: secret'), 'CheckJNI detected an error')


if __name__ == '__main__':
    unittest.main()
