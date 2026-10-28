#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('multi_fixture', Path(__file__).with_name('prepare-multiconnection-fixture.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
APP = '00000000-0000-4000-8000-000000000001'


class FixtureTests(unittest.TestCase):
    def test_existing_output_refused_before_http(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'existing'
            output.write_text('keep')
            with patch.object(fixture.management, 'Client') as client:
                with self.assertRaises(Exception):
                    fixture.prepare('http://127.0.0.1:1', 'unused', output)
                client.assert_not_called()
            self.assertEqual(output.read_text(), 'keep')

    def test_third_registered_and_directionally_granted_before_export(self):
        pair = {'source': {'device_id': 'source'}, 'target': {'application_id': APP}}
        with patch.object(fixture.management, 'Client') as client, \
             patch.object(fixture.management, 'read_fixture', return_value='private'), \
             patch.object(fixture.management, 'exercise', return_value=pair), \
             patch.object(fixture.management, 'write_pair') as write:
            client.return_value.request.side_effect = [
                {'grant': 'secret'}, {'device_id': 'third', 'device_credential': 'private'}, {'id': 'grant'}]
            fixture.prepare('http://127.0.0.1:1', 'input', '/not-existing-peerloom-fixture')
            calls = client.return_value.request.call_args_list
            self.assertEqual(calls[1].kwargs['body']['registration_grant'], 'secret')
            self.assertEqual(calls[2].args[4]['source_device_id'], 'source')
            self.assertEqual(calls[2].args[4]['target_device_id'], 'third')
            self.assertEqual(calls[2].args[4]['max_sessions'], 1)
            self.assertEqual(write.call_args.args[1]['third']['application_id'], APP)

    def test_failed_grant_does_not_export_partial_fixture(self):
        pair = {'source': {'device_id': 'source'}, 'target': {'application_id': APP}}
        with patch.object(fixture.management, 'Client') as client, \
             patch.object(fixture.management, 'read_fixture', return_value='private'), \
             patch.object(fixture.management, 'exercise', return_value=pair), \
             patch.object(fixture.management, 'write_pair') as write:
            client.return_value.request.side_effect = RuntimeError('denied')
            with self.assertRaises(RuntimeError):
                fixture.prepare('http://127.0.0.1:1', 'input', '/not-existing-peerloom-fixture')
            write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
