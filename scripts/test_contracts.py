"""协议结构回归；不替代运行时认证与授权测试。"""
import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
UUID = '9ab274c6-10ca-4eae-bddb-1c4ac23a1351'


def validator(name):
    schema = json.loads((ROOT / 'api' / name).read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


class ContractTests(unittest.TestCase):
    def test_registration_valid_platforms(self):
        check = validator('device-registration.schema.json')
        for platform in ('windows', 'macos', 'linux', 'android', 'ios', 'web'):
            check.validate({'application_id': UUID, 'platform': platform,
                            'installation_public_key': 'opaque-installation-label', 'registration_grant': 'reg_test'})

    def test_registration_negative(self):
        check = validator('device-registration.schema.json')
        valid = {'application_id': UUID, 'platform': 'linux', 'installation_public_key': 'key', 'registration_grant': 'reg_test'}
        bad = [dict(valid, platform='other'), dict(valid, application_id='not-uuid'),
               dict(valid, tenant_id=UUID), dict(valid, metadata={'deep': {'nested': True}}),
               dict(valid, metadata={'text': 'x' * 1025}),
               dict(valid, metadata={str(i): i for i in range(33)})]
        for field in valid:
            case = dict(valid)
            del case[field]
            bad.append(case)
        for case in bad:
            with self.subTest(case=list(case)):
                self.assertFalse(check.is_valid(case))

    def test_signal_fencing_and_negotiation(self):
        check = validator('signal-envelope.schema.json')
        hello = {'v': 1, 'type': 'hello', 'id': UUID, 'seq': 0,
                 'sent_at': '2026-10-28T00:00:00Z', 'payload': {}}
        check.validate(hello)
        offer = dict(hello, type='session.offer', session_id=UUID,
                     connection_generation=1, fencing_token='f' * 16,
                     negotiation_generation=1, payload={'sdp': 'v=0'})
        check.validate(offer)
        cases = [dict(hello, fencing_token='f' * 16), dict(offer, seq=-1),
                 dict(offer, v=2), dict(offer, type='unknown'),
                 dict(offer, sent_at='not-time'), dict(offer, id='bad'),
                 dict(offer, payload={'sdp': 'x' * 65537})]
        for field in ('connection_generation', 'fencing_token', 'negotiation_generation', 'session_id'):
            case = copy.deepcopy(offer)
            del case[field]
            cases.append(case)
        for case in cases:
            self.assertFalse(check.is_valid(case))

    def test_openapi_only_implemented_endpoints(self):
        api = json.loads((ROOT / 'api/openapi.json').read_text())
        self.assertEqual(set(api['paths']), {'/healthz', '/readyz', '/metrics', '/v1/device-registrations', '/v1/device-self', '/v1/device-credentials/refresh'})
        for path in api['paths'].values():
            operation = next(iter(path.values()))
            self.assertTrue({'200', '201'} & set(operation['responses']))
        Draft202012Validator.check_schema(api['components']['schemas']['Problem'])


if __name__ == '__main__':
    unittest.main()
