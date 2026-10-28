"""协议结构回归；不替代运行时认证与授权测试。"""
import copy
from datetime import datetime
import re
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
UUID = '9ab274c6-10ca-4eae-bddb-1c4ac23a1351'
FORMATS = FormatChecker()


@FORMATS.checks('date-time', raises=ValueError)
def check_rfc3339(value):
    if not isinstance(value, str):
        return True
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})', value):
        return False
    return datetime.fromisoformat(value.replace('Z', '+00:00')).tzinfo is not None


def validator(name):
    schema = json.loads((ROOT / 'api' / name).read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FORMATS)


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
        expected = {
            '/healthz': {'get'}, '/readyz': {'get'}, '/metrics': {'get'},
            '/v1/device-registrations': {'post'}, '/v1/device-self': {'get'},
            '/v1/device-credentials/refresh': {'post'}, '/v1/device-signal': {'get'},
            '/v1/bootstrap': {'get'}, '/v1/applications': {'get', 'post'},
            '/v1/applications/{id}': {'get', 'patch'},
            '/v1/registration-grants': {'post'}, '/v1/devices': {'get'},
            '/v1/devices/{id}': {'get', 'patch'}, '/v1/devices/{id}/revoke': {'post'},
            '/v1/connection-grants': {'get', 'post'},
            '/v1/connection-grants/{id}': {'get', 'delete'},
            '/v1/sessions': {'get'}, '/v1/sessions/{id}': {'get'},
            '/v1/sessions/{id}/terminate': {'post'}, '/v1/audit-events': {'get'},
        }
        self.assertEqual(set(api['paths']), set(expected))
        for name, methods in expected.items():
            self.assertEqual(set(api['paths'][name]), methods)
            for operation in api['paths'][name].values():
                self.assertTrue({'101', '200', '201'} & set(operation['responses']))
                for requirement in operation.get('security', []):
                    for scheme in requirement:
                        self.assertIn(scheme, api['components']['securitySchemes'])
        for schema in api['components']['schemas'].values():
            Draft202012Validator.check_schema(schema)

    def test_openapi_local_references_resolve(self):
        api = json.loads((ROOT / 'api/openapi.json').read_text())

        def walk(value):
            if isinstance(value, dict):
                reference = value.get('$ref', '')
                if reference.startswith('#/'):
                    target = api
                    for part in reference[2:].split('/'):
                        target = target[part.replace('~1', '/').replace('~0', '~')]
                    self.assertIsInstance(target, dict)
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(api)

    def management_validator(self, name):
        api = json.loads((ROOT / 'api/openapi.json').read_text())
        return Draft202012Validator({
            '$ref': '#/components/schemas/' + name,
            'components': api['components'],
        }, format_checker=FORMATS)

    def test_management_authentication_and_mutations(self):
        api = json.loads((ROOT / 'api/openapi.json').read_text())
        operations = 0
        for path, methods in api['paths'].items():
            for method, operation in methods.items():
                if '租户管理' not in operation.get('tags', []):
                    continue
                operations += 1
                self.assertEqual(operation['security'], [{'TenantServiceCredential': []}])
                scope = 'read' if method == 'get' else 'admin'
                self.assertEqual(operation['x-required-service-scope'], scope)
                if method != 'get':
                    key = next(p for p in operation['parameters'] if p['name'] == 'Idempotency-Key')
                    self.assertTrue(key['required'])
                    self.assertEqual(key['schema']['minLength'], 8)
                    self.assertEqual(key['schema']['maxLength'], 128)
                if '{id}' in path:
                    parameter = next(p for p in operation['parameters'] if p['in'] == 'path')
                    self.assertTrue(parameter['required'])
                    self.assertEqual(parameter['schema']['format'], 'uuid')
        self.assertEqual(operations, 17)

    def test_management_patch_preserves_null_and_rejects_empty(self):
        device = self.management_validator('ManagementDevicePatch')
        app = self.management_validator('ManagementApplicationPatch')
        for value in ({'connectable': False}, {'max_connections': 0},
                      {'max_connections': None}, {'metadata': {}}, {'tags': {'role': 'sensor'}}):
            device.validate(value)
        for value in ({}, {'status': 'active'}, {'tenant_id': UUID},
                      {'connectable': None}, {'metadata': {'nested': {}}},
                      {'max_connections': -1}, {'max_connections': 1025}):
            self.assertFalse(device.is_valid(value))
        for value in ({'enabled': False}, {'max_connections': 0}, {'name': '新名称'}):
            app.validate(value)
        for value in ({}, {'enabled': None}, {'registration_mode': 'direct'},
                      {'name': ''}, {'max_connections': 1025}):
            self.assertFalse(app.is_valid(value))

    def test_management_grant_and_properties_bounds(self):
        registration = self.management_validator('ManagementRegistrationGrantCreate')
        registration.validate({'application_id': UUID})
        self.assertFalse(registration.is_valid({'application_id': UUID, 'expires_in_seconds': 3601}))
        self.assertFalse(registration.is_valid({'application_id': UUID, 'tenant_id': UUID}))
        grant = self.management_validator('ManagementConnectionGrantCreate')
        valid = {'source_device_id': UUID,
                 'target_device_id': '9ab274c6-10ca-4eae-bddb-1c4ac23a1352',
                 'expires_in_seconds': 60}
        grant.validate(valid)
        absolute = {key: value for key, value in valid.items() if key != 'expires_in_seconds'}
        absolute['expires_at'] = '2027-01-01T00:00:00Z'
        grant.validate(absolute)
        grant.validate(dict(absolute, expires_at='2027-01-01T08:00:00+08:00'))
        self.assertFalse(grant.is_valid(dict(absolute, expires_in_seconds=60)))
        self.assertFalse(grant.is_valid(dict(absolute, expires_at='not-time')))
        self.assertFalse(grant.is_valid({key: value for key, value in absolute.items() if key != 'expires_at'}))
        for value in (dict(valid, expires_in_seconds=0), dict(valid, max_sessions=1025),
                      dict(valid, expiry_action='ignore'), dict(valid, tenant_id=UUID)):
            self.assertFalse(grant.is_valid(value))
        properties = self.management_validator('ManagementProperties')
        properties.validate({'active': False, 'count': 0, 'label': '温度', 'empty': None})
        for value in ({'bad': []}, {'bad': {'nested': 1}}, {'bad': 'x' * 1025},
                      {'bad\x00': True}, {str(i): i for i in range(33)}):
            self.assertFalse(properties.is_valid(value))

    def test_management_response_shapes_and_page_bounds(self):
        api = json.loads((ROOT / 'api/openapi.json').read_text())
        for name in ('Application', 'Device', 'ConnectionGrant', 'Session', 'AuditEvent'):
            check = self.management_validator('Management' + name + 'Page')
            check.validate({'items': [], 'next_cursor': 'opaque'})
            self.assertEqual(api['components']['schemas']['Management' + name + 'Page']
                             ['properties']['items']['maxItems'], 100)
        device_schema = api['components']['schemas']['ManagementDevice']
        self.assertEqual(device_schema['properties']['online']['anyOf'][1], {'type': 'null'})
        list_device = api['paths']['/v1/devices']['get']
        self.assertEqual({p['name'] for p in list_device['parameters']},
                         {'limit', 'cursor', 'application_id', 'online', 'tags'})
        self.assertNotIn('/v1/relay-nodes', api['paths'])
        self.assertNotIn('/v1/webhook-endpoints', api['paths'])



if __name__ == '__main__':
    unittest.main()
