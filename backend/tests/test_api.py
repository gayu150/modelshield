"""Exercise the HTTP contract against a disposable local database and server."""
import http.cookiejar
import json
import os
import pickle
import socket
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import uuid

TEMP = tempfile.TemporaryDirectory(prefix='modelshield-api-')
os.environ['MODELSHIELD_DATA_DIR'] = TEMP.name

import uvicorn  # noqa: E402
from backend.main import app  # noqa: E402
from backend.modelaudit_adapter import ScannerUnavailable  # noqa: E402
from backend.store import connect, password_hash  # noqa: E402


class Client:
    def __init__(self, base):
        self.base = base
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.csrf = None

    def request(self, method, path, body=None, headers=None):
        options = dict(headers or {})
        if body is not None and not isinstance(body, bytes):
            body = json.dumps(body).encode()
            options['Content-Type'] = 'application/json'
        if method != 'GET' and self.csrf:
            options.setdefault('X-CSRF-Token', self.csrf)
        request = urllib.request.Request(self.base + path, body, options, method=method)
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        content = response.read()
        return response.status, json.loads(content) if content else None

    def login(self, email):
        status, _ = self.request('POST', '/auth/login',
                                 {'email': email, 'password': 'integration-only-password'})
        assert status == 200
        status, identity = self.request('GET', '/auth/me')
        assert status == 200
        self.csrf = identity['csrfToken']


def multipart(filename, data, model='Demo model', source='Test registry'):
    boundary = 'ModelShield' + uuid.uuid4().hex
    parts = []
    for key, value in [('model_name', model), ('version', '1.0'), ('source', source)]:
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n').encode())
    parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                  'Content-Type: application/octet-stream\r\n\r\n').encode())
    parts += [data, f'\r\n--{boundary}--\r\n'.encode()]
    return b''.join(parts), {'Content-Type': f'multipart/form-data; boundary={boundary}'}


class APITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        cls.server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=port,
                                                  log_level='error', access_log=False))
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        for _ in range(100):
            if cls.server.started:
                break
            time.sleep(0.05)
        if not cls.server.started:
            raise RuntimeError('Test server did not start.')
        cls.base = f'http://127.0.0.1:{port}'
        with connect() as db:
            for email in ('first@example.test', 'second@example.test'):
                db.execute('INSERT INTO users VALUES (?, ?, ?, ?, ?)',
                           (str(uuid.uuid4()), email, email, 'analyst',
                            password_hash('integration-only-password')))

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(timeout=5)
        TEMP.cleanup()

    def test_authentication_csrf_artifact_scan_and_isolation(self):
        first = Client(self.base)
        self.assertEqual(first.request('GET', '/artifacts')[0], 401)
        self.assertEqual(first.request('POST', '/auth/login',
                                       {'email': 'first@example.test', 'password': 'wrong'})[0], 401)
        first.login('first@example.test')
        file_bytes = pickle.dumps(eval)
        body, headers = multipart('model.pkl', file_bytes)
        first.csrf = None
        self.assertEqual(first.request('POST', '/artifacts', body, headers)[0], 403)
        first.csrf = first.request('GET', '/auth/me')[1]['csrfToken']
        status, artifact = first.request('POST', '/artifacts', body, headers)
        self.assertEqual(status, 201)
        self.assertEqual(artifact['decision'], 'QUARANTINED')
        self.assertEqual(artifact['source'] if 'source' in artifact else artifact['provenance']['source'], 'Test registry')
        self.assertEqual(artifact['provenance']['verificationStatus'], 'UNVERIFIED')
        self.assertEqual(len(artifact['hash']), 64)
        artifact_id = artifact['id']
        self.assertEqual(first.request('GET', '/artifacts/' + artifact_id + '/findings')[1], [])
        status, scan = first.request('POST', '/artifacts/' + artifact_id + '/scan')
        self.assertEqual(status, 202)
        for _ in range(100):
            state = first.request('GET', '/scans/' + scan['scan_id'])[1]['status']
            if state in ('COMPLETED', 'FAILED'):
                break
            time.sleep(0.05)
        self.assertEqual(state, 'COMPLETED')
        self.assertEqual(first.request('GET', '/artifacts/' + artifact_id)[1]['decision'], 'BLOCKED')
        findings = first.request('GET', '/artifacts/' + artifact_id + '/findings')[1]
        self.assertTrue(any(item['severity'] == 'HIGH' for item in findings))
        self.assertTrue(any(item['scanner'] == 'ModelAudit' and item['severity'] == 'CRITICAL'
                            for item in findings))
        evidence = first.request('GET', '/artifacts/' + artifact_id + '/evidence')[1]
        self.assertTrue(evidence)
        self.assertTrue(any(item['scanner'] == 'ModelAudit' and item['artifactId'] == artifact_id
                            and item['verificationStatus'] == 'OBSERVED' for item in evidence))
        self.assertEqual(first.request('GET', '/findings/' + findings[0]['id'])[1]['id'], findings[0]['id'])
        graph = first.request('GET', '/artifacts/' + artifact_id + '/graph')[1]
        self.assertTrue(graph['edges'])
        self.assertTrue({'Artifact', 'Hash', 'Provenance', 'Finding', 'Evidence', 'Scanner'} <=
                        {node['kind'] for node in graph['nodes']})
        risk = first.request('GET', '/artifacts/' + artifact_id + '/risk')[1]
        self.assertEqual(risk['state'], 'INVESTIGATE')
        self.assertEqual(risk['integrity'], 'MATCH')
        self.assertEqual(risk['signature'], 'UNKNOWN')
        self.assertEqual(first.request('GET', '/artifacts/' + artifact_id)[1]['provenance']['signatureStatus'], 'UNKNOWN')
        second = Client(self.base)
        second.login('second@example.test')
        self.assertEqual(second.request('GET', '/artifacts')[1], [])
        for path in ('/artifacts/' + artifact_id, '/artifacts/' + artifact_id + '/evidence',
                     '/artifacts/' + artifact_id + '/graph', '/artifacts/' + artifact_id + '/risk',
                     '/findings/' + findings[0]['id'],
                     '/scans/' + scan['scan_id']):
            self.assertEqual(second.request('GET', path)[0], 404)
        self.assertEqual(first.request('POST', '/auth/logout')[0], 204)
        self.assertEqual(first.request('GET', '/auth/me')[0], 401)

    def test_rejects_disguised_upload_and_invalid_json_without_echoing_secrets(self):
        client = Client(self.base)
        client.login('first@example.test')
        body, headers = multipart('disguised.zip', b'not-a-zip')
        self.assertEqual(client.request('POST', '/artifacts', body, headers)[0], 422)
        status, error = client.request('POST', '/auth/login', b'{"password":"private-value"',
                                       {'Content-Type': 'application/json'})
        self.assertEqual(status, 422)
        self.assertNotIn('private-value', json.dumps(error))

    def test_modelaudit_failure_preserves_structural_scan_and_quarantines(self):
        client = Client(self.base)
        client.login('first@example.test')
        header = b'{"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
        artifact_bytes = struct.pack('<Q', len(header)) + header + b'\x00' * 4
        body, headers = multipart('partial-scan.safetensors', artifact_bytes)
        status, artifact = client.request('POST', '/artifacts', body, headers)
        self.assertEqual(status, 201)

        with patch('backend.main.modelaudit_scan', side_effect=ScannerUnavailable(
            'ModelAudit failed or returned no bounded report.')):
            status, scan = client.request('POST', f"/artifacts/{artifact['id']}/scan")
            self.assertEqual(status, 202)
            for _ in range(100):
                scan_result = client.request('GET', f"/scans/{scan['scan_id']}")[1]
                if scan_result['status'] in ('COMPLETED', 'FAILED'):
                    break
                time.sleep(0.05)

        self.assertEqual(scan_result['status'], 'COMPLETED')
        self.assertEqual(scan_result['modelAuditStatus'], 'FAILED')
        self.assertIn('bounded report', scan_result['modelAuditError'])
        findings = client.request('GET', f"/artifacts/{artifact['id']}/findings")[1]
        self.assertTrue(any('structural' in finding['scanner'].lower() for finding in findings))
        self.assertEqual(client.request('GET', f"/artifacts/{artifact['id']}")[1]['decision'], 'QUARANTINED')

    def test_login_rate_limit_and_expired_session(self):
        client = Client(self.base)
        for _ in range(5):
            self.assertEqual(client.request('POST', '/auth/login',
                           {'email': 'unregistered@example.test', 'password': 'wrong'})[0], 401)
        self.assertEqual(client.request('POST', '/auth/login',
                         {'email': 'unregistered@example.test', 'password': 'wrong'})[0], 429)
        client.login('second@example.test')
        user_id = client.request('GET', '/auth/me')[1]['id']
        with connect() as db:
            db.execute('UPDATE sessions SET expires_at = 0 WHERE user_id = ?', (user_id,))
        self.assertEqual(client.request('GET', '/auth/me')[0], 401)


if __name__ == '__main__':
    unittest.main()
