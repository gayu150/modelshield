"""Test Member 3 Governance, Policies, Decision Recording, Passport, and Audit Trail."""
import json
import os
import pickle
import tempfile
import threading
import time
import unittest
import urllib.request
import uuid

TEMP = tempfile.TemporaryDirectory(prefix='modelshield-gov-')
os.environ['MODELSHIELD_DATA_DIR'] = TEMP.name

import uvicorn  # noqa: E402
from backend.main import app  # noqa: E402
from backend.store import connect, initialize, password_hash  # noqa: E402
from backend.tests.test_api import Client, multipart  # noqa: E402


class GovernanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        initialize()
        with connect() as db:
            db.execute('''INSERT OR REPLACE INTO users (id, email, name, role, password_hash)
                          VALUES (?, ?, ?, ?, ?)''',
                       ('u-gov-1', 'reviewer@modelshield.local', 'Priya Sharma', 'Security Reviewer',
                        password_hash('gov-password')))
            db.execute('''INSERT OR REPLACE INTO users (id, email, name, role, password_hash)
                          VALUES (?, ?, ?, ?, ?)''',
                       ('u-gov-2', 'other@modelshield.local', 'Other User', 'ML Engineer',
                        password_hash('gov-password')))

        config = uvicorn.Config(app, host='127.0.0.1', port=8099, log_level='error')
        cls.server = uvicorn.Server(config)
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(timeout=5)
        TEMP.cleanup()

    def setUp(self):
        self.client = Client('http://127.0.0.1:8099')
        # Login helper custom for this password
        status, _ = self.client.request('POST', '/auth/login',
                                        {'email': 'reviewer@modelshield.local', 'password': 'gov-password'})
        self.assertEqual(status, 200)
        status, identity = self.client.request('GET', '/auth/me')
        self.assertEqual(status, 200)
        self.client.csrf = identity['csrfToken']

    def test_policies_catalog_endpoint(self):
        status, policies = self.client.request('GET', '/policies')
        self.assertEqual(status, 200)
        self.assertTrue(isinstance(policies, list))
        self.assertTrue(len(policies) >= 3)
        codes = [p['code'] for p in policies]
        self.assertIn('PROD-SEC-004', codes)
        self.assertIn('DEV-SANDBOX-001', codes)
        self.assertIn('FIN-COMPLY-009', codes)

        status, policy = self.client.request('GET', '/policies/POL-PROD-004')
        self.assertEqual(status, 200)
        self.assertEqual(policy['code'], 'PROD-SEC-004')
        self.assertTrue(len(policy['rules']) >= 4)

    def test_governance_decision_passport_and_audit_lifecycle(self):
        # 1. Upload an artifact
        file_bytes = pickle.dumps({'model_weights': [0.1, 0.2, 0.3]})
        body, headers = multipart('governance_model.pkl', file_bytes, model='Gov Model')
        status, artifact = self.client.request('POST', '/artifacts', body, headers)
        self.assertEqual(status, 201)
        artifact_id = artifact['id']
        self.assertEqual(artifact['decision'], 'QUARANTINED')

        # 2. Evaluate policy on artifact
        status, evaluation = self.client.request('POST', f'/artifacts/{artifact_id}/evaluate?policy_id=POL-PROD-004')
        self.assertEqual(status, 200)
        self.assertEqual(evaluation['policyCode'], 'PROD-SEC-004')
        self.assertIn(evaluation['overallOutcome'], ('PASS', 'CONDITIONAL', 'BLOCK'))
        self.assertTrue(len(evaluation['ruleEvaluations']) > 0)

        # 3. CSRF protection on decision endpoint
        no_csrf_client = Client('http://127.0.0.1:8099')
        no_csrf_client.request('POST', '/auth/login',
                               {'email': 'reviewer@modelshield.local', 'password': 'gov-password'})
        # Notice no_csrf_client.csrf is None
        status, err = no_csrf_client.request('POST', f'/artifacts/{artifact_id}/decision',
                                            {'decision': 'APPROVED', 'rationale': 'Direct test'})
        self.assertEqual(status, 403)

        # 4. Record decision with valid CSRF
        status, dec = self.client.request('POST', f'/artifacts/{artifact_id}/decision', {
            'decision': 'APPROVED',
            'rationale': 'Verified clean model without malicious payloads.',
            'conditions': ['Continuous runtime monitoring']
        })
        self.assertEqual(status, 200)
        self.assertEqual(dec['decision'], 'APPROVED')
        self.assertEqual(dec['reviewerName'], 'Priya Sharma')
        self.assertTrue(dec['signature'].startswith('0x'))

        # Verify artifact state updated
        status, updated_art = self.client.request('GET', f'/artifacts/{artifact_id}')
        self.assertEqual(status, 200)
        self.assertEqual(updated_art['decision'], 'APPROVED')

        # 5. Retrieve decision history
        status, history = self.client.request('GET', f'/artifacts/{artifact_id}/decisions')
        self.assertEqual(status, 200)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['id'], dec['id'])

        # 6. Retrieve Model Security Passport
        status, passport = self.client.request('GET', f'/artifacts/{artifact_id}/passport')
        self.assertEqual(status, 200)
        self.assertEqual(passport['status'], 'VALID')
        self.assertTrue(passport['passportNumber'].startswith('MSP-2026-'))
        self.assertEqual(passport['decision']['decision'], 'APPROVED')
        self.assertTrue(passport['verificationSeal']['signature'].startswith('0x'))

        # 7. Verify Evidence Graph includes Policy and Decision nodes
        status, graph = self.client.request('GET', f'/artifacts/{artifact_id}/graph')
        self.assertEqual(status, 200)
        node_kinds = {n['kind'] for n in graph['nodes']}
        self.assertIn('Policy', node_kinds)
        self.assertIn('Decision', node_kinds)
        edge_labels = {e['label'] for e in graph['edges']}
        self.assertIn('evaluated against', edge_labels)
        self.assertIn('yields decision', edge_labels)

        # 8. Verify Audit Trail contains all events
        status, audit = self.client.request('GET', '/audit')
        self.assertEqual(status, 200)
        self.assertTrue(len(audit) >= 4)
        event_types = [a['eventType'] for a in audit]
        self.assertIn('USER_LOGIN', event_types)
        self.assertIn('ARTIFACT_UPLOAD', event_types)
        self.assertIn('POLICY_EVALUATION', event_types)
        self.assertIn('DECISION_RECORDED', event_types)
        self.assertIn('PASSPORT_GENERATED', event_types)


if __name__ == '__main__':
    unittest.main()
