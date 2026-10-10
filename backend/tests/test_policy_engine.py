"""Synthetic unit tests for deterministic policy decisions; no artifacts execute."""
import unittest

from backend.policy_engine import PolicyDefinitionError, evaluate_policy


def policy(rules=None):
    return {
        'id': 'POL-TEST', 'code': 'TEST-001', 'name': 'Test policy', 'version': '1',
        'target_formats': ['ONNX'], 'rules': rules or [],
    }


def context(**overrides):
    values = {
        'artifactId': 'ART-1', 'format': 'ONNX', 'expectedHash': 'a' * 64,
        'observedHash': 'a' * 64, 'scanStatus': 'COMPLETED', 'findings': [],
        'modelAuditStatus': 'COMPLETED',
        'provenanceStatus': 'VERIFIED', 'signatureStatus': 'VALID',
        'evaluatedAt': '2026-10-09T00:00:00Z',
    }
    values.update(overrides)
    return values


class PolicyEngineTest(unittest.TestCase):
    def test_clean_verified_artifact_approved(self):
        result = evaluate_policy(policy(), context())
        self.assertEqual(result['decision'], 'APPROVED')
        self.assertFalse(result['requiresHumanReview'])

    def test_missing_or_failed_scan_quarantines(self):
        for status in ('NOT_SCANNED', 'FAILED', 'RUNNING'):
            with self.subTest(status=status):
                self.assertEqual(evaluate_policy(policy(), context(scanStatus=status))['decision'], 'QUARANTINED')

    def test_failed_scanner_cannot_be_made_a_blocking_malicious_verdict(self):
        result = evaluate_policy(policy([{
            'code': 'SCAN-FAILED', 'trigger': 'SCAN_FAILED', 'action': 'BLOCK',
        }]), context(scanStatus='FAILED'))
        self.assertEqual(result['decision'], 'QUARANTINED')

    def test_unavailable_modelaudit_quarantines_partial_scan(self):
        result = evaluate_policy(policy(), context(modelAuditStatus='FAILED'))
        self.assertEqual(result['decision'], 'QUARANTINED')
        self.assertIn('modelAuditStatus', result['unknownSignals'])

    def test_confirmed_malicious_evidence_blocks(self):
        result = evaluate_policy(policy([{
            'code': 'MALWARE', 'trigger': 'CONFIRMED_MALICIOUS', 'action': 'BLOCK',
        }]), context(findings=[{'id': 'F-1', 'confirmedMalicious': True, 'evidenceIds': ['E-1']}]))
        self.assertEqual(result['decision'], 'BLOCKED')
        malicious_rule = next(rule for rule in result['ruleEvaluations'] if rule['ruleCode'] == 'MALWARE')
        self.assertEqual(malicious_rule['evidenceRefs'], ['E-1'])

    def test_hash_mismatch_blocks(self):
        result = evaluate_policy(policy([{
            'code': 'HASH', 'trigger': 'HASH_MISMATCH', 'action': 'BLOCK',
        }]), context(observedHash='b' * 64))
        self.assertEqual(result['decision'], 'BLOCKED')

    def test_invalid_required_signature_blocks(self):
        result = evaluate_policy(policy([{
            'code': 'SIGNATURE', 'trigger': 'INVALID_SIGNATURE', 'action': 'BLOCK',
        }]), context(signatureStatus='INVALID'))
        self.assertEqual(result['decision'], 'BLOCKED')

    def test_unknown_mandatory_signature_quarantines(self):
        result = evaluate_policy(policy([{
            'code': 'SIGNATURE', 'trigger': 'INVALID_SIGNATURE', 'action': 'BLOCK',
        }]), context(signatureStatus='UNKNOWN'))
        self.assertEqual(result['decision'], 'QUARANTINED')
        self.assertIn('INVALID_SIGNATURE', result['unknownSignals'])

    def test_mandatory_provenance_block_only_on_configured_action(self):
        rules = [{'code': 'PROVENANCE', 'trigger': 'UNVERIFIED_PROVENANCE', 'action': 'BLOCK'}]
        result = evaluate_policy(policy(rules), context(provenanceStatus='MISSING'))
        self.assertEqual(result['decision'], 'BLOCKED')

    def test_unresolved_critical_is_quarantined_without_block_rule(self):
        result = evaluate_policy(policy(), context(findings=[{'id': 'F-2', 'severity': 'CRITICAL'}]))
        self.assertEqual(result['decision'], 'QUARANTINED')

    def test_warn_finding_is_conditional_and_explained(self):
        result = evaluate_policy(policy([{
            'code': 'LOW-MITIGATION', 'trigger': 'LOW', 'action': 'WARN',
            'remediation': 'Restrict use to staging.',
        }]), context(findings=[{'id': 'F-3', 'severity': 'LOW', 'evidenceIds': ['E-2']}]))
        self.assertEqual(result['decision'], 'CONDITIONAL')
        self.assertEqual(result['ruleEvaluations'][0]['evidenceRefs'], ['E-2'])

    def test_invalid_policy_rule_is_rejected(self):
        with self.assertRaises(PolicyDefinitionError):
            evaluate_policy(policy([{'code': 'UNSAFE', 'trigger': 'PYTHON_EXPR', 'action': 'ALLOW'}]), context())

    def test_invalid_mandatory_flag_is_rejected(self):
        with self.assertRaises(PolicyDefinitionError):
            evaluate_policy(policy([{'code': 'BAD-BOOL', 'trigger': 'HIGH', 'action': 'WARN', 'mandatory': 'false'}]), context())

    def test_unknown_finding_severity_fails_closed(self):
        result = evaluate_policy(policy(), context(findings=[{'id': 'F-UNKNOWN', 'severity': 'SEVERE'}]))
        self.assertEqual(result['decision'], 'QUARANTINED')
        self.assertIn('findingSeverity', result['unknownSignals'])

    def test_missing_hash_never_passes(self):
        result = evaluate_policy(policy(), context(observedHash=None))
        self.assertEqual(result['decision'], 'QUARANTINED')
        self.assertIn('integrityHash', result['unknownSignals'])


if __name__ == '__main__':
    unittest.main()
