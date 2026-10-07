"""ModelAudit output is normalized without trusting its text or status."""
import unittest

from backend.modelaudit_adapter import ScannerUnavailable, normalize


class ModelAuditAdapterTest(unittest.TestCase):
    def test_issue_is_linked_to_artifact_without_leaking_absolute_location(self):
        report = {'success': True, 'has_errors': False, 'issues': [{
            'message': 'Dangerous global reference', 'severity': 'critical',
            'rule_code': 'S104', 'why': 'Can execute code.',
            'location': r'C:\private\artifact.pkl (pos 29)',
            'details': {'position': 29, 'pickle_source': r'C:\private\artifact.pkl'},
        }]}
        findings, evidence = normalize(report, 'artifact-1', 'scan-1')
        self.assertEqual(findings[0]['evidenceIds'], [evidence[0]['id']])
        self.assertEqual(evidence[0]['artifactId'], 'artifact-1')
        self.assertEqual(evidence[0]['scanId'], 'scan-1')
        self.assertEqual(evidence[0]['location'], 'Byte 29')
        self.assertNotIn('C:\\private', str(evidence))

    def test_errors_and_unknown_severity_cannot_become_clean_scans(self):
        for report in ({'success': False, 'issues': []},
                       {'success': True, 'has_errors': True, 'issues': []},
                       {'success': True, 'issues': [{'severity': 'other'}]}):
            with self.subTest(report=report), self.assertRaises(ScannerUnavailable):
                normalize(report, 'artifact-1', 'scan-1')


if __name__ == '__main__':
    unittest.main()
