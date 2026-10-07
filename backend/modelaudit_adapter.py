"""Bounded ModelAudit CLI adapter. Scanner output is untrusted input."""
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from .config import DATA_DIR
from .scanner import digest, utc_now

MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_ISSUES = 1000
SEVERITIES = {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM',
              'low': 'LOW', 'info': 'INFO', 'informational': 'INFO'}


class ScannerUnavailable(RuntimeError):
    pass


def scanner_binary():
    configured = os.getenv('MODELSHIELD_MODELAUDIT_BIN')
    if configured:
        binary = Path(configured).resolve()
        return str(binary) if binary.is_file() else None
    local = Path(__file__).parent / '.venv-scanner' / 'Scripts' / 'modelaudit.exe'
    if local.is_file():
        return str(local)
    local_unix = Path(__file__).parent / '.venv-scanner' / 'bin' / 'modelaudit'
    if local_unix.is_file():
        return str(local_unix)
    return shutil.which('modelaudit')


def normalize(report: dict, artifact_id: str, scan_id: str):
    if not isinstance(report, dict) or report.get('has_errors') or report.get('success') is not True:
        raise ScannerUnavailable('ModelAudit did not complete successfully.')
    issues = report.get('issues')
    if not isinstance(issues, list) or len(issues) > MAX_ISSUES:
        raise ScannerUnavailable('ModelAudit returned an invalid or excessive issue list.')
    findings, evidence = [], []
    for issue in issues:
        if not isinstance(issue, dict):
            raise ScannerUnavailable('ModelAudit returned an invalid issue.')
        severity = SEVERITIES.get(str(issue.get('severity', '')).lower())
        if severity is None:
            raise ScannerUnavailable('ModelAudit returned an unknown severity.')
        message = str(issue.get('message') or 'Scanner issue')[:1000]
        rule = str(issue.get('rule_code') or issue.get('type') or 'UNKNOWN')[:100]
        finding_id, evidence_id = str(uuid.uuid4()), str(uuid.uuid4())
        details = issue.get('details') if isinstance(issue.get('details'), dict) else {}
        position = details.get('position')
        location = ('Byte ' + str(position) if isinstance(position, int) and position >= 0
                    else 'Artifact content')
        findings.append({'id': finding_id, 'title': message, 'severity': severity,
                         'description': str(issue.get('why') or message)[:2000],
                         'scanner': 'ModelAudit', 'scannerVersion': '0.2.52',
                         'findingType': rule, 'evidenceIds': [evidence_id],
                         'recommendation': 'Review the scanner evidence and artifact origin before release.'})
        evidence.append({'id': evidence_id, 'artifactId': artifact_id, 'scanId': scan_id,
                         'title': rule + ' evidence', 'kind': 'STATIC_ANALYSIS',
                         'timestamp': utc_now(), 'summary': message, 'content': location,
                         'source': 'ModelAudit', 'findingType': rule, 'severity': severity,
                         'location': location, 'verificationStatus': 'OBSERVED',
                         'scanner': 'ModelAudit'})
    return findings, evidence


def scan(path: Path, extension: str, artifact_id: str, scan_id: str, observed_hash: str):
    binary = scanner_binary()
    if not binary:
        raise ScannerUnavailable('ModelAudit is not installed.')
    with tempfile.TemporaryDirectory(prefix='modelaudit-', dir=DATA_DIR) as directory:
        root = Path(directory)
        aliased = root / ('artifact' + extension)
        shutil.copyfile(path, aliased)
        aliased.chmod(0o444)
        if digest(aliased) != observed_hash:
            raise ScannerUnavailable('Artifact bytes changed while preparing the external scan.')
        output = root / 'report.json'
        environment = {'PATH': os.environ.get('PATH', ''), 'SYSTEMROOT': os.environ.get('SYSTEMROOT', ''),
                       'USERPROFILE': str(root), 'APPDATA': str(root), 'LOCALAPPDATA': str(root),
                       'TEMP': str(root), 'TMP': str(root), 'NO_ANALYTICS': '1',
                       'PROMPTFOO_DISABLE_TELEMETRY': '1', 'HF_HUB_OFFLINE': '1',
                       'TRANSFORMERS_OFFLINE': '1'}
        try:
            result = subprocess.run([binary, 'scan', str(aliased), '--format', 'json',
                                     '--no-cache', '--output', str(output)],
                                    cwd=root, env=environment, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ScannerUnavailable('ModelAudit could not complete within the scan limit.') from exc
        if result.returncode not in (0, 1) or not output.is_file() or output.stat().st_size > MAX_REPORT_BYTES:
            raise ScannerUnavailable('ModelAudit failed or returned no bounded report.')
        try:
            report = json.loads(output.read_text(encoding='utf-8'))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ScannerUnavailable('ModelAudit returned invalid JSON.') from exc
        return normalize(report, artifact_id, scan_id)
