"""Deterministic, explainable policy evaluation over persisted scan signals."""
from __future__ import annotations

import hmac
from collections.abc import Mapping, Sequence


SUPPORTED_TRIGGERS = {
    'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'ANY_FINDING',
    'HASH_MISMATCH', 'UNVERIFIED_PROVENANCE', 'UNVERIFIED_SIGNATURE',
    'INVALID_SIGNATURE', 'CONFIRMED_MALICIOUS', 'SCAN_FAILED',
    'SCAN_INCOMPLETE', 'UNSUPPORTED_FORMAT',
}
SUPPORTED_ACTIONS = {'BLOCK', 'QUARANTINE', 'WARN', 'CONDITIONAL', 'ALLOW'}
SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
PRECEDENCE = {'APPROVED': 0, 'CONDITIONAL': 1, 'QUARANTINED': 2, 'BLOCKED': 3}


class PolicyDefinitionError(ValueError):
    """Raised when a stored policy contains an unsupported or unsafe rule."""


def validate_policy(policy: Mapping) -> list[dict]:
    if not isinstance(policy, Mapping) or not policy.get('id') or not policy.get('code') or not policy.get('version'):
        raise PolicyDefinitionError('Policy identity and version are required.')
    raw_rules = policy.get('rules')
    if not isinstance(raw_rules, Sequence) or isinstance(raw_rules, (str, bytes)):
        raise PolicyDefinitionError('Policy rules must be a list.')
    rules: list[dict] = []
    codes: set[str] = set()
    for raw in raw_rules:
        if not isinstance(raw, Mapping):
            raise PolicyDefinitionError('Each policy rule must be an object.')
        code = raw.get('code')
        trigger = raw.get('trigger')
        action = raw.get('action', 'BLOCK')
        if not isinstance(code, str) or not code.strip() or code in codes:
            raise PolicyDefinitionError('Policy rule codes must be present and unique.')
        if trigger not in SUPPORTED_TRIGGERS:
            raise PolicyDefinitionError(f'Unsupported policy trigger: {trigger}.')
        if action not in SUPPORTED_ACTIONS:
            raise PolicyDefinitionError(f'Unsupported policy action: {action}.')
        if not isinstance(raw.get('enabled', True), bool):
            raise PolicyDefinitionError(f'Rule {code} enabled must be a boolean.')
        if 'mandatory' in raw and not isinstance(raw['mandatory'], bool):
            raise PolicyDefinitionError(f'Rule {code} mandatory must be a boolean.')
        if 'nonWaivable' in raw and not isinstance(raw['nonWaivable'], bool):
            raise PolicyDefinitionError(f'Rule {code} nonWaivable must be a boolean.')
        mandatory = bool(raw.get('mandatory', action == 'BLOCK'))
        non_waivable = bool(raw.get('nonWaivable', action == 'BLOCK'))
        if non_waivable and not mandatory:
            raise PolicyDefinitionError(f'Non-waivable rule {code} must be mandatory.')
        if non_waivable and action not in {'BLOCK', 'QUARANTINE'}:
            raise PolicyDefinitionError(f'Non-waivable rule {code} must block or quarantine on failure.')
        if mandatory and action == 'ALLOW':
            raise PolicyDefinitionError(f'Mandatory rule {code} cannot allow a failed condition.')
        priority = raw.get('priority', 100)
        if not isinstance(priority, int) or isinstance(priority, bool):
            raise PolicyDefinitionError(f'Rule {code} priority must be an integer.')
        rule = dict(raw)
        rule.update({'mandatory': mandatory, 'nonWaivable': non_waivable, 'priority': priority})
        rules.append(rule)
        codes.add(code)
    return sorted(rules, key=lambda rule: (rule['priority'], rule['code']))


def evaluate_policy(policy: Mapping, context: Mapping) -> dict:
    """Evaluate trusted backend context; no user expressions or code are run."""
    rules = validate_policy(policy)
    artifact_id = context.get('artifactId')
    if not isinstance(artifact_id, str) or not artifact_id:
        raise ValueError('Artifact identity is required for evaluation.')
    scan_status = context.get('scanStatus', 'NOT_SCANNED')
    modelaudit_status = context.get('modelAuditStatus', 'UNKNOWN')
    findings = context.get('findings', [])
    if not isinstance(findings, list):
        raise ValueError('Findings must be a normalized list.')
    expected_hash = context.get('expectedHash')
    observed_hash = context.get('observedHash')
    format_name = str(context.get('format', '')).upper()
    source_fields = context.get('provenanceFields', [])
    signature_status = context.get('signatureStatus', 'UNKNOWN')
    evidence_by_finding = {str(f.get('id')): f.get('evidenceIds', []) for f in findings if isinstance(f, Mapping)}

    results: list[dict] = []
    decisions: list[str] = []
    unknown_signals: list[str] = []
    if str(signature_status).upper() in {'UNKNOWN', 'UNAVAILABLE'}:
        unknown_signals.append('signatureStatus')

    def append_result(rule: Mapping, result: str, reason: str, evidence_refs: list[str] | None = None):
        action = rule.get('action', 'BLOCK')
        if result in {'FAIL', 'UNKNOWN'}:
            if result == 'UNKNOWN':
                decisions.append('QUARANTINED')
            elif action == 'BLOCK':
                decisions.append('BLOCKED')
            elif action in {'QUARANTINE'} or (result == 'UNKNOWN' and rule['mandatory']):
                decisions.append('QUARANTINED')
            elif action in {'WARN', 'CONDITIONAL'}:
                decisions.append('CONDITIONAL')
        results.append({
            'ruleId': rule.get('id', rule['code']), 'ruleCode': rule['code'],
            'ruleTitle': rule.get('title', rule['code']), 'passed': result == 'PASS',
            'result': result, 'action': action, 'reason': reason,
            'mandatory': rule['mandatory'], 'nonWaivable': rule['nonWaivable'],
            'evidenceRefs': sorted(set(evidence_refs or [])),
            'remediation': rule.get('remediation', rule.get('description', '')),
        })

    # Required scan state is a hard gate; an absent/failed scanner is never a clean result.
    if scan_status != 'COMPLETED':
        synthetic = {'id': 'SYSTEM-SCAN-COMPLETE', 'code': 'SYSTEM-SCAN-COMPLETE',
                     'title': 'Required security scan completed', 'action': 'QUARANTINE',
                     'mandatory': True, 'nonWaivable': True, 'remediation': 'Complete a successful scan before release.'}
        reason = f'Scan state is {scan_status}; completed scan evidence is required.'
        append_result(synthetic, 'UNKNOWN', reason)
        unknown_signals.append('scanStatus')

    if modelaudit_status != 'COMPLETED':
        synthetic = {'id': 'SYSTEM-MODELAUDIT-COMPLETE', 'code': 'SYSTEM-MODELAUDIT-COMPLETE',
                     'title': 'ModelAudit completed with a bounded report', 'action': 'QUARANTINE',
                     'mandatory': True, 'nonWaivable': True,
                     'remediation': 'Restore ModelAudit scanner availability and rerun the security scan.'}
        append_result(synthetic, 'UNKNOWN', f'ModelAudit state is {modelaudit_status}; scanner coverage is incomplete.')
        unknown_signals.append('modelAuditStatus')

    unsupported_severity = [finding for finding in findings if isinstance(finding, Mapping)
                            and str(finding.get('severity', '')).upper() not in SEVERITIES]
    if unsupported_severity:
        synthetic = {'id': 'SYSTEM-FINDING-SEVERITY', 'code': 'SYSTEM-FINDING-SEVERITY',
                     'title': 'Finding severity is recognized', 'action': 'QUARANTINE',
                     'mandatory': True, 'nonWaivable': True,
                     'remediation': 'Normalize the finding severity before release evaluation.'}
        append_result(synthetic, 'UNKNOWN', 'One or more scanner findings have an unknown severity.')
        unknown_signals.append('findingSeverity')

    if expected_hash and observed_hash:
        if not hmac.compare_digest(str(expected_hash).lower(), str(observed_hash).lower()):
            synthetic = {'id': 'SYSTEM-HASH-INTEGRITY', 'code': 'SYSTEM-HASH-INTEGRITY',
                         'title': 'Uploaded bytes match intake digest', 'action': 'BLOCK',
                         'mandatory': True, 'nonWaivable': True, 'remediation': 'Reject the changed artifact and investigate storage integrity.'}
            append_result(synthetic, 'FAIL', 'Observed scan digest differs from the server-recorded intake digest.')
    else:
        synthetic = {'id': 'SYSTEM-HASH-AVAILABLE', 'code': 'SYSTEM-HASH-AVAILABLE',
                     'title': 'Integrity digest available', 'action': 'QUARANTINE',
                     'mandatory': True, 'nonWaivable': True, 'remediation': 'Recalculate and verify the artifact digest.'}
        append_result(synthetic, 'UNKNOWN', 'Expected or observed SHA-256 digest is unavailable.')
        unknown_signals.append('integrityHash')

    target_formats = policy.get('target_formats', policy.get('targetFormats', []))
    if target_formats and format_name not in {str(value).upper() for value in target_formats}:
        synthetic = {'id': 'SYSTEM-FORMAT-ALLOWED', 'code': 'SYSTEM-FORMAT-ALLOWED',
                     'title': 'Artifact format permitted by policy', 'action': 'BLOCK',
                     'mandatory': True, 'nonWaivable': True, 'remediation': 'Use a format allowed by this policy.'}
        append_result(synthetic, 'FAIL', f'Format {format_name or "UNKNOWN"} is not allowed by this policy.')

    def matching_findings(trigger: str) -> list[Mapping]:
        if trigger == 'ANY_FINDING':
            return [finding for finding in findings if isinstance(finding, Mapping)]
        if trigger in SEVERITIES:
            return [finding for finding in findings if isinstance(finding, Mapping) and str(finding.get('severity', '')).upper() == trigger]
        if trigger == 'CONFIRMED_MALICIOUS':
            return [finding for finding in findings if isinstance(finding, Mapping) and finding.get('confirmedMalicious') is True]
        return []

    for rule in rules:
        if not rule.get('enabled', True):
            results.append({'ruleId': rule.get('id', rule['code']), 'ruleCode': rule['code'],
                            'ruleTitle': rule.get('title', rule['code']), 'passed': False,
                            'result': 'SKIPPED', 'action': rule['action'], 'reason': 'Rule is disabled.',
                            'mandatory': rule['mandatory'], 'nonWaivable': rule['nonWaivable'],
                            'evidenceRefs': [], 'remediation': rule.get('remediation', rule.get('description', ''))})
            continue
        trigger = rule['trigger']
        matched: list[Mapping] = []
        unknown = False
        reason = 'No matching policy violation was found.'
        if trigger in (*SEVERITIES, 'ANY_FINDING', 'CONFIRMED_MALICIOUS'):
            matched = matching_findings(trigger)
            if matched:
                reason = f'{len(matched)} finding(s) matched the {trigger} rule.'
        elif trigger == 'HASH_MISMATCH':
            unknown = not expected_hash or not observed_hash
            matched = [rule] if not unknown and not hmac.compare_digest(str(expected_hash).lower(), str(observed_hash).lower()) else []
            reason = 'Observed digest differs from the expected digest.' if matched else 'Hash comparison is unavailable.' if unknown else reason
        elif trigger == 'UNVERIFIED_PROVENANCE':
            matched = [rule] if context.get('provenanceStatus') != 'VERIFIED' else []
            reason = f"Provenance state is {context.get('provenanceStatus', 'UNKNOWN')}." if matched else reason
        elif trigger == 'UNVERIFIED_SIGNATURE':
            signature_status = str(signature_status).upper()
            unknown = signature_status in {'UNKNOWN', 'UNAVAILABLE'}
            matched = [rule] if signature_status in {'MISSING', 'UNVERIFIED'} else []
            reason = f'Signature state is {signature_status}.' if unknown or matched else reason
        elif trigger == 'INVALID_SIGNATURE':
            signature_status = str(signature_status).upper()
            unknown = signature_status in {'UNKNOWN', 'UNAVAILABLE'}
            matched = [rule] if signature_status == 'INVALID' else []
            reason = f'Signature state is {signature_status}.' if unknown or matched else reason
        elif trigger == 'SCAN_FAILED':
            unknown = scan_status == 'FAILED'
            reason = f'Scan state is {scan_status}.' if unknown else reason
        elif trigger == 'SCAN_INCOMPLETE':
            unknown = scan_status in {'NOT_SCANNED', 'QUEUED', 'RUNNING', 'FAILED'}
            reason = f'Scan state is {scan_status}.' if unknown or matched else reason
        elif trigger == 'UNSUPPORTED_FORMAT':
            matched = [rule] if target_formats and format_name not in {str(value).upper() for value in target_formats} else []

        refs = [str(ref) for finding in matched if isinstance(finding, Mapping)
                for ref in (finding.get('evidenceIds') or [])]
        if unknown:
            append_result(rule, 'UNKNOWN', reason, refs)
            unknown_signals.append(trigger)
        elif matched:
            append_result(rule, 'FAIL', reason, refs)
        else:
            append_result(rule, 'PASS', reason)

    # Unresolved high/critical findings require isolation unless an explicit
    # BLOCK rule already made a stronger, confirmed determination.
    severity_rules = {rule['trigger'] for rule in rules if rule.get('enabled', True)}
    for severity in ('CRITICAL', 'HIGH'):
        unresolved = [finding for finding in findings if isinstance(finding, Mapping)
                      and str(finding.get('severity', '')).upper() == severity]
        if unresolved and severity not in severity_rules:
            synthetic = {'id': f'SYSTEM-{severity}-REVIEW', 'code': f'SYSTEM-{severity}-REVIEW',
                         'title': f'{severity} findings reviewed', 'action': 'QUARANTINE',
                         'mandatory': True, 'nonWaivable': False,
                         'remediation': 'Investigate the finding and attach review evidence.'}
            refs = [str(ref) for finding in unresolved for ref in (finding.get('evidenceIds') or [])]
            append_result(synthetic, 'FAIL', f'{len(unresolved)} unresolved {severity} finding(s) require investigation.', refs)

    outcome = max(decisions, key=lambda status: PRECEDENCE[status]) if decisions else 'APPROVED'
    if scan_status != 'COMPLETED' and outcome == 'APPROVED':
        outcome = 'QUARANTINED'
    return {
        'artifactId': artifact_id, 'decision': outcome, 'overallOutcome': outcome,
        'policyId': policy['id'], 'policyCode': policy['code'], 'policyName': policy.get('name', policy['code']),
        'policyVersion': str(policy['version']), 'ruleEvaluations': results,
        'unknownSignals': sorted(set(unknown_signals)),
        'requiresHumanReview': outcome in {'CONDITIONAL', 'QUARANTINED'},
        'evaluatedAt': context.get('evaluatedAt'),
        'artifactHash': expected_hash,
    }
