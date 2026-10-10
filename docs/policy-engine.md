# ModelShield policy engine

The backend evaluates policies through `backend/policy_engine.py`. Rules use
allowlisted triggers and actions; arbitrary expressions are not executed.
Each persisted evaluation stores the exact policy snapshot and version, the
artifact's intake SHA-256, normalized rule results, evidence references, unknown
signals, timestamp, and proposed governance decision in `policy_evaluations`.

## Default decision precedence

The engine uses this fixed order: `APPROVED < CONDITIONAL < QUARANTINED <
BLOCKED`. A stronger result from any applicable rule wins; a reviewer may
record the evaluated outcome or a more restrictive outcome. They cannot
override a mandatory block, or release an artifact whose policy result is
conditional or quarantined.

- **BLOCKED**: a configured blocking rule failed on available evidence, such
  as a configured critical finding or an intake/scan digest mismatch.
- **QUARANTINED**: a required scan or digest is missing, a scan is not
  complete, a required signal is unknown, or an unresolved high/critical
  finding has no explicit policy rule.
- **CONDITIONAL**: a configured warning rule failed and does not coincide with
  a block or quarantine result. Conditions must be recorded for reviewer
  decisions.
- **APPROVED**: all available mandatory checks passed and no unresolved
  higher-precedence outcome exists.

The seeded policies are demonstration defaults and require security review
before production use. In the default production policy, critical findings and
digest mismatch block, high findings and uploader-claimed provenance require
conditional review, and incomplete scanning quarantines. Unknown signatures are
reported as unknown; they are not treated as invalid or valid.

## Evidence and enforcement limits

The scanner's structural findings and ModelAudit output are the
available scan signals. The observed file hash is compared with the hash saved
at intake; this checks storage/intake consistency and is not an independent
trusted publisher digest. Signature verification is not implemented, and
provenance fields are uploader claims rather than verified attestations.
Therefore the engine reports signature status as `UNKNOWN` and provenance as
`MISSING` or `UNVERIFIED`.

If ModelAudit cannot return a valid bounded report, the backend preserves any
structural findings, records the ModelAudit error separately, and completes
the scan with limited coverage. The policy engine quarantines that artifact
until a successful ModelAudit scan provides complete coverage. A structural
scanner failure still marks the whole scan failed.

Quarantine is a governance state in the database. This implementation does not
move bytes into a separate storage boundary or enforce downstream deployment
access controls. Conditional requirements are recorded as administrative
conditions; technical enforcement and expiry are not currently implemented.
Approval means only that the artifact passed the configured available checks.

## Integrated endpoints

- `GET /policies` and `GET /policies/{id}` expose the configured policy catalog.
- `POST /artifacts/{id}/evaluate` evaluates trusted server-side artifact,
  completed-scan, finding, provenance, and digest records and persists the
  result.
- `POST /artifacts/{id}/scan` invokes evaluation after scanning and records the
  resulting automatic decision, including conditional requirements or
  quarantine remediation.
- `POST /artifacts/{id}/decision` checks the authenticated reviewer role,
  recomputes the policy result, enforces precedence, and binds the decision to
  its evaluation ID, policy version, and artifact hash.
- `POST /artifacts/{id}/replay`, `GET /artifacts/{id}/passport`,
  `GET /artifacts/{id}/graph`, and `GET /audit` expose replay, governance,
  evidence, and decision history through existing routes.

Evaluation response example (abbreviated):

```json
{
  "evaluationId": "EVAL-...",
  "artifactId": "...",
  "decision": "QUARANTINED",
  "overallOutcome": "QUARANTINED",
  "policyCode": "PROD-SEC-004",
  "policyVersion": "2.0",
  "ruleEvaluations": [],
  "unknownSignals": ["signatureStatus"],
  "requiresHumanReview": true,
  "artifactHash": "<intake sha256>"
}
```

To demonstrate outcomes, use a fully scanned clean artifact with matching
digest and no configured warnings for `APPROVED`; include uploader-claimed
provenance under the production policy for `CONDITIONAL`; evaluate before
scanning for `QUARANTINED`; and use a synthetic test finding matching an
enabled blocking rule or a digest mismatch for `BLOCKED`. Tests use synthetic
signals and do not execute malicious files.
