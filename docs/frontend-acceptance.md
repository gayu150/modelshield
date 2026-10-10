# ModelShield Workflow Acceptance

Scope: End-to-end pipeline covering authentication, artifact intake, security analysis and evidence, policy evaluation, conditional human review, final decisions, Model Security Passport, and Audit Trail.

## Completed automated checks

- **Frontend unit tests (21 tests pass)**: cover request handling, response validation, encoded routes, file/hash rules, demo fixtures consistency, governance policy contracts, decision records, passport verification, and audit trail events.
- **Component render checks (4 tests pass)**: cover escaping of hostile strings (in findings, graph labels, model names, and decision justifications), empty reports, pagination, and visual Model Security Passport rendering.
- **Frontend build**: `tsc -b && vite build` builds with 0 errors and produces optimized bundles with TypeScript type-safety.
- **Backend HTTP integration checks (11 tests pass)**: cover credential login, CSRF rejection, file upload, scan completion, ModelAudit normalization, cross-user isolation, policies catalog, policy evaluation against findings, decision recording with CSRF, decision history, passport generation, audit log persistence, evidence graph policy/decision nodes, and logout.
- **Static & isolated scanner checks**: prove that pickle content is not executed, archive traversal is reported without extraction, and structural headers are inspected.

### Run automated verification
```powershell
python -m unittest discover -s backend/tests -v
cd frontend
npm test
npm run build
npx --yes tsx@4.20.6 --test tests/render.test.tsx
```

## End-to-End Pipeline
$$\text{Upload} \to \text{Quarantine} \to \text{Scan} \to \text{Findings + Evidence} \to \text{Policy Evaluation} \to \text{Human Review if Needed} \to \text{Final Decision} \to \text{Passport} \to \text{Audit}$$

1. Upload a supported model file. The application quarantines it and records a SHA-256 fingerprint.
2. Opening an unscanned artifact starts the security scan automatically. Structural and ModelAudit checks generate findings and evidence.
3. The active policy records rule-level results and a proposed outcome. A passing outcome may approve automatically; an outcome requiring judgment leaves the artifact quarantined.
4. The **Review Queue** distinguishes artifacts awaiting a scan from artifacts requiring review. Reviewers inspect the record and enter a rationale before recording the final disposition.
5. The **Model Security Passport** summarizes recorded evidence and the final decision. The **Audit Trail** records policy evaluations and decisions.
6. Demo mode uses illustrative fixtures and does not scan uploaded model bytes.
