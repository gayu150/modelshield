# ModelShield

ModelShield provides evidence-based security release governance for ML model artifacts, connecting artifact intake, security scanning, findings, evidence, policy evaluation, human review, security passports, and an auditable decision history.

## Run locally

Use Python 3.10+ and Node 20+ (Node 22.13 recommended). From the repository root:

```powershell
python -m pip install -r backend/requirements.txt
python -m venv backend/.venv-scanner
backend/.venv-scanner/Scripts/python.exe -m pip install -r backend/requirements-scanner.txt
python -m backend.create_user
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

The account creation command prompts for an email, display name, role, and password. Create a **security reviewer** or **admin** account to record review decisions; public sign-ups receive the analyst role. No default account is included. On macOS/Linux, use `backend/.venv-scanner/bin/python` for the scanner install. A custom scanner executable can be set through `MODELSHIELD_MODELAUDIT_BIN`. In another terminal:

```powershell
Copy-Item frontend/.env.example frontend/.env.local
# Set VITE_USE_MOCK_DATA=false in frontend/.env.local
cd frontend
npm ci
npm run dev
```

Vite listens on 127.0.0.1 and proxies /api to the backend on 127.0.0.1:8000. Set VITE_USE_MOCK_DATA=true for the fully interactive standalone client-side demo mode. Set MODELSHIELD_DATA_DIR to move the ignored backend/data directory.

## What works

- **Artifact intake**: Session login/logout, registry search/filter/pagination, validated uploads, and SHA-256 fingerprints.
- **Security analysis**: Static and ModelAudit 0.2.52 findings, evidence timeline, provenance claims, and risk summary.
- **Policy and release governance**:
  - Opening an unscanned artifact starts its security scan automatically.
  - The centralized backend policy evaluator automatically records explainable, versioned `APPROVED`, `CONDITIONAL`, `QUARANTINED`, or `BLOCKED` decisions after a scan. Conditions and evidence are stored with the decision; mandatory blocking rules cannot be overridden.
  - The Review Queue shows each artifact's automatic policy decision and supports authorized review when additional governance action is needed.
  - The policy catalog, Model Security Passport, audit trail, and evidence graph expose the rules and evidence behind each result.

## Integrated Pipeline Flow

$$\text{Upload} \to \text{Quarantine} \to \text{Scan} \to \text{Findings + Evidence} \to \text{Policy Evaluation} \to \text{Human Review if Needed} \to \text{Final Decision} \to \text{Passport + Audit}$$

1. Upload a supported model file (`.onnx`, `.pkl`, `.pt`, `.safetensors`, `.h5`). ModelShield quarantines and fingerprints it.
2. Opening its details starts the scan automatically. Demo mode uses sample records and does not scan uploaded bytes.
3. When scanning completes, the active policy evaluates the scan and automatically applies its decision. The Review Queue shows the outcome, rationale, and recorded conditions.
4. Review flagged artifacts in **Review Queue**, inspect the evidence, and record an outcome with a required rationale.
5. View the final decision in the **Model Security Passport** and its history in the **Audit Trail**.

Frontend modules live under `frontend/src/pages/auth`, `dashboard`, `artifacts`, `security`, and `governance`. Shared UI and layout live under `frontend/src/components/common` and `frontend/src/routes`. Backend endpoints and storage are implemented in `backend/main.py`, `backend/store.py`, and `backend/scanner.py`.

See [the policy engine guide](docs/policy-engine.md) for decision precedence, integrated endpoints, demonstration defaults, and current security-signal limitations.

## Validate

```powershell
python -m unittest discover -s backend/tests -v
cd frontend
npm test
npm run build
npx --yes tsx@4.20.6 --test tests/render.test.tsx
```

The backend tests use a disposable local HTTP server and database to check login, CSRF, upload, scans, ownership, evidence, logout and API compatibility with the frontend parsers. They also verify that static scans never execute pickle content.

## Remaining limits

This is a single process prototype. In process scan jobs fail on server restart; use a durable worker before depending on large or concurrent scans. The ModelAudit subprocess has a timeout and temporary workspace but does not have OS-level network, CPU or memory isolation; deploy a restricted scanner worker before scanning untrusted files in a shared environment. SQLite and the unpaginated registry suit small installations. Scanner findings are not a release decision. A headless render checked the login page; the authenticated browser journey and keyboard checks remain pending. Production TLS, backups, encryption at rest, monitoring and load behavior have not been verified. See docs/frontend-acceptance.md.
