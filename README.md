# ModelShield

ModelShield provides an end-to-end evidence-based security release governance platform for ML model artifacts. It connects Member 1 (artifact intake & fingerprinting), Member 2 (security scanning & evidence graph), and Member 3 (release policies, review queue, decision engine, model security passport, and tamper-evident audit trail).

## Run locally

Use Python 3.10+ and Node 20+ (Node 22.13 recommended). From the repository root:

```powershell
python -m pip install -r backend/requirements.txt
python -m venv backend/.venv-scanner
backend/.venv-scanner/Scripts/python.exe -m pip install -r backend/requirements-scanner.txt
python -m backend.create_user
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

The account creation command prompts for an email, display name and password. No default account is included. On macOS/Linux, use `backend/.venv-scanner/bin/python` for the scanner install. A custom scanner executable can be set through `MODELSHIELD_MODELAUDIT_BIN`. In another terminal:

```powershell
Copy-Item frontend/.env.example frontend/.env.local
# Set VITE_USE_MOCK_DATA=false in frontend/.env.local
cd frontend
npm ci
npm run dev
```

Vite listens on 127.0.0.1 and proxies /api to the backend on 127.0.0.1:8000. Set VITE_USE_MOCK_DATA=true for the fully interactive standalone client-side demo mode. Set MODELSHIELD_DATA_DIR to move the ignored backend/data directory.

## What works

- **Member 1 (Intake & Registry)**: Session login/logout, registry statistics, artifact search/filter/pagination, validated upload, SHA-256 fingerprinting, artifact detail, and scan control.
- **Member 2 (Security & Evidence)**: Static and ModelAudit 0.2.52 scanner findings, evidence timeline, provenance claims, and risk summary.
- **Member 3 (Governance & Decisions)**:
  - **Review Queue**: Triage workstation for quarantined and conditional models with filters and quick actions.
  - **Release Policies**: Active policy catalog (e.g. `PROD-SEC-004`, `DEV-SANDBOX-001`, `FIN-COMPLY-009`) with automated rule evaluation against scanner findings and cryptographic hash integrity.
  - **Decision Engine**: Reviewer sign-off dialog to record decisions (`APPROVED`, `CONDITIONAL`, `QUARANTINED`, `BLOCKED`) with required rationale, operational conditions, and CSRF protection.
  - **Model Security Passport**: Official verifiable attestation certificate with JSON export and print views.
  - **Audit Trail**: Immutable chronological activity stream tracking logins, uploads, scans, policy checks, decisions, and passport generation.
  - **Evidence Graph**: Linked Policy and Decision nodes connecting directly to the artifact and scanner evidence graph.

## Integrated Pipeline Flow

$$\text{Upload (M1)} \to \text{Artifact (M1)} \to \text{Scan (M1)} \to \text{Findings (M2)} \to \text{Evidence (M2)} \to \mathbf{\text{Policy (M3)}} \to \mathbf{\text{Decision (M3)}} \to \mathbf{\text{Passport (M3)}} \to \mathbf{\text{Audit (M3)}}$$

1. Upload supported ML model (.onnx, .pkl, .pt, .safetensors, .h5). Automatically quarantined and hashed (SHA-256).
2. Choose **Start scan** to generate structural checks and ModelAudit findings.
3. Review Findings, Evidence, and Evidence Graph.
4. Triage models in the **Review Queue** or on the **Artifact Page**.
5. Evaluate compliance against **Release Policies**.
6. Commit a signed **Governance Decision** (`APPROVED` / `CONDITIONAL` / `BLOCKED`).
7. Generate and export the verifiable **Model Security Passport**.
8. Inspect all operations in the **Audit Trail**.

Frontend modules live under `frontend/src/pages/auth`, `dashboard`, `artifacts`, `security`, and `governance`. Shared UI and layout live under `frontend/src/components/common` and `frontend/src/routes`. Backend endpoints and storage are implemented in `backend/main.py`, `backend/store.py`, and `backend/scanner.py`.

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
