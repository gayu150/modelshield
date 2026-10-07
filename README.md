# ModelShield

ModelShield includes the Member 1 artifact workflow and Member 2 security analysis. The React frontend connects to a FastAPI backend with SQLite records and local upload storage. Member 3 governance work is outside this implementation.

## Run locally

Use Python 3.13 and Node 22.13 or newer. From the repository root:

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

Vite listens on 127.0.0.1 and proxies /api to the backend on 127.0.0.1:8000. Set VITE_USE_MOCK_DATA=true only for the clearly labeled interface demo; demo uploads never transmit file bytes or run scans. Set MODELSHIELD_DATA_DIR to move the ignored backend/data directory. Production deployment needs an HTTPS reverse proxy, MODELSHIELD_SECURE_COOKIE=true and MODELSHIELD_ALLOWED_HOSTS for its actual host.

If port 8000 is occupied, start Uvicorn on another port (for example 8010) and set `VITE_DEV_API_TARGET=http://127.0.0.1:8010` in `frontend/.env.local` before starting Vite.

## What works

Member 1: cookie session login and logout, registry statistics, artifact search/filter/pagination, validated upload, SHA-256 fingerprint, artifact detail and scan polling. Member 2: scanner findings, evidence timeline, graph, provenance and risk summary. The backend scopes artifacts and every related report to the uploading user. Authenticated mutations require the CSRF token from GET /auth/me. The frontend validates API payloads before rendering them.

Uploads remain QUARANTINED. The built-in structural scanner reads bytes without loading a model. ModelAudit 0.2.52 runs as a separate local process on a read-only copy and its JSON issues are normalized into findings and evidence. Missing scanner, timeout, malformed report or scanner error marks the scan FAILED. Neither scanner approves models or verifies publisher signatures. Other decision statuses remain frontend data contract values for the future governance module.

## Upload and scan flow

1. Upload a supported ML model file. The backend validates it, saves it under its local upload directory, records its SHA-256, and sets status to QUARANTINED automatically.
2. On the artifact page, choose Start scan. This is a separate action; there is no manual quarantine button.
3. When the scan completes, review Findings, Evidence, Evidence graph, and Provenance. Scanning does not change the QUARANTINED status.

The current quarantine is a database status and a local storage convention, not a separate hardened quarantine service. APK is an Android application package and is not a supported model upload format.

The provenance form records uploader claims for source, publisher, repository, revision and origin. Those values are marked UNVERIFIED. The risk summary combines hash comparison, scan state and finding severities; it remains INCOMPLETE or INVESTIGATE because publisher signatures and full scanner coverage are unavailable. The graph links artifacts, hashes, provenance, scanners, findings and evidence. It does not contain policy or decision nodes, which belong to Member 3.

Frontend modules are under frontend/src/pages/auth, dashboard, artifacts and security. Their shared UI and routing live under frontend/src/components/common and frontend/src/routes. Backend endpoints and storage are implemented in backend/main.py, backend/store.py and backend/scanner.py.

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
