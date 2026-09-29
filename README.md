# ModelShield

Member 1 frontend starter for the ModelShield honor project: login UI, dashboard, and artifact management.

## Run the frontend

```powershell
cd frontend
npm install
npm run dev
```

The current dashboard uses sample artifacts so the first member can build and integrate the module before the API is ready. Selecting files adds them to the local quarantine view for this browser session; it does not upload model bytes or scan them yet. The generic API client is in `frontend/src/services/api/client.ts` and reads `VITE_API_BASE_URL` (defaults to `/api`).

Copy `frontend/.env.example` to `frontend/.env.local` when you are ready to configure the API. Vite forwards `/api/*` requests to the FastAPI target at `http://127.0.0.1:8000` by default. Set `VITE_USE_MOCK_DATA=false` to load the dashboard list and upload through the API. Artifact endpoint helpers are in `frontend/src/services/api/artifacts.ts`; align their response schema with the backend before integration.

## Member 1 ownership

- Login/authentication UI shell
- Dashboard and artifact statistics
- Artifact table, search, and decision filter
- Upload interaction and quarantine-state presentation
- Shared page shell, navigation, and visual tokens

The artifact, finding, decision, and provenance data contracts still need to be aligned with the backend team before connecting `POST /auth/login`, `GET /auth/me`, `POST /artifacts`, `GET /artifacts`, `GET /artifacts/{id}`, `POST /artifacts/{id}/scan`, and `GET /scans/{id}`.
