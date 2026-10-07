# Member 1 and Member 2 acceptance

Scope: authentication, artifact intake, scanning and security evidence. Member 3 governance is excluded.

## Completed automated checks

- Frontend unit tests cover request handling, response validation, encoded routes, file/hash rules, demo consistency and session failure states.
- Component render checks cover escaping of hostile strings, empty reports and pagination.
- Backend HTTP integration checks cover credential login, CSRF rejection, upload, scan completion, findings/evidence/graph, cross-user denial and logout.
- Live backend responses are passed through the frontend contract parsers.
- Static scanner checks prove that pickle content is not executed and archive traversal is reported without extraction.
- Scanner, session expiry, login throttling and malformed request cases are exercised with a disposable local database.

Run python -m unittest discover -s backend/tests -v from the repository root. Run npm test, npm run build and npx --yes tsx@4.20.6 --test tests/render.test.tsx from frontend.

## Browser checks pending

The UI automation surface has no connected browser. These checks need a browser session:

1. In demo mode, verify the banner, dashboard counts, search, filters, pagination and temporary upload behavior.
2. In live mode, sign in with an account created by python -m backend.create_user. Upload a small supported artifact and confirm its quarantine status and SHA-256.
3. Start a scan; confirm queued/running/completed display and automatic evidence refresh.
4. Open findings, scanner details, evidence, graph and provenance. Check navigation, keyboard focus, Escape behavior, zoom and direct URLs.
5. Try malformed and oversized files, duplicate submission, missing evidence, scanner failure and an expired session.
6. Inspect desktop and mobile layouts, print view and copy hash feedback.

## Before wider deployment

- Put the API behind HTTPS, configure secure cookies and allowed hosts, and enforce request body limits at the proxy.
- Replace in process scan jobs with a durable queue and isolated workers; define explicit format coverage and resource limits.
- Run ModelAudit in a restricted worker with CPU, memory, filesystem and network limits; add publisher signature verification before making release decisions.
- Validate backups, storage encryption, monitoring, schema migrations, load behavior and realistic large reports.
- Keep policy, approval, passport and audit implementation assigned to Member 3.
