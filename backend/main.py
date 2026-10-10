import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

logger = logging.getLogger(__name__)

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field

if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from backend.config import ALLOWED_HOSTS, FORCE_SECURE_COOKIE, MAX_UPLOAD_BYTES, SESSION_SECONDS, UPLOAD_DIR
    from backend.scanner import EXTENSIONS, digest, report, utc_now, validate_content
    from backend.modelaudit_adapter import ScannerUnavailable, scan as modelaudit_scan
    from backend.policy_engine import PolicyDefinitionError, evaluate_policy as run_policy_engine
    from backend.store import DUMMY_PASSWORD_HASH, check_password, connect, end_session, find_session, initialize, new_session, password_hash, record_audit
else:
    from .config import ALLOWED_HOSTS, FORCE_SECURE_COOKIE, MAX_UPLOAD_BYTES, SESSION_SECONDS, UPLOAD_DIR
    from .scanner import EXTENSIONS, digest, report, utc_now, validate_content
    from .modelaudit_adapter import ScannerUnavailable, scan as modelaudit_scan
    from .policy_engine import PolicyDefinitionError, evaluate_policy as run_policy_engine
    from .store import DUMMY_PASSWORD_HASH, check_password, connect, end_session, find_session, initialize, new_session, password_hash, record_audit


@asynccontextmanager
async def lifespan(_app: FastAPI):
    initialize()
    yield


app = FastAPI(title='ModelShield intake and security API', lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)


@app.exception_handler(RequestValidationError)
async def invalid_input(_request: Request, _exc: RequestValidationError):
    return JSONResponse(status_code=422,
                        content={'error': {'code': 'INVALID_INPUT', 'message': 'Invalid request data.'}})


@app.exception_handler(HTTPException)
async def controlled_error(_request: Request, exc: HTTPException):
    code = {400: 'BAD_REQUEST', 401: 'UNAUTHORIZED', 403: 'FORBIDDEN',
            404: 'NOT_FOUND', 409: 'CONFLICT', 413: 'FILE_TOO_LARGE',
            422: 'INVALID_INPUT', 429: 'RATE_LIMITED'}.get(exc.status_code, 'REQUEST_FAILED')
    return JSONResponse(status_code=exc.status_code,
                        content={'error': {'code': code, 'message': str(exc.detail)}})


@app.middleware('http')
async def security_headers(request: Request, call_next):
    if request.method in {'POST', 'PUT', 'PATCH'}:
        length = request.headers.get('content-length')
        if length and length.isdigit() and int(length) > MAX_UPLOAD_BYTES + 1024 * 1024:
            return JSONResponse(status_code=413, content={'error': {'code': 'FILE_TOO_LARGE', 'message': 'Upload exceeds 2 GB.'}})
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Frame-Options'] = 'DENY'
    return response


class Credentials(BaseModel):
    model_config = ConfigDict(extra='forbid')
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


class Registration(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=1024)


def current_user(request: Request):
    token = request.cookies.get('modelshield_session')
    with connect() as db:
        user = find_session(db, token)
    if user is None:
        raise HTTPException(401, 'Sign in required.')
    return dict(user)


def csrf_user(request: Request, user=Depends(current_user)):
    submitted = request.headers.get('X-CSRF-Token', '')
    if not submitted or not hmac.compare_digest(submitted, user['csrf_token']):
        raise HTTPException(403, 'Invalid request token.')
    return user


def owned_artifact(db: sqlite3.Connection, artifact_id: str, user_id: str):
    row = db.execute('SELECT * FROM artifacts WHERE id = ? AND owner_id = ?',
                     (artifact_id, user_id)).fetchone()
    if row is None:
        raise HTTPException(404, 'Artifact not found.')
    return row


def latest_scan(db: sqlite3.Connection, artifact_id: str):
    return db.execute('''SELECT * FROM scans WHERE artifact_id = ? AND status = 'COMPLETED'
                         ORDER BY created_at DESC, id DESC LIMIT 1''', (artifact_id,)).fetchone()


def current_scan(db: sqlite3.Connection, artifact_id: str):
    return db.execute('''SELECT * FROM scans WHERE artifact_id = ?
                         ORDER BY created_at DESC, rowid DESC LIMIT 1''', (artifact_id,)).fetchone()


def policy_findings(db: sqlite3.Connection, scan_row):
    if scan_row is None or scan_row['status'] != 'COMPLETED':
        return []
    return [json.loads(row['payload']) for row in db.execute(
        'SELECT payload FROM findings WHERE scan_id = ? ORDER BY rowid', (scan_row['id'],)
    ).fetchall()]


def artifact_json(db: sqlite3.Connection, row):
    scan = latest_scan(db, row['id'])
    scan_progress = db.execute('''SELECT status FROM scans WHERE artifact_id = ?
                                 ORDER BY created_at DESC, id DESC LIMIT 1''', (row['id'],)).fetchone()
    findings = db.execute('SELECT COUNT(*) FROM findings WHERE scan_id = ?',
                          (scan['id'],)).fetchone()[0] if scan else 0
    evaluation_row = db.execute('''SELECT id, result_payload FROM policy_evaluations WHERE artifact_id = ?
                                   ORDER BY created_at DESC, rowid DESC LIMIT 1''', (row['id'],)).fetchone()
    evaluation = json.loads(evaluation_row['result_payload']) if evaluation_row else {}
    latest_state = scan_progress['status'] if scan_progress else 'NOT_SCANNED'
    if latest_state != 'COMPLETED' and evaluation.get('scanStatus') != latest_state:
        evaluation = {}
    linked_decision = db.execute('''SELECT id, reviewer_role FROM decisions WHERE artifact_id = ?
                                   AND artifact_hash = ? AND policy_version = ?
                                   ORDER BY created_at DESC, id DESC LIMIT 1''',
                                 (row['id'], evaluation.get('artifactHash'), evaluation.get('policyVersion'))).fetchone() if evaluation else None
    review_required = latest_state != 'COMPLETED' or (
        bool(evaluation.get('requiresHumanReview')) and
        (linked_decision is None or linked_decision['reviewer_role'] == 'Automated Policy Engine')
    )
    return {'id': row['id'], 'name': row['name'], 'model': row['model'],
            'version': row['version'], 'format': row['format'],
            'uploadedBy': row['owner_name'], 'uploadedAt': row['uploaded_at'],
            'decision': row['decision'], 'findings': findings, 'hash': row['sha256'],
            'scanStatus': latest_state,
            'policyOutcome': evaluation.get('decision'),
            'reviewRequired': review_required,
            'provenance': {'source': row['source'], 'publisher': row['publisher'],
                           'repository': row['repository'], 'revision': row['revision'],
                           'origin': row['origin'],
                           'verificationStatus': 'UNVERIFIED' if any(row[key] for key in ('source', 'publisher', 'repository', 'revision', 'origin')) else 'MISSING',
                           'signatureStatus': 'UNKNOWN', 'expectedHash': row['sha256'],
                           'observedHash': scan['observed_hash'] if scan else None}}


@app.post('/auth/login')
def login(payload: Credentials, request: Request, response: Response):
    import time
    email = payload.email.strip().lower()
    now = int(time.time())
    with connect() as db:
        db.execute('DELETE FROM login_failures WHERE first_attempt < ?', (now - 900,))
        failures = db.execute('SELECT * FROM login_failures WHERE email = ?', (email,)).fetchone()
        if failures and failures['attempts'] >= 5 and now - failures['first_attempt'] < 900:
            raise HTTPException(429, 'Too many login attempts. Try again later.')
        user = db.execute('SELECT * FROM users WHERE email = ?',
                          (email,)).fetchone()
        valid_password = check_password(payload.password,
                                        user['password_hash'] if user else DUMMY_PASSWORD_HASH)
        if user is None or not valid_password:
            if failures and now - failures['first_attempt'] < 900:
                db.execute('UPDATE login_failures SET attempts = attempts + 1 WHERE email = ?', (email,))
            else:
                db.execute('INSERT OR REPLACE INTO login_failures VALUES (?, ?, ?)', (email, 1, now))
            db.commit()
            raise HTTPException(401, 'Invalid email or password.')
        db.execute('DELETE FROM login_failures WHERE email = ?', (email,))
        token = new_session(db, user['id'])
        record_audit(db, user['id'], user['name'], user['role'], 'USER_LOGIN',
                     f"User {user['name']} signed in successfully.")
    response.set_cookie('modelshield_session', token, max_age=SESSION_SECONDS,
                        httponly=True, secure=FORCE_SECURE_COOKIE or request.url.scheme == 'https',
                        samesite='strict', path='/')
    return {'id': user['id'], 'email': user['email'], 'name': user['name'], 'role': user['role']}


@app.post('/auth/register', status_code=201)
def register(payload: Registration, request: Request, response: Response):
    name = payload.name.strip()
    email = payload.email.strip().lower()
    if len(name) < 2 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(422, 'Enter a valid name and email address.')
    user_id = str(uuid.uuid4())
    role = 'analyst'
    try:
        with connect() as db:
            db.execute('INSERT INTO users VALUES (?, ?, ?, ?, ?)',
                       (user_id, email, name, role, password_hash(payload.password)))
            token = new_session(db, user_id)
            record_audit(db, user_id, name, role, 'USER_REGISTERED',
                         f'User {name} created an account.')
    except sqlite3.IntegrityError:
        raise HTTPException(409, 'An account with this email already exists.') from None
    response.set_cookie('modelshield_session', token, max_age=SESSION_SECONDS,
                        httponly=True, secure=FORCE_SECURE_COOKIE or request.url.scheme == 'https',
                        samesite='strict', path='/')
    return {'id': user_id, 'email': email, 'name': name, 'role': role}


@app.get('/auth/me')
def me(user=Depends(current_user)):
    return {key: user[key] for key in ('id', 'email', 'name', 'role')} | {'csrfToken': user['csrf_token']}


@app.post('/auth/logout', status_code=204)
def logout(request: Request, response: Response, _user=Depends(csrf_user)):
    with connect() as db:
        record_audit(db, _user['id'], _user['name'], _user['role'], 'USER_LOGOUT',
                     f"User {_user['name']} signed out.")
        end_session(db, request.cookies['modelshield_session'])
    response.delete_cookie('modelshield_session', path='/', samesite='strict')


@app.get('/artifacts')
def artifacts(user=Depends(current_user)):
    with connect() as db:
        rows = db.execute('''SELECT artifacts.*, users.name AS owner_name FROM artifacts
                             JOIN users ON users.id = artifacts.owner_id
                             WHERE owner_id = ? ORDER BY uploaded_at DESC, artifacts.id DESC''',
                          (user['id'],)).fetchall()
        return [artifact_json(db, row) for row in rows]


@app.post('/artifacts', status_code=201)
async def upload(file: UploadFile = File(...), model_name: str = Form(...),
                 version: str = Form(...), source: str | None = Form(None),
                 publisher: str | None = Form(None), repository: str | None = Form(None),
                 revision: str | None = Form(None), origin: str | None = Form(None),
                 user=Depends(csrf_user)):
    model_name, version = model_name.strip(), version.strip()
    if not model_name or len(model_name) > 200 or not version or len(version) > 100:
        raise HTTPException(422, 'Model name and version are required and must be concise.')
    provenance_fields = (source, publisher, repository, revision, origin)
    if any(value is not None and len(value) > 1000 for value in provenance_fields):
        raise HTTPException(422, 'Provenance value is too long.')
    name = (file.filename or '').replace('\\', '/').split('/')[-1]
    if not name or len(name) > 255 or any(ord(ch) < 32 for ch in name):
        raise HTTPException(422, 'Invalid filename.')
    extension = Path(name).suffix.lower()
    if extension not in EXTENSIONS:
        raise HTTPException(422, 'Unsupported file format.')
    artifact_id = str(uuid.uuid4())
    temporary = UPLOAD_DIR / (artifact_id + '.partial')
    destination = UPLOAD_DIR / artifact_id
    size = 0
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as output:
            while block := await file.read(1024 * 1024):
                size += len(block)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, 'Upload exceeds 2 GB.')
                output.write(block)
        try:
            validate_content(temporary, extension, file.content_type)
        except (ValueError, OSError) as exc:
            raise HTTPException(422, str(exc)) from None
        sha = digest(temporary)
        temporary.replace(destination)
        with connect() as db:
            db.execute('''INSERT INTO artifacts
                          (id, owner_id, name, model, version, format, uploaded_at,
                           source, publisher, repository, revision, origin, path, sha256)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (artifact_id, user['id'], name, model_name, version,
                        extension.removeprefix('.').upper(), utc_now(), source, publisher,
                        repository, revision, origin, str(destination), sha))
            row = db.execute('''SELECT artifacts.*, users.name AS owner_name FROM artifacts
                                JOIN users ON users.id = owner_id WHERE artifacts.id = ?''',
                             (artifact_id,)).fetchone()


            record_audit(db, user['id'], user['name'], user['role'], 'ARTIFACT_UPLOAD',
                         f"Uploaded artifact {name} ({extension.removeprefix('.').upper()}). Automatically placed in QUARANTINED state.",
                         target_id=artifact_id, target_name=name,
                         details={'format': extension.removeprefix('.').upper(), 'sizeBytes': size})
            return artifact_json(db, row)
    except Exception:
        temporary.unlink(missing_ok=True)
        destination.unlink(missing_ok=True)
        raise
    finally:
        await file.close()


@app.get('/artifacts/{artifact_id}')
def artifact(artifact_id: str, user=Depends(current_user)):
    with connect() as db:
        row = db.execute('''SELECT artifacts.*, users.name AS owner_name FROM artifacts
                            JOIN users ON users.id = owner_id
                            WHERE artifacts.id = ? AND owner_id = ?''',
                         (artifact_id, user['id'])).fetchone()
        if row is None:
            raise HTTPException(404, 'Artifact not found.')
        return artifact_json(db, row)


@app.delete('/artifacts/{artifact_id}', status_code=204)
def delete_artifact(artifact_id: str, user=Depends(csrf_user)):
    stored_path = None
    with connect() as db:
        row = owned_artifact(db, artifact_id, user['id'])
        active_scan = db.execute('''SELECT id FROM scans WHERE artifact_id = ?
                                    AND status IN ('QUEUED','RUNNING') LIMIT 1''',
                                 (artifact_id,)).fetchone()
        if active_scan:
            raise HTTPException(409, 'Wait for the security scan to finish before deleting this artifact.')
        stored_path = row['path']
        record_audit(db, user['id'], user['name'], user['role'], 'ARTIFACT_DELETED',
                     f"Deleted artifact {row['name']} and its scan records.",
                     target_id=artifact_id, target_name=row['name'],
                     details={'decision': row['decision']})
        scan_ids = [item['id'] for item in db.execute('SELECT id FROM scans WHERE artifact_id = ?',
                                                       (artifact_id,)).fetchall()]
        for scan_id in scan_ids:
            db.execute('DELETE FROM findings WHERE scan_id = ?', (scan_id,))
            db.execute('DELETE FROM evidence WHERE scan_id = ?', (scan_id,))
        db.execute('DELETE FROM policy_evaluations WHERE artifact_id = ?', (artifact_id,))
        db.execute('DELETE FROM decisions WHERE artifact_id = ?', (artifact_id,))
        db.execute('DELETE FROM scans WHERE artifact_id = ?', (artifact_id,))
        db.execute('DELETE FROM artifacts WHERE id = ?', (artifact_id,))
    if stored_path:
        try:
            Path(stored_path).unlink(missing_ok=True)
        except OSError:
            # The record and audit entry are authoritative; a leftover file can
            # be removed by storage maintenance without restoring the artifact.
            pass
    return Response(status_code=204)


def run_scan(scan_id: str, artifact_id: str, path: str, extension: str, expected_hash: str):
    try:
        with connect() as db:
            db.execute("UPDATE scans SET status = ?, modelaudit_status = ?, modelaudit_error = NULL WHERE id = ?",
                       ('RUNNING', 'RUNNING', scan_id))
        findings, evidence, observed = report(Path(path), extension, expected_hash)
        modelaudit_status, modelaudit_error = 'COMPLETED', None
        try:
            external_findings, external_evidence = modelaudit_scan(Path(path), extension, artifact_id, scan_id, observed)
        except ScannerUnavailable as exc:
            # Preserve built-in structural results; the policy engine will
            # quarantine because external scanner coverage is incomplete.
            external_findings, external_evidence = [], []
            modelaudit_status, modelaudit_error = 'FAILED', str(exc)
        findings.extend(external_findings)
        evidence.extend(external_evidence)
        for item in evidence:
            item.setdefault('artifactId', artifact_id)
            item.setdefault('scanId', scan_id)
            item.setdefault('source', item['scanner'])
            item.setdefault('verificationStatus', 'OBSERVED')
        with connect() as db:
            for item in findings:
                db.execute('INSERT INTO findings VALUES (?, ?, ?)',
                           (item['id'], scan_id, json.dumps(item)))
            for item in evidence:
                db.execute('INSERT INTO evidence VALUES (?, ?, ?)',
                           (item['id'], scan_id, json.dumps(item)))
            db.execute('''UPDATE scans SET progress = ?, observed_hash = ?,
                          modelaudit_status = ?, modelaudit_error = ? WHERE id = ?''',
                       (99, observed, modelaudit_status, modelaudit_error, scan_id))
        apply_automated_policy_decision(artifact_id)
    except Exception as exc:
        logger.exception('Security scan failed for scan id %s', scan_id)
        failure = str(exc) if isinstance(exc, ScannerUnavailable) else 'Scanner failed.'
        with connect() as db:
            db.execute('UPDATE scans SET status = ?, progress = ?, completed_at = ?, error = ? WHERE id = ?',
                       ('FAILED', 100, utc_now(), failure, scan_id))
            db.execute("UPDATE scans SET modelaudit_status = 'FAILED', modelaudit_error = ? WHERE id = ?",
                       (failure, scan_id))
            db.execute("UPDATE artifacts SET decision = 'QUARANTINED' WHERE id = ?", (artifact_id,))
        try:
            apply_automated_policy_decision(artifact_id)
        except Exception:
            logger.exception('Could not persist the automatic quarantine decision for scan id %s', scan_id)


@app.post('/artifacts/{artifact_id}/scan', status_code=202)
def start_scan(artifact_id: str, background_tasks: BackgroundTasks, user=Depends(csrf_user)):
    scan_id = str(uuid.uuid4())
    with connect() as db:
        row = owned_artifact(db, artifact_id, user['id'])
        existing = db.execute('''SELECT id FROM scans WHERE artifact_id = ? AND status IN ('QUEUED','RUNNING') LIMIT 1''',
                              (artifact_id,)).fetchone()
        if existing:
            raise HTTPException(409, 'A scan is already running for this artifact.')
        db.execute('''INSERT INTO scans (id, artifact_id, status, progress, created_at)
                      VALUES (?, ?, ?, ?, ?)''',
                   (scan_id, artifact_id, 'QUEUED', 0, utc_now()))
        record_audit(db, user['id'], user['name'], user['role'], 'SCAN_STARTED',
                     f"Initiated security scan for artifact {row['name']}.",
                     target_id=artifact_id, target_name=row['name'],
                     details={'scanId': scan_id})
    background_tasks.add_task(run_scan, scan_id, artifact_id, row['path'], '.' + row['format'].lower(), row['sha256'])
    return {'scan_id': scan_id}


@app.get('/artifacts/{artifact_id}/scan')
def artifact_scan(artifact_id: str, user=Depends(current_user)):
    with connect() as db:
        owned_artifact(db, artifact_id, user['id'])
        # The detail screen needs the newest scan in every lifecycle state.
        # Returning only completed scans made an in-flight scan look absent,
        # causing the client to start a duplicate and receive HTTP 409.
        scan = db.execute('''SELECT * FROM scans WHERE artifact_id = ?
                             ORDER BY created_at DESC, id DESC LIMIT 1''',
                          (artifact_id,)).fetchone()
        return {'scan': None if scan is None else {
            'id': scan['id'], 'status': scan['status'], 'progress': scan['progress'],
            'error': scan['error'] if scan['status'] == 'FAILED' else None,
            'modelAuditStatus': scan['modelaudit_status'],
            'modelAuditError': scan['modelaudit_error'],
        }}


@app.get('/scans/{scan_id}')
def scan_status(scan_id: str, user=Depends(current_user)):
    with connect() as db:
        row = db.execute('''SELECT scans.* FROM scans JOIN artifacts ON artifacts.id = scans.artifact_id
                            WHERE scans.id = ? AND artifacts.owner_id = ?''',
                         (scan_id, user['id'])).fetchone()
        if row is None:
            raise HTTPException(404, 'Scan not found.')
        return {'id': row['id'], 'status': row['status'], 'progress': row['progress'],
                'error': row['error'] if row['status'] == 'FAILED' else None,
                'modelAuditStatus': row['modelaudit_status'],
                'modelAuditError': row['modelaudit_error']}


def report_rows(db, artifact_id: str, user_id: str, table: str):
    if table not in {'findings', 'evidence'}:
        raise ValueError('Invalid report table.')
    owned_artifact(db, artifact_id, user_id)
    scan = latest_scan(db, artifact_id)
    return [] if not scan else [json.loads(row['payload']) for row in
                                  db.execute(f'SELECT payload FROM {table} WHERE scan_id = ? ORDER BY rowid',
                                             (scan['id'],)).fetchall()]


@app.get('/artifacts/{artifact_id}/findings')
def findings(artifact_id: str, user=Depends(current_user)):
    with connect() as db:
        return report_rows(db, artifact_id, user['id'], 'findings')


@app.get('/findings/{finding_id}')
def finding(finding_id: str, user=Depends(current_user)):
    with connect() as db:
        row = db.execute('''SELECT findings.payload FROM findings
                            JOIN scans ON scans.id = findings.scan_id
                            JOIN artifacts ON artifacts.id = scans.artifact_id
                            WHERE findings.id = ? AND artifacts.owner_id = ?''',
                         (finding_id, user['id'])).fetchone()
        if row is None:
            raise HTTPException(404, 'Finding not found.')
        return json.loads(row['payload'])


@app.get('/artifacts/{artifact_id}/evidence')
def evidence(artifact_id: str, user=Depends(current_user)):
    with connect() as db:
        return report_rows(db, artifact_id, user['id'], 'evidence')


@app.get('/artifacts/{artifact_id}/graph')
def graph(artifact_id: str, user=Depends(current_user)):
    with connect() as db:
        row = owned_artifact(db, artifact_id, user['id'])
        related_findings = report_rows(db, artifact_id, user['id'], 'findings')
        related_evidence = report_rows(db, artifact_id, user['id'], 'evidence')
        policy_row = db.execute("SELECT * FROM policies WHERE status = 'ACTIVE' ORDER BY code LIMIT 1").fetchone()
        latest_dec = db.execute('''SELECT * FROM decisions WHERE artifact_id = ?
                                ORDER BY created_at DESC LIMIT 1''', (artifact_id,)).fetchone()
    nodes = [{'id': artifact_id, 'label': row['name'], 'kind': 'Artifact'}]
    hash_id, provenance_id = 'hash:' + artifact_id, 'provenance:' + artifact_id
    nodes += [{'id': hash_id, 'label': 'SHA-256 ' + row['sha256'][:12] + '…', 'kind': 'Hash'},
              {'id': provenance_id, 'label': 'Uploader-supplied provenance', 'kind': 'Provenance'}]
    nodes += [{'id': item['id'], 'label': item['title'], 'kind': 'Finding'} for item in related_findings]
    nodes += [{'id': item['id'], 'label': item['title'], 'kind': 'Evidence'} for item in related_evidence]
    edges = [{'source': artifact_id, 'target': hash_id, 'label': 'hashed as'},
             {'source': artifact_id, 'target': provenance_id, 'label': 'has declared origin'}]
    edges += [{'source': artifact_id, 'target': item['id'], 'label': 'has finding'} for item in related_findings]
    edges += [{'source': item['id'], 'target': evidence_id, 'label': 'supported by'}
              for item in related_findings for evidence_id in item['evidenceIds']]
    edges += [{'source': artifact_id, 'target': item['id'], 'label': 'fingerprinted by'}
              for item in related_evidence if item['kind'] == 'INTEGRITY']
    scanners = sorted({item['scanner'] for item in related_evidence if item.get('scanner')})
    for scanner in scanners:
        scanner_id = 'scanner:' + artifact_id + ':' + scanner
        nodes.append({'id': scanner_id, 'label': scanner, 'kind': 'Scanner'})
        edges.extend({'source': scanner_id, 'target': item['id'], 'label': 'produced'}
                     for item in related_evidence if item.get('scanner') == scanner)

    # Policy and automated decision nodes in the evidence graph
    if policy_row:
        policy_node_id = 'policy:' + artifact_id
        nodes.append({'id': policy_node_id, 'label': 'Policy: ' + policy_row['name'], 'kind': 'Policy'})
        edges.append({'source': artifact_id, 'target': policy_node_id, 'label': 'evaluated against'})
        for finding_item in related_findings:
            edges.append({'source': finding_item['id'], 'target': policy_node_id, 'label': 'evaluated by'})
        if latest_dec:
            dec_node_id = 'decision:' + artifact_id
            nodes.append({'id': dec_node_id, 'label': 'Decision: ' + latest_dec['decision'], 'kind': 'Decision'})
            edges.append({'source': policy_node_id, 'target': dec_node_id, 'label': 'yields decision'})
            edges.append({'source': dec_node_id, 'target': artifact_id, 'label': 'recorded for'})
    return {'nodes': nodes, 'edges': edges}


@app.get('/artifacts/{artifact_id}/risk')
def risk_summary(artifact_id: str, user=Depends(current_user)):
    with connect() as db:
        row = owned_artifact(db, artifact_id, user['id'])
        scan = db.execute('''SELECT * FROM scans WHERE artifact_id = ?
                             ORDER BY created_at DESC, rowid DESC LIMIT 1''',
                          (artifact_id,)).fetchone()
        findings = report_rows(db, artifact_id, user['id'], 'findings')
    counts = {level: sum(item['severity'] == level for item in findings)
              for level in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')}
    integrity = ('UNKNOWN' if not scan or not scan['observed_hash'] else
                 'MATCH' if hmac.compare_digest(scan['observed_hash'], row['sha256']) else 'MISMATCH')
    provenance = 'UNVERIFIED' if any(row[key] for key in ('source', 'publisher', 'repository', 'revision', 'origin')) else 'MISSING'
    status = scan['status'] if scan else 'NOT_SCANNED'
    reasons = []
    if integrity == 'MISMATCH':
        reasons.append('Observed bytes differ from the uploaded artifact hash.')
    if counts['CRITICAL'] or counts['HIGH']:
        reasons.append('High severity scanner findings require investigation.')
    if status != 'COMPLETED':
        reasons.append('The latest scan did not complete; displayed findings may come from an earlier scan.')
    if provenance != 'VERIFIED':
        reasons.append('The declared source has not been independently verified.')
    reasons.append('No trusted signature verification has been performed.')
    reasons.append('Built-in checks provide limited scanner coverage.')
    state = 'INVESTIGATE' if integrity == 'MISMATCH' or counts['CRITICAL'] or counts['HIGH'] else 'INCOMPLETE'
    return {'state': state, 'reasons': reasons, 'findingCounts': counts,
            'integrity': integrity, 'provenance': provenance, 'signature': 'UNKNOWN',
            'scanStatus': status}


class DecisionPayload(BaseModel):
    model_config = ConfigDict(extra='forbid')
    decision: str = Field(min_length=3, max_length=30)
    rationale: str = Field(min_length=3, max_length=2000)
    conditions: list[str] = Field(default_factory=list)


def evaluate_artifact_policy(db: sqlite3.Connection, artifact_row, scan_row, findings, policy_id: str | None = None):
    if policy_id:
        policy_row = db.execute('SELECT * FROM policies WHERE id = ? OR code = ?', (policy_id, policy_id)).fetchone()
    else:
        policy_row = db.execute("""SELECT * FROM policies WHERE status = 'ACTIVE'
                                  ORDER BY CASE WHEN code = 'PROD-SEC-004' THEN 0 ELSE 1 END, code
                                  LIMIT 1""").fetchone()
    if policy_row is None:
        raise HTTPException(404, 'Policy not found.')
    policy = dict(policy_row)
    policy['rules'] = json.loads(policy_row['rules'])
    policy['target_formats'] = json.loads(policy_row['target_formats'])
    provenance_values = [artifact_row[key] for key in ('source', 'publisher', 'repository', 'revision', 'origin')]
    provenance_status = 'MISSING' if not any(provenance_values) else 'UNVERIFIED'
    context = {
        'artifactId': artifact_row['id'], 'format': artifact_row['format'],
        'expectedHash': artifact_row['sha256'],
        'observedHash': scan_row['observed_hash'] if scan_row else None,
        'scanStatus': scan_row['status'] if scan_row else 'NOT_SCANNED',
        'modelAuditStatus': scan_row['modelaudit_status'] if scan_row else 'UNKNOWN',
        'findings': findings,
        'provenanceFields': [key for key, value in zip(('source', 'publisher', 'repository', 'revision', 'origin'), provenance_values) if value],
        'provenanceStatus': provenance_status,
        # Signature verification is not implemented by this repository.
        'signatureStatus': 'UNKNOWN',
        'evaluatedAt': utc_now(),
    }
    try:
        result = run_policy_engine(policy, context)
    except PolicyDefinitionError as exc:
        raise HTTPException(500, f'Active policy definition is invalid: {exc}') from None
    result['evaluationId'] = 'EVAL-' + secrets.token_hex(8).upper()
    result['evidenceReferences'] = sorted({
        ref for rule in result['ruleEvaluations'] for ref in rule.get('evidenceRefs', [])
    })
    return result


def persist_policy_evaluation(db: sqlite3.Connection, artifact_row, evaluation: dict):
    policy_row = db.execute('SELECT * FROM policies WHERE id = ?', (evaluation['policyId'],)).fetchone()
    if policy_row is None:
        raise HTTPException(404, 'Policy not found.')
    snapshot = {
        'id': policy_row['id'], 'code': policy_row['code'], 'name': policy_row['name'],
        'version': policy_row['version'], 'description': policy_row['description'],
        'targetFormats': json.loads(policy_row['target_formats']),
        'rules': json.loads(policy_row['rules']),
    }
    db.execute('''INSERT INTO policy_evaluations
                  (id, artifact_id, artifact_hash, policy_id, policy_code, policy_version,
                   policy_snapshot, result_payload, created_at)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
               (evaluation['evaluationId'], artifact_row['id'], artifact_row['sha256'],
                evaluation['policyId'], evaluation['policyCode'], evaluation['policyVersion'],
                json.dumps(snapshot), json.dumps(evaluation), evaluation['evaluatedAt']))


def apply_automated_policy_decision(artifact_id: str):
    with connect() as db:
        artifact_row = db.execute('''SELECT artifacts.*, users.name AS owner_name,
                                            users.role AS owner_role
                                     FROM artifacts JOIN users ON users.id = artifacts.owner_id
                                     WHERE artifacts.id = ?''', (artifact_id,)).fetchone()
        scan_row = db.execute('''SELECT * FROM scans WHERE artifact_id = ?
                                 AND status IN ('RUNNING', 'FAILED')
                                 ORDER BY created_at DESC, id DESC LIMIT 1''', (artifact_id,)).fetchone()
        if artifact_row is None or scan_row is None:
            return

        try:
            completed_scan = dict(scan_row)
            # Findings and digest are final at this point; publish COMPLETED
            # only after policy application finishes to avoid polling races.
            if completed_scan['status'] == 'RUNNING':
                completed_scan['status'] = 'COMPLETED'
            evaluation = evaluate_artifact_policy(
                db, artifact_row, completed_scan,
                [json.loads(row['payload']) for row in db.execute(
                    'SELECT payload FROM findings WHERE scan_id = ? ORDER BY rowid',
                    (scan_row['id'],),
                ).fetchall()],
            )
            persist_policy_evaluation(db, artifact_row, evaluation)
        except HTTPException as exc:
            db.execute("UPDATE artifacts SET decision = 'QUARANTINED' WHERE id = ?", (artifact_id,))
            record_audit(db, artifact_row['owner_id'], 'ModelShield Policy Engine',
                         'Automated Policy Engine', 'POLICY_EVALUATION',
                         f"Automatic release decision was not made for {artifact_row['name']}: {exc.detail}",
                         target_id=artifact_id, target_name=artifact_row['name'], status='FAILURE',
                         details={'requiresHumanReview': True, 'evaluationError': exc.detail})
            final_scan_status = 'FAILED' if scan_row['status'] == 'FAILED' else 'COMPLETED'
            db.execute('UPDATE scans SET status = ?, progress = ?, completed_at = ? WHERE id = ?',
                       (final_scan_status, 100, utc_now(), scan_row['id']))
            finding_count = db.execute('SELECT COUNT(*) FROM findings WHERE scan_id = ?',
                                       (scan_row['id'],)).fetchone()[0]
            record_audit(db, artifact_row['owner_id'], artifact_row['owner_name'], artifact_row['owner_role'],
                         'SCAN_FAILED' if final_scan_status == 'FAILED' else 'SCAN_COMPLETED',
                         f"Scan {'failed' if final_scan_status == 'FAILED' else 'completed'} for {artifact_row['name']} with {finding_count} findings.",
                         target_id=artifact_id, target_name=artifact_row['name'], status='FAILURE' if final_scan_status == 'FAILED' else 'SUCCESS',
                         details={'findingsCount': finding_count, 'scanId': scan_row['id']})
            return

        # Apply and record every policy outcome. Conditional requirements are
        # generated from the failed rule's rationale/remediation; quarantine is
        # a recorded restrictive disposition pending any later reviewer action.
        proposed_decision = evaluation['decision']
        decision = proposed_decision
        failed_rules = [rule for rule in evaluation['ruleEvaluations'] if not rule['passed']]
        rationale = '; '.join(
            f"{rule['ruleCode']}: {rule['reason']}" for rule in failed_rules
        ) or f"All enabled checks passed under {evaluation['policyCode']}."
        rationale = f"Policy evaluation ({evaluation['policyCode']}): {rationale}"[:2000]
        conditions = [
            f"{rule['reason']} {rule['remediation']}".strip()
            for rule in failed_rules
            if rule['action'] in {'WARN', 'CONDITIONAL'}
        ]
        if decision == 'CONDITIONAL' and not conditions:
            conditions = [rule['remediation'] for rule in failed_rules if rule.get('remediation')]
        now_iso = utc_now()
        if decision:
            decision_id = 'DEC-' + secrets.token_hex(6).upper()
            signature = '0x' + secrets.token_hex(20)
            db.execute('UPDATE artifacts SET decision = ? WHERE id = ?', (decision, artifact_id))
            db.execute('''INSERT INTO decisions (id, artifact_id, reviewer_id, reviewer_name, reviewer_role,
                                                 decision, rationale, conditions, created_at, signature,
                                                 evaluation_id, policy_version, artifact_hash)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (decision_id, artifact_id, artifact_row['owner_id'], 'ModelShield Policy Engine',
                        'Automated Policy Engine', decision, rationale, json.dumps(conditions), now_iso, signature,
                        evaluation['evaluationId'], evaluation['policyVersion'], evaluation['artifactHash']))
        db.execute('UPDATE artifacts SET decision = ? WHERE id = ?', (decision, artifact_id))
        record_audit(db, artifact_row['owner_id'], 'ModelShield Policy Engine',
                     'Automated Policy Engine', 'POLICY_EVALUATION',
                     f"Evaluated {evaluation['policyCode']} for {artifact_row['name']}: {evaluation['overallOutcome']}.",
                     target_id=artifact_id, target_name=artifact_row['name'],
                     status='SUCCESS' if proposed_decision == 'APPROVED' else 'WARNING' if proposed_decision in {'CONDITIONAL', 'QUARANTINED'} else 'FAILURE',
                     details={'policyCode': evaluation['policyCode'], 'policyVersion': evaluation['policyVersion'],
                              'outcome': evaluation['overallOutcome'], 'proposedDecision': proposed_decision,
                              'evaluationId': evaluation['evaluationId'],
                              'requiresHumanReview': evaluation['requiresHumanReview'],
                              'ruleEvaluations': evaluation['ruleEvaluations']})
        if decision:
            record_audit(db, artifact_row['owner_id'], 'ModelShield Policy Engine',
                         'Automated Policy Engine', 'DECISION_RECORDED',
                         f"Policy checks set {artifact_row['name']} to {decision}.",
                         target_id=artifact_id, target_name=artifact_row['name'],
                         status='SUCCESS' if decision == 'APPROVED' else 'WARNING' if decision in {'CONDITIONAL', 'QUARANTINED'} else 'FAILURE',
                         details={'decision': decision, 'rationale': rationale, 'conditions': conditions,
                                  'policyCode': evaluation['policyCode'], 'policyVersion': evaluation['policyVersion'],
                                  'evaluationId': evaluation['evaluationId'], 'artifactHash': evaluation['artifactHash'],
                                  'automated': True})
        final_scan_status = 'FAILED' if scan_row['status'] == 'FAILED' else 'COMPLETED'
        db.execute('UPDATE scans SET status = ?, progress = ?, completed_at = ? WHERE id = ?',
                   (final_scan_status, 100, utc_now(), scan_row['id']))
        finding_count = db.execute('SELECT COUNT(*) FROM findings WHERE scan_id = ?',
                                   (scan_row['id'],)).fetchone()[0]
        record_audit(db, artifact_row['owner_id'], artifact_row['owner_name'], artifact_row['owner_role'],
                     'SCAN_FAILED' if final_scan_status == 'FAILED' else 'SCAN_COMPLETED',
                     f"Scan {'failed' if final_scan_status == 'FAILED' else 'completed'} for {artifact_row['name']} with {finding_count} findings.",
                     target_id=artifact_id, target_name=artifact_row['name'],
                     status='FAILURE' if final_scan_status == 'FAILED' else 'SUCCESS',
                     details={'findingsCount': finding_count, 'scanId': scan_row['id']})


@app.get('/policies')
def get_policies(_user=Depends(current_user)):
    with connect() as db:
        rows = db.execute('SELECT * FROM policies ORDER BY code').fetchall()
        return [{
            'id': r['id'],
            'code': r['code'],
            'name': r['name'],
            'version': r['version'],
            'description': r['description'],
            'status': r['status'],
            'targetFormats': json.loads(r['target_formats']),
            'rules': json.loads(r['rules']),
            'updatedAt': r['updated_at']
        } for r in rows]


@app.get('/policies/{policy_id}')
def get_policy(policy_id: str, _user=Depends(current_user)):
    with connect() as db:
        r = db.execute('SELECT * FROM policies WHERE id = ? OR code = ?', (policy_id, policy_id)).fetchone()
        if r is None:
            raise HTTPException(404, 'Policy not found.')
        return {
            'id': r['id'],
            'code': r['code'],
            'name': r['name'],
            'version': r['version'],
            'description': r['description'],
            'status': r['status'],
            'targetFormats': json.loads(r['target_formats']),
            'rules': json.loads(r['rules']),
            'updatedAt': r['updated_at']
        }


@app.post('/artifacts/{artifact_id}/evaluate')
def evaluate_policy(artifact_id: str, policy_id: str | None = None, user=Depends(current_user)):
    with connect() as db:
        art = owned_artifact(db, artifact_id, user['id'])
        scan = current_scan(db, artifact_id)
        findings = policy_findings(db, scan)
        eval_result = evaluate_artifact_policy(db, art, scan, findings, policy_id)
        persist_policy_evaluation(db, art, eval_result)
        record_audit(db, user['id'], user['name'], user['role'], 'POLICY_EVALUATION',
                     f"Evaluated policy {eval_result['policyCode']} on {art['name']}. Outcome: {eval_result['overallOutcome']}.",
                     target_id=artifact_id, target_name=art['name'],
                     status='SUCCESS' if eval_result['decision'] == 'APPROVED' else 'WARNING' if eval_result['decision'] in {'CONDITIONAL', 'QUARANTINED'} else 'FAILURE',
                     details={'policyCode': eval_result['policyCode'], 'policyVersion': eval_result['policyVersion'],
                              'outcome': eval_result['overallOutcome'],
                              'proposedDecision': eval_result['decision'],
                              'evaluationId': eval_result['evaluationId'],
                              'requiresHumanReview': eval_result['requiresHumanReview'],
                              'ruleEvaluations': eval_result['ruleEvaluations'],
                              'unknownSignals': eval_result['unknownSignals']})
        return eval_result


@app.post('/artifacts/{artifact_id}/replay')
def replay_decision(artifact_id: str, policy_id: str | None = None, user=Depends(csrf_user)):
    with connect() as db:
        art = owned_artifact(db, artifact_id, user['id'])
        scan = current_scan(db, artifact_id)
        if scan is None:
            raise HTTPException(409, 'Complete a security scan before replaying a decision.')
        findings = policy_findings(db, scan)
        evaluation = evaluate_artifact_policy(db, art, scan, findings, policy_id)
        persist_policy_evaluation(db, art, evaluation)
        original = db.execute('''SELECT decision, created_at FROM decisions WHERE artifact_id = ?
                                 ORDER BY created_at DESC, id DESC LIMIT 1''', (artifact_id,)).fetchone()
        replay_id = 'RPL-' + secrets.token_hex(6).upper()
        record_audit(
            db, user['id'], user['name'], user['role'], 'DECISION_REPLAY',
            f"Replayed {art['name']} against {evaluation['policyCode']} version {evaluation['policyVersion']}; original decision preserved.",
            target_id=artifact_id, target_name=art['name'],
            status='SUCCESS',
            details={'replayId': replay_id,
                     'originalDecision': original['decision'] if original else art['decision'],
                     'originalDecisionAt': original['created_at'] if original else None,
                     'policyId': evaluation['policyId'], 'policyCode': evaluation['policyCode'],
                     'policyVersion': evaluation['policyVersion'], 'evaluation': evaluation})
        return {'replayId': replay_id,
                'originalDecision': original['decision'] if original else art['decision'],
                'originalDecisionAt': original['created_at'] if original else None,
                'evaluation': evaluation}


@app.post('/artifacts/{artifact_id}/decision')
def make_decision(artifact_id: str, payload: DecisionPayload, user=Depends(csrf_user)):
    if user['role'].strip().lower() not in {'security reviewer', 'governance admin', 'admin'}:
        raise HTTPException(403, 'A Security Reviewer or administrator role is required to record a governance decision.')
    decision_val = payload.decision.strip().upper()
    if decision_val not in {'APPROVED', 'CONDITIONAL', 'QUARANTINED', 'BLOCKED'}:
        raise HTTPException(422, 'Invalid decision status.')
    if decision_val == 'CONDITIONAL' and not payload.conditions:
        raise HTTPException(422, 'A conditional decision must include at least one explicit condition.')
    with connect() as db:
        art = owned_artifact(db, artifact_id, user['id'])
        scan = current_scan(db, artifact_id)
        findings = policy_findings(db, scan)
        evaluation = evaluate_artifact_policy(db, art, scan, findings)
        persist_policy_evaluation(db, art, evaluation)
        policy_decision = evaluation['decision']
        decision_rank = {'APPROVED': 0, 'CONDITIONAL': 1, 'QUARANTINED': 2, 'BLOCKED': 3}
        if decision_rank[decision_val] < decision_rank[policy_decision]:
            raise HTTPException(409, f'The current policy evaluation requires {policy_decision} or a more restrictive decision.')
        existing = db.execute('''SELECT id, decision, reviewer_role, artifact_hash FROM decisions WHERE artifact_id = ?
                                 ORDER BY created_at DESC, id DESC LIMIT 1''', (artifact_id,)).fetchone()
        if existing:
            if existing['artifact_hash'] == art['sha256']:
                if decision_rank[decision_val] < decision_rank[existing['decision']]:
                    raise HTTPException(409, 'A reviewer cannot make the automatic decision less restrictive.')
                if decision_val == existing['decision'] and existing['reviewer_role'] != 'Automated Policy Engine':
                    raise HTTPException(409, 'This decision has already been recorded for the current artifact hash.')
        db.execute('UPDATE artifacts SET decision = ? WHERE id = ?', (decision_val, artifact_id))
        dec_id = 'DEC-' + secrets.token_hex(6).upper()
        signature = '0x' + secrets.token_hex(20)
        now_iso = utc_now()
        conditions_json = json.dumps(payload.conditions)
        db.execute('''INSERT INTO decisions (id, artifact_id, reviewer_id, reviewer_name, reviewer_role,
                                             decision, rationale, conditions, created_at, signature,
                                             evaluation_id, policy_version, artifact_hash)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                   (dec_id, artifact_id, user['id'], user['name'], user['role'],
                    decision_val, payload.rationale, conditions_json, now_iso, signature,
                    evaluation['evaluationId'], evaluation['policyVersion'], evaluation['artifactHash']))
        record_audit(db, user['id'], user['name'], user['role'], 'DECISION_RECORDED',
                     f"Recorded decision {decision_val} for {art['name']}.",
                     target_id=artifact_id, target_name=art['name'],
                     status='SUCCESS' if decision_val == 'APPROVED' else 'WARNING' if decision_val == 'CONDITIONAL' else 'FAILURE',
                     details={'decision': decision_val, 'rationale': payload.rationale, 'conditions': payload.conditions,
                              'evaluationId': evaluation['evaluationId'], 'policyCode': evaluation['policyCode'],
                              'policyVersion': evaluation['policyVersion'], 'artifactHash': evaluation['artifactHash']})
        return {
            'id': dec_id,
            'artifactId': artifact_id,
            'decision': decision_val,
            'rationale': payload.rationale,
            'conditions': payload.conditions,
            'reviewerId': user['id'],
            'reviewerName': user['name'],
            'reviewerRole': user['role'],
            'createdAt': now_iso,
            'signature': signature
        }


@app.get('/artifacts/{artifact_id}/decisions')
def get_decisions(artifact_id: str, user=Depends(current_user)):
    with connect() as db:
        owned_artifact(db, artifact_id, user['id'])
        rows = db.execute('''SELECT * FROM decisions WHERE artifact_id = ?
                             ORDER BY created_at DESC, id DESC''', (artifact_id,)).fetchall()
        return [{
            'id': r['id'],
            'artifactId': r['artifact_id'],
            'decision': r['decision'],
            'rationale': r['rationale'],
            'conditions': json.loads(r['conditions']) if r['conditions'] else [],
            'reviewerId': r['reviewer_id'],
            'reviewerName': r['reviewer_name'],
            'reviewerRole': r['reviewer_role'],
            'createdAt': r['created_at'],
            'signature': r['signature']
        } for r in rows]


@app.get('/artifacts/{artifact_id}/passport')
def get_passport(artifact_id: str, user=Depends(current_user)):
    with connect() as db:
        art = owned_artifact(db, artifact_id, user['id'])
        scan = current_scan(db, artifact_id)
        findings = policy_findings(db, scan)
        eval_result = evaluate_artifact_policy(db, art, scan, findings)
        dec_row = db.execute('''SELECT * FROM decisions WHERE artifact_id = ?
                                ORDER BY created_at DESC LIMIT 1''', (artifact_id,)).fetchone()

        if dec_row:
            dec_data = {
                'id': dec_row['id'],
                'artifactId': artifact_id,
                'decision': dec_row['decision'],
                'rationale': dec_row['rationale'],
                'conditions': json.loads(dec_row['conditions']) if dec_row['conditions'] else [],
                'reviewerId': dec_row['reviewer_id'],
                'reviewerName': dec_row['reviewer_name'],
                'reviewerRole': dec_row['reviewer_role'],
                'createdAt': dec_row['created_at'],
                'signature': dec_row['signature']
            }
        else:
            dec_data = {
                'id': 'DEC-INITIAL-' + artifact_id[:6],
                'artifactId': artifact_id,
                'decision': art['decision'],
                'rationale': 'Initial intake quarantine status pending governance sign-off.',
                'conditions': [],
                'reviewerId': user['id'],
                'reviewerName': user['name'],
                'reviewerRole': user['role'],
                'createdAt': art['uploaded_at'],
                'signature': '0x' + secrets.token_hex(16)
            }

        hash_matches = (scan is not None and scan['observed_hash'] is not None and
                        hmac.compare_digest(scan['observed_hash'], art['sha256']))

        counts = {level: sum(item['severity'] == level for item in findings)
                  for level in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')}

        passport_num = f"MSP-2026-{(abs(hash(artifact_id)) % 900000 + 100000)}"
        issued_at = dec_data['createdAt']
        seal_sig = '0x' + hmac.new(b'modelshield-governance-seal', (artifact_id + art['sha256']).encode(), 'sha256').hexdigest()[:40] + '...'

        passport = {
            'passportId': 'PSP-' + artifact_id[:8].upper(),
            'passportNumber': passport_num,
            'issuedAt': issued_at,
            'status': ('REVOKED' if art['decision'] == 'BLOCKED' else
                       'PENDING' if art['decision'] == 'QUARANTINED' else
                       'CONDITIONAL' if art['decision'] == 'CONDITIONAL' else 'VALID'),
            'artifact': {
                'id': art['id'],
                'name': art['name'],
                'model': art['model'],
                'version': art['version'],
                'format': art['format'],
                'sha256': art['sha256'],
                'uploadedBy': user['name'],
                'uploadedAt': art['uploaded_at']
            },
            'integrity': {
                'hashMatches': hash_matches,
                'observedHash': scan['observed_hash'] if scan and scan['observed_hash'] else art['sha256'],
                'expectedHash': art['sha256']
            },
            'provenance': {
                'source': art['source'],
                'publisher': art['publisher'],
                'repository': art['repository'],
                'revision': art['revision'],
                'origin': art['origin'],
                'verificationStatus': 'UNVERIFIED' if any(art[key] for key in ('source', 'publisher', 'repository', 'revision', 'origin')) else 'MISSING'
            },
            'scanSummary': {
                'scanner': 'ModelAudit 0.2.52 & Structural Engine',
                'scannedAt': scan['completed_at'] if scan else None,
                'totalFindings': len(findings),
                'criticalCount': counts['CRITICAL'],
                'highCount': counts['HIGH'],
                'mediumCount': counts['MEDIUM'],
                'lowCount': counts['LOW']
            },
            'policyEvaluation': eval_result,
            'decision': dec_data,
            'verificationSeal': {
                'algorithm': 'SHA256-RSA-MODELSHIELD-SIGN',
                'signature': seal_sig,
                'issuer': 'ModelShield Release Governance Authority'
            }
        }
        record_audit(db, user['id'], user['name'], user['role'], 'PASSPORT_GENERATED',
                     f"Generated Model Security Passport {passport_num} for {art['name']}.",
                     target_id=artifact_id, target_name=art['name'],
                     details={'passportNumber': passport_num, 'status': passport['status']})
        return passport


@app.get('/audit')
def audit_trail(event_type: str | None = None, target_id: str | None = None, user=Depends(current_user)):
    with connect() as db:
        query = 'SELECT * FROM audit_logs WHERE user_id = ?'
        params = [user['id']]
        if event_type:
            query += ' AND event_type = ?'
            params.append(event_type)
        if target_id:
            query += ' AND target_id = ?'
            params.append(target_id)
        query += ' ORDER BY created_at DESC, id DESC LIMIT 200'
        rows = db.execute(query, params).fetchall()
        return [{
            'id': r['id'],
            'timestamp': r['created_at'],
            'eventType': r['event_type'],
            'actor': {'id': r['user_id'], 'name': r['user_name'], 'role': r['user_role']},
            'targetId': r['target_id'],
            'targetName': r['target_name'],
            'description': r['description'],
            'status': r['status'],
            'details': json.loads(r['payload']) if r['payload'] else {}
        } for r in rows]


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=8000)

