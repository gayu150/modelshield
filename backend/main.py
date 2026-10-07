import hmac
import json
import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field

from .config import ALLOWED_HOSTS, FORCE_SECURE_COOKIE, MAX_UPLOAD_BYTES, SESSION_SECONDS, UPLOAD_DIR
from .scanner import EXTENSIONS, digest, report, utc_now, validate_content
from .modelaudit_adapter import ScannerUnavailable, scan as modelaudit_scan
from .store import DUMMY_PASSWORD_HASH, check_password, connect, end_session, find_session, initialize, new_session


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


def artifact_json(db: sqlite3.Connection, row):
    scan = latest_scan(db, row['id'])
    findings = db.execute('SELECT COUNT(*) FROM findings WHERE scan_id = ?',
                          (scan['id'],)).fetchone()[0] if scan else 0
    return {'id': row['id'], 'name': row['name'], 'model': row['model'],
            'version': row['version'], 'format': row['format'],
            'uploadedBy': row['owner_name'], 'uploadedAt': row['uploaded_at'],
            'decision': row['decision'], 'findings': findings, 'hash': row['sha256'],
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
    response.set_cookie('modelshield_session', token, max_age=SESSION_SECONDS,
                        httponly=True, secure=FORCE_SECURE_COOKIE or request.url.scheme == 'https',
                        samesite='strict', path='/')
    return {'id': user['id'], 'email': user['email'], 'name': user['name'], 'role': user['role']}


@app.get('/auth/me')
def me(user=Depends(current_user)):
    return {key: user[key] for key in ('id', 'email', 'name', 'role')} | {'csrfToken': user['csrf_token']}


@app.post('/auth/logout', status_code=204)
def logout(request: Request, response: Response, _user=Depends(csrf_user)):
    with connect() as db:
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


def run_scan(scan_id: str, artifact_id: str, path: str, extension: str, expected_hash: str):
    try:
        with connect() as db:
            db.execute('UPDATE scans SET status = ? WHERE id = ?', ('RUNNING', scan_id))
        findings, evidence, observed = report(Path(path), extension, expected_hash)
        external_findings, external_evidence = modelaudit_scan(Path(path), extension, artifact_id, scan_id, observed)
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
            db.execute('UPDATE scans SET status = ?, progress = ?, completed_at = ?, observed_hash = ? WHERE id = ?',
                       ('COMPLETED', 100, utc_now(), observed, scan_id))
    except Exception as exc:
        failure = str(exc) if isinstance(exc, ScannerUnavailable) else 'Scanner failed.'
        with connect() as db:
            db.execute('UPDATE scans SET status = ?, progress = ?, completed_at = ?, error = ? WHERE id = ?',
                       ('FAILED', 100, utc_now(), failure, scan_id))


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
    background_tasks.add_task(run_scan, scan_id, artifact_id, row['path'], '.' + row['format'].lower(), row['sha256'])
    return {'scan_id': scan_id}


@app.get('/scans/{scan_id}')
def scan_status(scan_id: str, user=Depends(current_user)):
    with connect() as db:
        row = db.execute('''SELECT scans.* FROM scans JOIN artifacts ON artifacts.id = scans.artifact_id
                            WHERE scans.id = ? AND artifacts.owner_id = ?''',
                         (scan_id, user['id'])).fetchone()
        if row is None:
            raise HTTPException(404, 'Scan not found.')
        return {'id': row['id'], 'status': row['status'], 'progress': row['progress'],
                'error': row['error'] if row['status'] == 'FAILED' else None}


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
