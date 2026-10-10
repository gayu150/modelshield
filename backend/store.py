import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager

from .config import DATA_DIR, DATABASE, SESSION_SECONDS, UPLOAD_DIR


def initialize():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL, role TEXT NOT NULL,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
                csrf_token TEXT NOT NULL, expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
            CREATE TABLE IF NOT EXISTS login_failures (
                email TEXT PRIMARY KEY, attempts INTEGER NOT NULL, first_attempt INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id),
                name TEXT NOT NULL, model TEXT NOT NULL, version TEXT NOT NULL,
                format TEXT NOT NULL, uploaded_at TEXT NOT NULL,
                source TEXT, publisher TEXT, repository TEXT, revision TEXT, origin TEXT,
                path TEXT NOT NULL, sha256 TEXT NOT NULL,
                decision TEXT NOT NULL DEFAULT 'QUARANTINED'
            );
            CREATE INDEX IF NOT EXISTS artifacts_owner_time ON artifacts(owner_id, uploaded_at DESC);
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES artifacts(id),
                status TEXT NOT NULL, progress INTEGER NOT NULL,
                created_at TEXT NOT NULL, completed_at TEXT,
                error TEXT, observed_hash TEXT,
                modelaudit_status TEXT NOT NULL DEFAULT 'UNKNOWN', modelaudit_error TEXT
            );
            CREATE INDEX IF NOT EXISTS scans_artifact_time ON scans(artifact_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id),
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS findings_scan ON findings(scan_id);
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id),
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS evidence_scan ON evidence(scan_id);
            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY, code TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL, version TEXT NOT NULL,
                description TEXT NOT NULL, status TEXT NOT NULL,
                target_formats TEXT NOT NULL, rules TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES artifacts(id),
                reviewer_id TEXT NOT NULL REFERENCES users(id),
                reviewer_name TEXT NOT NULL, reviewer_role TEXT NOT NULL,
                decision TEXT NOT NULL, rationale TEXT NOT NULL,
                conditions TEXT, valid_until TEXT, created_at TEXT NOT NULL,
                signature TEXT NOT NULL, evaluation_id TEXT, policy_version TEXT, artifact_hash TEXT
            );
            CREATE INDEX IF NOT EXISTS decisions_artifact ON decisions(artifact_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS policy_evaluations (
                id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES artifacts(id),
                artifact_hash TEXT, policy_id TEXT NOT NULL, policy_code TEXT NOT NULL,
                policy_version TEXT NOT NULL, policy_snapshot TEXT NOT NULL,
                result_payload TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS evaluations_artifact ON policy_evaluations(artifact_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
                user_name TEXT NOT NULL, user_role TEXT NOT NULL,
                event_type TEXT NOT NULL, target_id TEXT,
                target_name TEXT, description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'SUCCESS',
                payload TEXT, created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS audit_logs_time ON audit_logs(created_at DESC);
        ''')
        # In-process work from a previous server run cannot resume.
        db.execute("UPDATE scans SET status = 'FAILED', error = 'Server restarted during scan.' WHERE status IN ('QUEUED', 'RUNNING')")
        columns = {row['name'] for row in db.execute('PRAGMA table_info(artifacts)')}
        for column in ('publisher', 'repository', 'revision', 'origin'):
            if column not in columns:
                db.execute(f'ALTER TABLE artifacts ADD COLUMN {column} TEXT')
        decision_columns = {row['name'] for row in db.execute('PRAGMA table_info(decisions)')}
        for column in ('evaluation_id', 'policy_version', 'artifact_hash'):
            if column not in decision_columns:
                db.execute(f'ALTER TABLE decisions ADD COLUMN {column} TEXT')
        scan_columns = {row['name'] for row in db.execute('PRAGMA table_info(scans)')}
        if 'modelaudit_status' not in scan_columns:
            db.execute("ALTER TABLE scans ADD COLUMN modelaudit_status TEXT NOT NULL DEFAULT 'UNKNOWN'")
        if 'modelaudit_error' not in scan_columns:
            db.execute('ALTER TABLE scans ADD COLUMN modelaudit_error TEXT')

        # Seed standard release policies if table is empty
        policy_count = db.execute('SELECT COUNT(*) FROM policies').fetchone()[0]
        if policy_count == 0:
            default_policies = [
                {
                    'id': 'POL-PROD-004',
                    'code': 'PROD-SEC-004',
                    'name': 'Production Model Security',
                    'version': '2.0',
                    'description': 'Enterprise release standard for customer-facing and production inference pipelines. Blocks release on critical findings or hash mismatches.',
                    'status': 'ACTIVE',
                    'target_formats': json.dumps(['ONNX', 'PKL', 'PT', 'SAFETENSORS', 'H5']),
                    'updated_at': '2026-10-01T08:00:00Z',
                    'rules': json.dumps([
                        {'id': 'R-01', 'code': 'RULE-CRIT-FAIL', 'title': 'Zero Tolerance Critical Findings',
                         'description': 'Release blocked if any CRITICAL severity finding is detected in static or structural analysis.',
                         'trigger': 'CRITICAL', 'action': 'BLOCK', 'enabled': True},
                        {'id': 'R-02', 'code': 'RULE-HIGH-REVIEW', 'title': 'High Severity Triage Requirement',
                         'description': 'Artifacts with HIGH severity findings require conditional sign-off with documented mitigation.',
                         'trigger': 'HIGH', 'action': 'WARN', 'enabled': True},
                        {'id': 'R-03', 'code': 'RULE-HASH-INTEGRITY', 'title': 'Cryptographic Digest Match',
                         'description': 'Observed file hash during scan must match the uploader SHA-256 fingerprint exactly.',
                         'trigger': 'HASH_MISMATCH', 'action': 'BLOCK', 'enabled': True},
                        {'id': 'R-04', 'code': 'RULE-PROV-CHECK', 'title': 'Supply Chain Provenance Verification',
                         'description': 'Artifact source and repository claims must be specified and reviewed.',
                         'trigger': 'UNVERIFIED_PROVENANCE', 'action': 'WARN', 'enabled': True},
                    ]),
                },
                {
                    'id': 'POL-SANDBOX-001',
                    'code': 'DEV-SANDBOX-001',
                    'name': 'Development Sandbox Policy',
                    'version': '1.1',
                    'description': 'Permissive governance tier for internal research and scratchpad experimentation. Warns on vulnerabilities without halting evaluation.',
                    'status': 'ACTIVE',
                    'target_formats': json.dumps(['ONNX', 'PKL', 'PT', 'SAFETENSORS', 'H5', 'BIN']),
                    'updated_at': '2026-09-15T12:00:00Z',
                    'rules': json.dumps([
                        {'id': 'R-05', 'code': 'RULE-HASH-BASIC', 'title': 'Digest Sanity Check',
                         'description': 'Blocks corrupted transfers if bytes fail fingerprinting.',
                         'trigger': 'HASH_MISMATCH', 'action': 'BLOCK', 'enabled': True},
                        {'id': 'R-06', 'code': 'RULE-CRIT-WARN', 'title': 'Advisory Critical Alert',
                         'description': 'Flags critical issues for developer remediation before staging promotion.',
                         'trigger': 'CRITICAL', 'action': 'WARN', 'enabled': True},
                    ]),
                },
                {
                    'id': 'POL-FIN-009',
                    'code': 'FIN-COMPLY-009',
                    'name': 'Regulated Financial AI Standard',
                    'version': '3.0',
                    'description': 'Strict compliance policy for banking, fraud detection, and credit scoring models under regulatory scrutiny.',
                    'status': 'ACTIVE',
                    'target_formats': json.dumps(['ONNX', 'SAFETENSORS']),
                    'updated_at': '2026-10-05T09:30:00Z',
                    'rules': json.dumps([
                        {'id': 'R-07', 'code': 'RULE-STRICT-CRIT', 'title': 'Critical Security Zero-Tolerance',
                         'description': 'Immediate release veto on any discovered code execution or serialization risk.',
                         'trigger': 'CRITICAL', 'action': 'BLOCK', 'enabled': True},
                        {'id': 'R-08', 'code': 'RULE-STRICT-HIGH', 'title': 'High Severity Zero-Tolerance',
                         'description': 'High severity findings unconditionally block release in regulated tiers.',
                         'trigger': 'HIGH', 'action': 'BLOCK', 'enabled': True},
                        {'id': 'R-09', 'code': 'RULE-PROV-MANDATORY', 'title': 'Verified Publisher Identity',
                         'description': 'Unverified provenance claims immediately block release.',
                         'trigger': 'UNVERIFIED_PROVENANCE', 'action': 'BLOCK', 'enabled': True},
                    ]),
                },
            ]
            for p in default_policies:
                db.execute('''INSERT INTO policies (id, code, name, version, description, status, target_formats, rules, updated_at)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (p['id'], p['code'], p['name'], p['version'], p['description'], p['status'],
                            p['target_formats'], p['rules'], p['updated_at']))


def record_audit(db: sqlite3.Connection, user_id: str, user_name: str, user_role: str,
                 event_type: str, description: str, target_id: str | None = None,
                 target_name: str | None = None, status: str = 'SUCCESS',
                 details: dict | None = None):
    audit_id = 'AUD-' + secrets.token_hex(6).upper()
    now_iso = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    db.execute('''INSERT INTO audit_logs (id, user_id, user_name, user_role, event_type,
                                          target_id, target_name, description, status, payload, created_at)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
               (audit_id, user_id, user_name, user_role, event_type, target_id, target_name,
                description, status, json.dumps(details or {}), now_iso))
    return audit_id



@contextmanager
def connect():
    db = sqlite3.connect(DATABASE, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys = ON')
    db.execute('PRAGMA busy_timeout = 30000')
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600_000)
    return salt.hex() + ':' + digest.hex()


def check_password(password: str, stored: str) -> bool:
    try:
        salt_hex, expected_hex = stored.split(':', 1)
        candidate = password_hash(password, bytes.fromhex(salt_hex)).split(':', 1)[1]
        return hmac.compare_digest(candidate, expected_hex)
    except (ValueError, TypeError):
        return False


# Keep failed-login verification cost comparable for unknown and known emails.
DUMMY_PASSWORD_HASH = password_hash('not-a-real-account-password')


def new_session(db: sqlite3.Connection, user_id: str):
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    db.execute('DELETE FROM sessions WHERE expires_at <= ?', (int(time.time()),))
    db.execute('INSERT INTO sessions VALUES (?, ?, ?, ?)',
               (hashlib.sha256(token.encode()).hexdigest(), user_id, csrf, int(time.time()) + SESSION_SECONDS))
    return token


def find_session(db: sqlite3.Connection, token: str | None):
    if not token:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    return db.execute('''SELECT users.id, users.email, users.name, users.role, sessions.csrf_token
                         FROM sessions JOIN users ON users.id = sessions.user_id
                         WHERE sessions.token_hash = ? AND sessions.expires_at > ?''',
                      (digest, int(time.time()))).fetchone()


def end_session(db: sqlite3.Connection, token: str):
    db.execute('DELETE FROM sessions WHERE token_hash = ?',
               (hashlib.sha256(token.encode()).hexdigest(),))
