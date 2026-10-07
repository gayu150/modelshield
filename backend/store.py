import hashlib
import hmac
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
                error TEXT, observed_hash TEXT
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
        ''')
        # In-process work from a previous server run cannot resume.
        db.execute("UPDATE scans SET status = 'FAILED', error = 'Server restarted during scan.' WHERE status IN ('QUEUED', 'RUNNING')")
        columns = {row['name'] for row in db.execute('PRAGMA table_info(artifacts)')}
        for column in ('publisher', 'repository', 'revision', 'origin'):
            if column not in columns:
                db.execute(f'ALTER TABLE artifacts ADD COLUMN {column} TEXT')


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
