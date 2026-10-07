import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv('MODELSHIELD_DATA_DIR', str(ROOT / 'data'))).resolve()
DATABASE = DATA_DIR / 'modelshield.sqlite3'
UPLOAD_DIR = DATA_DIR / 'uploads'
MAX_UPLOAD_BYTES = 2 * 1024**3
SCAN_PREFIX_BYTES = 64 * 1024**2
SESSION_SECONDS = 8 * 60 * 60
ALLOWED_HOSTS = [host.strip() for host in os.getenv('MODELSHIELD_ALLOWED_HOSTS', '127.0.0.1,localhost,testserver').split(',') if host.strip()]
FORCE_SECURE_COOKIE = os.getenv('MODELSHIELD_SECURE_COOKIE', 'false').lower() == 'true'
