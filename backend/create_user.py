import getpass
import sqlite3
import uuid

if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from backend.store import connect, initialize, password_hash
else:
    from .store import connect, initialize, password_hash


def main():
    initialize()
    email = input('Work email: ').strip().lower()
    name = input('Display name: ').strip()
    role = input('Role [analyst/security reviewer/admin] (default analyst): ').strip().lower() or 'analyst'
    if not email or '@' not in email or not name:
        raise SystemExit('A valid email and display name are required.')
    if role not in {'analyst', 'security reviewer', 'governance admin', 'admin'}:
        raise SystemExit('Choose analyst, security reviewer, governance admin, or admin.')
    password = getpass.getpass('Password (at least 12 characters): ')
    confirmation = getpass.getpass('Confirm password: ')
    if len(password) < 12 or password != confirmation:
        raise SystemExit('Passwords must match and contain at least 12 characters.')
    try:
        with connect() as db:
            db.execute('INSERT INTO users VALUES (?, ?, ?, ?, ?)',
                       (str(uuid.uuid4()), email, name, role, password_hash(password)))
    except sqlite3.IntegrityError:
        raise SystemExit('That email already exists.') from None
    print('User created.')


if __name__ == '__main__':
    main()
