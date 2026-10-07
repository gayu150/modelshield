import getpass
import sqlite3
import uuid

from .store import connect, initialize, password_hash


def main():
    initialize()
    email = input('Work email: ').strip().lower()
    name = input('Display name: ').strip()
    if not email or '@' not in email or not name:
        raise SystemExit('A valid email and display name are required.')
    password = getpass.getpass('Password (at least 12 characters): ')
    confirmation = getpass.getpass('Confirm password: ')
    if len(password) < 12 or password != confirmation:
        raise SystemExit('Passwords must match and contain at least 12 characters.')
    try:
        with connect() as db:
            db.execute('INSERT INTO users VALUES (?, ?, ?, ?, ?)',
                       (str(uuid.uuid4()), email, name, 'analyst', password_hash(password)))
    except sqlite3.IntegrityError:
        raise SystemExit('That email already exists.') from None
    print('User created.')


if __name__ == '__main__':
    main()
