"""Prepare only the persistent local VAmPI lab; preserve existing records."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import time
import httpx

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'artifacts/labs/vampi'
URL = 'http://127.0.0.1:18080'

def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + '.tmp-' + secrets.token_hex(4))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(json.dumps(data, indent=2) if not isinstance(data, str) else data)
    temporary.replace(path)

def prepare():
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (DATA / 'prepare.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        credentials = DATA / 'accounts.json'
        if not credentials.exists():
            nonce = secrets.token_hex(5)
            save(credentials, {'owner': {'username': 'adaptix_owner_' + nonce, 'password': secrets.token_urlsafe(24)},
                'other': {'username': 'adaptix_other_' + nonce, 'password': secrets.token_urlsafe(24)},
                'book': 'adaptix_private_' + nonce, 'secret': secrets.token_urlsafe(24)})
        settings = json.loads(credentials.read_text())
        tokens = {}
        with httpx.Client(base_url=URL, trust_env=False, timeout=10, follow_redirects=False) as client:
            root = client.get('/'); root.raise_for_status()
            if root.json().get('vulnerable') != 1:
                raise RuntimeError('Expected the explicitly vulnerable local VAmPI lab')
            for role in ('owner', 'other'):
                account = settings[role]
                register = client.post('/users/v1/register', json={**account, 'email': account['username'] + '@vampi.invalid'})
                register.raise_for_status()
                login = client.post('/users/v1/login', json=account)
                login.raise_for_status()
                token = login.json().get('auth_token')
                if not isinstance(token, str):
                    raise RuntimeError('Lab login failed; existing accounts were not reset')
                me = client.get('/me', headers={'Authorization': 'Bearer ' + token})
                me.raise_for_status()
                if me.json().get('data', {}).get('username') != account['username']:
                    raise RuntimeError('Identity validation failed')
                tokens[role] = token
            target = URL + '/books/v1/' + settings['book']
            headers = {'Authorization': 'Bearer ' + tokens['owner']}
            book = client.get(target, headers=headers)
            if book.status_code == 404:
                created = client.post('/books/v1', headers=headers, json={'book_title': settings['book'], 'secret': settings['secret']})
                created.raise_for_status()
                book = client.get(target, headers=headers)
            book.raise_for_status()
            if book.json().get('owner') != settings['owner']['username'] or book.json().get('secret') != settings['secret']:
                raise RuntimeError('Book ownership/content changed; refusing to replace existing data')
        scenario = [{'name': 'vampi-private-book', 'base_url': URL, 'path_template': '/books/v1/{object_id}',
            'object_id': settings['book'], 'method': 'GET',
            **{role + '_identity': {'name': settings[role]['username'], 'headers': {'Authorization': 'Bearer ' + tokens[role]}}
               for role in ('owner', 'other')},
            'ground_truth': {'private': True, 'identities_valid': True, 'owner': settings['owner']['username'], 'object_id': settings['book']}}]
        db = DATA / 'data/database/database.db'
        with sqlite3.connect(db) as connection:
            connection.execute('PRAGMA query_only=ON')
            object_owner = connection.execute('SELECT users.username FROM books JOIN users ON books.user_id=users.id WHERE book_title=?', (settings['book'],)).fetchone()
            if not object_owner or object_owner[0] != settings['owner']['username']:
                raise RuntimeError('Persistent database does not establish expected private-object ownership')
        manifest = {'version': 'adaptix-persistent-vampi-v1', 'scope': URL, 'target': target, 'prepared_at': int(time.time()),
            'image': (ROOT / 'lab/vampi/image.lock').read_text().strip(), 'database': str(db),
            'snapshot_sha256': hashlib.sha256(db.read_bytes()).hexdigest(),
            'ground_truth': {'private_object_owner': settings['owner']['username'], 'object_id': settings['book'],
                'identities_checked_via': '/me', 'vulnerable': True},
            'prepare_preserves_existing_records': True}
        save(DATA / 'scenarios.json', scenario)
        save(DATA / 'target.txt', target + '\n')
        save(DATA / 'manifest.json', manifest)
        save(ROOT / 'artifacts/idor-vampi-scenarios.json', scenario)
        save(ROOT / 'artifacts/idor-vampi-target.txt', target + '\n')
        print(json.dumps({'lab': 'ready', 'base_url': URL, 'target': target, 'scenarios': str(DATA / 'scenarios.json'),
            'identities_validated': 2, 'existing_data_preserved': True}))

if __name__ == '__main__':
    try:
        prepare()
    except Exception as error:
        # Never echo HTTP bodies, credentials or signed tokens.
        print('Lab preparation failed: ' + type(error).__name__ + '. Check service health and persistent accounts/database.', file=sys.stderr)
        raise SystemExit(1)
