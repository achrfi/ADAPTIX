import json
import os
from pathlib import Path
import sqlite3
import tarfile
import time

root = Path(__file__).resolve().parents[2]
data = root / 'artifacts/labs/vampi'
destination = data / 'backups' / ('state-' + time.strftime('%Y%m%d-%H%M%S'))
destination.mkdir(parents=True, mode=0o700)
snapshot = destination / 'database.db'
with sqlite3.connect(data / 'data/database/database.db') as source, sqlite3.connect(snapshot) as target:
    source.backup(target)
snapshot.chmod(0o600)
with tarfile.open(destination / 'configuration.tar.gz', 'w:gz') as archive:
    archive.add(root / 'lab/vampi', arcname='lab/vampi', filter=lambda entry: None if '__pycache__' in entry.name else entry)
    if (data / 'accounts.json').exists(): archive.add(data / 'accounts.json', arcname='accounts.json')
(destination / 'configuration.tar.gz').chmod(0o600)
print(json.dumps({'backup': str(destination), 'sqlite_consistent_snapshot': True}))
