"""ADAPTIX unified module. Migrated from tested running code."""
import hashlib
import re
from src.adaptix.config import ROOT


def artifact_path(state, stage, host, suffix):
    safe = hashlib.sha256(host.encode()).hexdigest()[:12]
    run_id = str(state['run_id'])
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', run_id):
        run_id = hashlib.sha256(run_id.encode()).hexdigest()[:24]
    folder = ROOT / 'artifacts' / 'scans' / run_id
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    return folder / f'{stage}-{safe}.{suffix}'

def save_text(path, text):
    path.write_text(text, encoding='utf-8')
    path.chmod(0o600)
