"""ADAPTIX unified module. Migrated from tested running code."""
import hashlib
from src.adaptix.config import ROOT


def artifact_path(state, stage, host, suffix):
    safe = hashlib.sha256(host.encode()).hexdigest()[:12]
    folder = ROOT / 'artifacts' / 'scans' / state['run_id']
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    return folder / f'{stage}-{safe}.{suffix}'

def save_text(path, text):
    path.write_text(text, encoding='utf-8')
    path.chmod(0o600)
