"""Local wordlist loading and provenance for reproducible lab runs."""

import hashlib
import json
from pathlib import Path
from src.adaptix.config import ROOT

DATA = ROOT / 'work' / 'wordlists' / 'SecLists'


def load_wordlist(path: Path | None = None) -> tuple[list[str], dict]:
    selected = Path(path) if path is not None else DATA / "common.txt"
    try:
        if selected.stat().st_size > 10_000_000:
            raise ValueError('wordlist_too_large')
        raw = selected.read_bytes()
        words = [line.strip() for line in raw.decode("utf-8-sig").splitlines() if line.strip()]
    except (OSError, UnicodeError):
        raise ValueError("wordlist_unreadable") from None
    if not words:
        raise ValueError("wordlist_empty")
    digest = hashlib.sha256(raw).hexdigest()
    if path is None:
        provenance = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
        if digest != provenance["sha256"]:
            raise ValueError("wordlist_integrity_failed")
    else:
        provenance = {"project": "operator_file", "file_name": selected.name, "sha256": digest}
    return words, {**provenance, "entries": len(words)}
