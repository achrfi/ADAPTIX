"""ADAPTIX unified module. Migrated from tested running code."""
from functools import lru_cache
from pathlib import Path
import os
import yaml
ROOT = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=16)
def config(filename):
    """Configuration is immutable for the lifetime of a run; parse each file once."""
    with (ROOT / 'config' / filename).open(encoding='utf-8') as f:
        return yaml.safe_load(f)


def load_dotenv():
    """Load `.env` into os.environ without overriding an already-set variable.

    The project shipped a `.env.example` and a `.env`, but nothing read either:
    an operator who put a provider key there saw it ignored, and had to export
    the variable by hand for every shell. Real environment variables win, so a
    one-off `ADAPTIX_API_KEY=... python -m ...` still overrides the file.

    Returns the list of variable names that were newly set - never the values,
    so this is safe to print or log.
    """
    path = ROOT / '.env'
    if not path.is_file():
        return []
    applied = []
    try:
        lines = path.read_text(encoding='utf-8').splitlines()
    except OSError:
        return []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        if line.lower().startswith('export '):
            line = line[7:].lstrip()
        key, _, value = line.partition('=')
        key = key.strip()
        if not key or key in os.environ:
            continue
        value = value.strip()
        # Strip one layer of matching quotes; keep everything else verbatim so a
        # key containing '#' or spaces survives.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        os.environ[key] = value
        applied.append(key)
    return applied
