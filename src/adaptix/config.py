"""ADAPTIX unified module. Migrated from tested running code."""
from functools import lru_cache
from pathlib import Path
import yaml
ROOT = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=16)
def config(filename):
    """Configuration is immutable for the lifetime of a run; parse each file once."""
    with (ROOT / 'config' / filename).open(encoding='utf-8') as f:
        return yaml.safe_load(f)
