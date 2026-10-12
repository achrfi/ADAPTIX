"""ADAPTIX unified module. Migrated from tested running code."""
from pathlib import Path
import yaml
ROOT = Path(__file__).resolve().parents[2]


def config(filename):
    with (ROOT / 'config' / filename).open(encoding='utf-8') as f:
        return yaml.safe_load(f)
