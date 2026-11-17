"""Suite-wide bootstrap: the project root is importable regardless of the pytest cwd.

Two portability defects are fixed here, both of which made the suite machine-local:

1. ``from src.adaptix...`` and ``from tests... import`` require the project root on
   ``sys.path``. Seeded here once, deterministically, instead of the eleven test
   modules that used to hardcode ``sys.path.insert(0, '/root/projects/adaptix')`` -
   a literal path that only worked on one workstation.
2. Test modules read project files with paths relative to the process cwd, so
   invoking ``pytest /path/to/tests`` from elsewhere aborted with a collection
   error. The root anchor below lets every module resolve its own location.

This file must stay free of project imports: it runs before ``sys.path`` is ready.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
