"""Test package marker.

Present so the suite can be collected from any working directory. Two import styles
depend on it, and they pull in opposite directions once this file exists:

* ``from tests.test_adaptix_planning_recovery import ...`` needs ``tests`` to be an
  importable package, so the project root must be on ``sys.path``.
* ``from test_adaptix_idor import ...`` (implicit-relative, written before this file
  existed) needs ``tests/`` itself on ``sys.path``, or the module is not found.

Both paths are registered here rather than in ``pyproject.toml`` because bare
``pytest`` from an arbitrary cwd must work without the caller passing ``-o pythonpath``.
Registering the package directory second keeps ``tests.*`` resolution first.
"""
import pathlib
import sys

_TESTS_DIR = pathlib.Path(__file__).resolve().parent
_ROOT = _TESTS_DIR.parent

for _path in (str(_ROOT), str(_TESTS_DIR)):
    if _path not in sys.path:
        sys.path.insert(0, _path)
