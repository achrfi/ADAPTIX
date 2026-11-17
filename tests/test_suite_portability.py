"""The suite must collect from any working directory on any machine.

Measured defect: three test modules failed to collect outside the project root.
`tests/test_idor_severity.py` read `src/...` relative to the process cwd, and eleven
modules inserted a literal `/root/projects/adaptix` into `sys.path`, so the suite only
worked on the machine that wrote it. A checkout on another host, or a CI runner that
invokes pytest from the repository root with a different absolute path, could not run.

This module pins the property instead of the individual files: no test may depend on an
absolute path, and collection must succeed with the cwd set elsewhere.
"""
import pathlib
import re
import subprocess
import sys


TESTS_DIR = pathlib.Path(__file__).resolve().parent
ROOT = TESTS_DIR.parent


def _test_files():
    return sorted(TESTS_DIR.glob('test_*.py'))


def test_no_test_file_hardcodes_an_absolute_project_path():
    offenders = []
    for path in _test_files():
        for lineno, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            # `/root/...`, `C:\...`, and any other drive-rooted literal path.
            if re.search(r"['\"](/root/|[A-Za-z]:\\\\)", line):
                offenders.append(f'{path.name}:{lineno}: {line.strip()}')
    assert not offenders, (
        'a test resolves a path from the machine that wrote it; '
        'use pathlib.Path(__file__).resolve().parents[1] instead:\n' + '\n'.join(offenders))


def test_no_test_file_does_a_cwd_relative_read():
    """`Path('src/...')` silently depends on where pytest was invoked."""
    offenders = []
    for path in _test_files():
        text = path.read_text(encoding='utf-8')
        for match in re.finditer(r"pathlib\.Path\(\s*['\"](src|tests)/", text):
            line = text[:match.start()].count('\n') + 1
            offenders.append(f'{path.name}:{line}')
    assert not offenders, (
        'cwd-relative read breaks collection outside the project root: '
        + ', '.join(offenders))


def test_collection_succeeds_from_a_foreign_cwd(tmp_path):
    """Collect every test module with the cwd outside the project tree."""
    result = subprocess.run(
        [sys.executable, '-m', 'pytest', str(TESTS_DIR), '--collect-only', '-q',
         '-p', 'no:cacheprovider', '--no-header'],
        cwd=str(tmp_path), capture_output=True, text=True, timeout=600,
    )
    assert result.returncode == 0, (
        'collection from a foreign cwd failed:\n'
        + result.stdout[-3000:] + result.stderr[-2000:])
    assert 'error during collection' not in result.stdout, result.stdout[-2000:]
    # Pin the whole suite, not just "no error": a fix that silently collected nothing
    # would otherwise pass this test.
    last = (result.stdout.strip().splitlines() or ['0'])[-1]
    collected = int(last.split()[0])
    assert collected > 500, f'only {collected} tests collected: the suite is not whole'
