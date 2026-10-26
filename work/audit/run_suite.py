"""Run regression tests on an isolated copy; preserve the working project's artifacts."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('label')
    args = parser.parse_args()
    if not args.label.replace('-', '').isalnum():
        parser.error('label must be alphanumeric')
    destination = ROOT / 'work' / 'audit' / args.label
    project = destination / 'project'
    project.mkdir(parents=True, exist_ok=False)
    for name in ('src', 'tests', 'config', 'templates', 'lab', 'scripts'):
        shutil.copytree(ROOT / name, project / name,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.adaptix_scope_signing_key'))
    for name in ('pyproject.toml', 'requirements.lock', 'langgraph.json', '.env.example', 'INTEGRATION.md'):
        shutil.copy2(ROOT / name, project / name)
    (project / 'work').mkdir()
    shutil.copy2(ROOT / 'work' / 'recon_local.py', project / 'work' / 'recon_local.py')
    shutil.copytree(ROOT / 'work' / 'checks', project / 'work' / 'checks')
    shutil.copytree(ROOT / 'work' / 'wordlists', project / 'work' / 'wordlists')
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1',
           'LITELLM_LOCAL_MODEL_COST_MAP': 'True', 'LANGSMITH_TRACING': 'false'}
    env.pop('PYTHONPATH', None)
    command = [sys.executable, '-m', 'pytest', 'tests', 'work/checks', '-q', '-p', 'no:cacheprovider',
               '--basetemp', str(destination / 'pytest-tmp'), '--tb=short']
    started = time.monotonic()
    with (destination / 'pytest.log').open('w') as output:
        result = subprocess.run(command, cwd=project, env=env, stdout=output,
                                stderr=subprocess.STDOUT, timeout=600, check=False)
    summary = {'label': args.label, 'returncode': result.returncode,
               'elapsed_seconds': round(time.monotonic() - started, 2),
               'log': str(destination.relative_to(ROOT) / 'pytest.log')}
    (destination / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)
    print('\n'.join((destination / 'pytest.log').read_text().splitlines()[-12:]))
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
