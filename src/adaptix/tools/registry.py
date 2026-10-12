"""ADAPTIX unified module. Migrated from tested running code."""
import os
import shutil
import subprocess
import importlib.util
import importlib.metadata
from pathlib import Path
from src.adaptix.config import config


def _version_or_help(path, args, timeout=8):
    try:
        out = subprocess.run([path, *args], capture_output=True, text=True, timeout=timeout, check=False)
        return (out.stdout + '\n' + out.stderr)[:12000]
    except (OSError, subprocess.TimeoutExpired):
        return ''

def tool_registry():
    """Never accept Python httpx/httpx2 in place of ProjectDiscovery CLI."""
    data = config('tools.yaml')['tools']
    result = {}
    for name in ('nmap', 'httpx', 'nuclei'):
        spec = data[name]
        if not spec.get('enabled', True):
            result[name] = {'enabled': False, 'path': None, 'detail': 'disabled'}
            continue
        override = os.environ.get(spec.get('env', ''), '').strip()
        candidates = [override] if override else [spec.get('command', name)]
        if name == 'httpx' and not override:
            candidates += ['/usr/bin/httpx2', '/bin/httpx2', 'httpx2']
        found = None
        detail = 'not found / failed identity validation'
        for candidate in candidates:
            path = shutil.which(candidate) if not os.path.isabs(candidate) else candidate
            if not path or not Path(path).is_file() or not os.access(path, os.X_OK):
                continue
            help_text = _version_or_help(path, ['-h'])
            if name == 'httpx' and not ('-rate-limit' in help_text and '-json' in help_text and 'httpx' in help_text.lower()):
                continue
            if name == 'nuclei':
                version_text = _version_or_help(path, ['-version'])
                if 'nuclei engine version:' not in version_text.lower():
                    continue
            if name == 'nmap' and 'nmap' not in _version_or_help(path, ['--version']).lower():
                continue
            found, detail = path, 'validated'
            break
        version = _version_or_help(found, ['--version'] if name == 'nmap' else ['-version']) if found else ''
        result[name] = {'enabled': True, 'path': found, 'detail': detail,
                        'version': next((line.strip() for line in version.splitlines() if line.strip()), '')[:160]}
    spec = data['playwright']
    enabled = bool(spec.get('enabled', True))
    installed = importlib.util.find_spec('playwright') is not None
    result['playwright'] = {'enabled': enabled, 'path': 'python-module' if (installed and enabled) else None,
                            'detail': 'disabled' if not enabled else ('validated' if installed else 'python package missing'),
                            'version': importlib.metadata.version('playwright') if installed else ''}
    return result

def run_tool(argv, timeout=45, stdin=None):
    """No shell interpolation; prevent unbounded output and hanging processes."""
    try:
        completed = subprocess.run(argv, input=stdin, capture_output=True, text=True,
                                   timeout=timeout, check=False, errors='replace')
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'returncode': -1, 'stdout': '', 'stderr': str(exc)}
    return {'returncode': completed.returncode, 'stdout': completed.stdout[:1_000_000],
            'stderr': completed.stderr[-2500:]}
