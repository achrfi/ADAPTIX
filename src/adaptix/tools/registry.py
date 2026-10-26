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
    for name in ('httpx', 'nuclei'):
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
            found, detail = path, 'validated'
            break
        version = _version_or_help(found, ['-version']) if found else ''
        result[name] = {'enabled': True, 'path': found, 'detail': detail,
                        'version': next((line.strip() for line in version.splitlines() if line.strip()), '')[:160]}
    # Tombstone for historical callers; never expose an executable Nmap capability.
    result['nmap'] = {'enabled': False, 'path': None, 'detail': 'retired', 'version': ''}
    spec = data['playwright']
    enabled = bool(spec.get('enabled', True))
    installed = importlib.util.find_spec('playwright') is not None
    result['playwright'] = {'enabled': enabled, 'path': 'python-module' if (installed and enabled) else None,
                            'detail': 'disabled' if not enabled else ('validated' if installed else 'python package missing'),
                            'version': importlib.metadata.version('playwright') if installed else ''}
    for name in ('web_discover', 'http_request', 'browser_test'):
        result[name] = {'enabled': True, 'path': 'python-module', 'detail': 'in-process scope-pinned HTTP adapter',
                        'version': ''}
    descriptions = {'httpx': 'Observe one HTTP endpoint',
                    'nuclei': 'Run configured Nuclei templates. Adaptive mode uses historical service products/HTTPX technologies to select HTTP template tags; unknown products use native automatic detection. HTTPX first can improve selection. Matches are unverified.',
                    'playwright': 'Observe browser page and capture screenshot without form submission',
                    'browser_test': 'Navigate one in-scope URL carrying a run marker in its query in a read-only browser session, then a control navigation without the marker; captured and dismissed dialogs on the payload navigation but never from the control are the deterministic browser-execution proof for XSS candidates. Nothing is clicked or submitted.',
                    'web_discover': 'Passive reconnaissance: GET one seed document plus robots.txt and sitemap.xml, then extract in-scope links, forms, scripts and documented routes into web_routes.',
                    'http_request': 'Send one bounded, rate-limited HTTP request to an in-scope URL. Method GET/HEAD is non-destructive; POST/PUT/PATCH/DELETE require exact human approval. The response is reduced to a structured trace with deterministic signatures (SQL/NoSQL errors, reflected markup, traversal markers, sensitive data); a signature is not proof by itself.'}
    for name, description in descriptions.items():
        result[name]['description'] = description
    result['idor'] = {'enabled': True, 'path': 'python-module', 'detail': 'two-identity configured scenario; GET only',
                      'description': 'Execute a named configured scenario once: GET owner and other identity, compare responses and verify against private-object ground truth. Results and verification are already in idor_findings; evaluate them in reflection, never call this tool again to evaluate its existing result.'}
    result['union_extract'] = {
        'enabled': True, 'path': 'python-module', 'detail': 'deterministic; scope-pinned HTTP',
        'description': ('Escalate a VERIFIED SQL injection on one parameter to measurable impact. '
                        'Discovers the UNION result-column count from the server\'s own column-count '
                        'error, then extracts data (user emails, password hashes, database version) '
                        'from the injected query and verifies it against a control response. Use this '
                        'instantly after a SQL injection finding instead of writing a UNION payload by '
                        'hand: the column count is discovered, never guessed, and every request is '
                        'recorded. It targets the same endpoint and parameter the finding names; no '
                        'arguments are needed.')}
    result['api_discover'] = {'enabled': True, 'path': 'python-module',
        'description': 'GET one observed API endpoint or listed document probe, parse OpenAPI GET routes and actual collection records. No schema examples as object data.'}
    result['scenario'] = {'enabled': True, 'path': 'python-module',
        'description': 'Build a scenario from a listed scenario_candidates name. Three GET requests validate two supplied sessions and owner private content; requires identity context. Produces an idor_scenarios name for the idor tool.'}
    # Real static-content discovery (ffuf) over wordlists the project ships. This is
    # the only capability that finds paths an application never links to; without it
    # every run was limited to whatever the root document already advertised.
    static_available = bool(shutil.which(os.environ.get('ADAPTIX_FFUF_PATH', '').strip() or 'ffuf'))
    if os.environ.get('ADAPTIX_FFUF_PATH'):
        static_available = Path(os.environ['ADAPTIX_FFUF_PATH']).is_file()
    from src.adaptix.tools.static_discovery import PROFILES
    result['static_discovery'] = {
        'enabled': static_available,
        'path': os.environ.get('ADAPTIX_FFUF_PATH') or (shutil.which('ffuf') if static_available else None),
        'detail': 'validated' if static_available else 'ffuf binary not found',
        'version': (_version_or_help(shutil.which('ffuf') or '', ['-V']).strip().splitlines() or [''])[0][:160] if static_available else '',
        'description': ('Bounded static content discovery: runs ffuf against one authorized origin with a '
                        'project wordlist profile (' + '/'.join(sorted(PROFILES)) + ') and records matching '
                        'paths as observed web_routes. Finds paths the application never links to. A match '
                        'means the path answered, never that it is vulnerable.'),
        'risk': 'observe', 'operation': 'observe'}
    for name, spec in result.items():
        spec['risk'] = 'template_dependent' if name == 'nuclei' else 'observe'
        spec['operation'] = 'authorization_test_get' if name == 'idor' else 'observe'
    return result


def run_tool(argv, timeout=45, stdin=None, stderr_limit=2500):
    """No shell interpolation; prevent unbounded output and hanging processes."""
    try:
        completed = subprocess.run(argv, input=stdin, capture_output=True, text=True,
                                   timeout=timeout, check=False, errors='replace')
    except subprocess.TimeoutExpired as exc:
        def decoded(value):
            return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else value or ''
        # Nuclei emits complete JSONL findings as it runs; retain them on timeout.
        return {'returncode': -1, 'stdout': decoded(exc.stdout)[:1_000_000],
                'stderr': (f'Tool timed out after {timeout} seconds; partial output retained. '
                           + decoded(exc.stderr))[-stderr_limit:]}
    except OSError as exc:
        return {'returncode': -1, 'stdout': '', 'stderr': str(exc)}
    # Callers requesting a larger limit need the banner/accounting lines that
    # appear at the start of the stream, before periodic progress output.
    return {'returncode': completed.returncode, 'stdout': completed.stdout[:1_000_000],
            'stderr': completed.stderr[-stderr_limit:]}


def tool_handlers():
    """Capability adapters; adding tools does not change the graph topology."""
    from src.adaptix.tools.httpx import httpx_probe
    from src.adaptix.tools.nuclei import nuclei_check
    from src.adaptix.tools.playwright import browser_observe
    from src.adaptix.tools.idor import idor_test
    from src.adaptix.tools.discovery import api_discover, build_scenario
    from src.adaptix.tools.web import web_discover, http_request
    from src.adaptix.tools.playwright import browser_test
    from src.adaptix.tools.static_discovery import static_discovery
    from src.adaptix.tools.vuln_probes import (authorization_probe, injection_probe,
                                              script_probe)
    from src.adaptix.tools.union_extract import union_extract
    return {'httpx': httpx_probe, 'nuclei': nuclei_check,
            'playwright': browser_observe, 'browser_test': browser_test, 'idor': idor_test, 'api_discover': api_discover,
            'scenario': build_scenario, 'web_discover': web_discover, 'http_request': http_request,
            'static_discovery': static_discovery, 'authorization_probe': authorization_probe,
            'injection_probe': injection_probe, 'script_probe': script_probe,
            'union_extract': union_extract}
