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
    for name in ('web_discover', 'http_request', 'browser_test'):
        result[name] = {'enabled': True, 'path': 'python-module', 'detail': 'in-process scope-pinned HTTP adapter',
                        'version': ''}
    descriptions = {'nmap': 'Discover services on one pinned host', 'httpx': 'Observe one HTTP endpoint',
                    'nuclei': 'Run configured Nuclei templates. Adaptive mode uses observed Nmap products/HTTPX technologies to select HTTP template tags; unknown products use native automatic detection. HTTPX first can improve selection. Matches are unverified.',
                    'playwright': 'Observe browser page and capture screenshot without form submission',
                    'browser_test': 'Navigate one in-scope URL carrying a run marker in its query in a read-only browser session, then a control navigation without the marker; captured and dismissed dialogs on the payload navigation but never from the control are the deterministic browser-execution proof for XSS candidates. Nothing is clicked or submitted.',
                    'web_discover': 'Passive reconnaissance: GET one seed document plus robots.txt and sitemap.xml, then extract in-scope links, forms, scripts and documented routes into web_routes.',
                    'http_request': 'Send one bounded, rate-limited HTTP request to an in-scope URL. Method GET/HEAD is non-destructive; POST/PUT/PATCH/DELETE require exact human approval. The response is reduced to a structured trace with deterministic signatures (SQL/NoSQL errors, reflected markup, traversal markers, sensitive data); a signature is not proof by itself.'}
    for name, description in descriptions.items():
        result[name]['description'] = description
    result['idor'] = {'enabled': True, 'path': 'python-module', 'detail': 'two-identity configured scenario; GET only',
                      'description': 'Execute a named configured scenario once: GET owner and other identity, compare responses and verify against private-object ground truth. Results and verification are already in idor_findings; evaluate them in reflection, never call this tool again to evaluate its existing result.'}
    result['api_discover'] = {'enabled': True, 'path': 'python-module',
        'description': 'GET one observed API endpoint or listed document probe, parse OpenAPI GET routes and actual collection records. No schema examples as object data.'}
    result['scenario'] = {'enabled': True, 'path': 'python-module',
        'description': 'Build a scenario from a listed scenario_candidates name. Three GET requests validate two supplied sessions and owner private content; requires identity context. Produces an idor_scenarios name for the idor tool.'}
    for name, spec in result.items():
        spec['risk'] = 'template_dependent' if name == 'nuclei' else 'observe'
        spec['operation'] = 'authorization_test_get' if name == 'idor' else 'observe'
    return result


def run_tool(argv, timeout=45, stdin=None, stderr_limit=2500,
             request_budget=None, request_rate=None, request_concurrency=1):
    """No shell interpolation; prevent unbounded output and hanging processes."""
    if request_budget is not None:
        return _run_request_bounded_tool(argv, timeout, stdin, stderr_limit,
                                         request_budget, request_rate, request_concurrency)
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



def _run_request_bounded_tool(argv, timeout, stdin, stderr_limit, budget, rate, concurrency):
    """Actively stop Nuclei as request telemetry approaches the operator ceiling.

    The engine exposes sampled, not per-request, counters. In addition to the
    sampled-counter guard, use an earlier wall-clock envelope derived from -rl
    and concurrency. This is a conservative stop mechanism, NOT a proof of an
    exact network-level count: an external egress gate would be needed for that.
    """
    import json
    import re
    import threading
    import time
    from collections import deque

    limit = int(budget)
    rate = max(1, int(rate or 1))
    concurrency = max(1, int(concurrency or 1))
    if limit <= 0:
        return {'returncode': -2, 'stdout': '', 'stderr': 'No positive Nuclei request budget',
                'request_guard_tripped': 'no_budget', 'requests_observed': None}

    # One stats interval, concurrent requests and a small extra cushion account
    # for requests between telemetry samples and the termination signal.
    reserve = concurrency + 2 * rate + 2
    threshold = max(1, limit - reserve)
    # Use process-start time, not the first stats sample, to fail conservatively.
    # Startup overhead only reduces scan coverage; it cannot enlarge permission.
    elapsed_guard = max(0.5, (limit - reserve) / rate)
    output = deque(maxlen=10000)
    errors = deque(maxlen=10000)
    counters = {'requests': None}
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, errors='replace')
    except OSError as exc:
        return {'returncode': -1, 'stdout': '', 'stderr': str(exc),
                'request_guard_tripped': 'launch_failed', 'requests_observed': None}

    def collect(stream, chunks, parse_stats=False):
        for line in iter(stream.readline, ''):
            chunks.append(line)
            if not parse_stats:
                continue
            count = None
            try:
                row = json.loads(line.strip())
                if isinstance(row, dict) and 'requests' in row:
                    count = int(row['requests'])
            except (ValueError, TypeError):
                match = re.search(r'Requests:\s*(\d+)/', line)
                if match:
                    count = int(match.group(1))
            if count is not None:
                previous = counters['requests']
                counters['requests'] = max(count, previous or 0)
        stream.close()

    stdout_thread = threading.Thread(target=collect, args=(process.stdout, output), daemon=True)
    stderr_thread = threading.Thread(target=collect, args=(process.stderr, errors, True), daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    if stdin:
        try:
            process.stdin.write(stdin)
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
    process.stdin.close()
    began = time.monotonic()
    tripped = None
    while process.poll() is None:
        elapsed = time.monotonic() - began
        if counters['requests'] is not None and counters['requests'] >= threshold:
            tripped = 'telemetry_guard'
            break
        if elapsed >= elapsed_guard:
            tripped = 'rate_window_guard'
            break
        if elapsed >= timeout:
            tripped = 'timeout'
            break
        time.sleep(0.05)
    if tripped:
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    stdout_thread.join(timeout=2)
    stderr_thread.join(timeout=2)
    observed = counters['requests']
    if observed is not None and observed > limit:
        tripped = 'ceiling_exceeded'
    return {'returncode': -2 if tripped else process.returncode,
            'stdout': ''.join(output)[:1_000_000],
            'stderr': ''.join(errors)[-stderr_limit:],
            'request_guard_tripped': tripped,
            'requests_observed': observed}


def tool_handlers():
    """Capability adapters; adding tools does not change the graph topology."""
    from src.adaptix.tools.nmap import reconnaissance
    from src.adaptix.tools.httpx import httpx_probe
    from src.adaptix.tools.nuclei import nuclei_check
    from src.adaptix.tools.playwright import browser_observe
    from src.adaptix.tools.idor import idor_test
    from src.adaptix.tools.discovery import api_discover, build_scenario
    from src.adaptix.tools.web import web_discover, http_request
    from src.adaptix.tools.playwright import browser_test
    return {'nmap': reconnaissance, 'httpx': httpx_probe, 'nuclei': nuclei_check,
            'playwright': browser_observe, 'browser_test': browser_test, 'idor': idor_test, 'api_discover': api_discover,
            'scenario': build_scenario, 'web_discover': web_discover, 'http_request': http_request}
