"""Scope-pinned static content discovery (ffuf) as an executable capability.

The adaptive graph previously had no way to *find* content: `web_discover` reads
links/forms/scripts that a served document already references, and `api_discover`
reads a document the application already advertised. Nothing could answer "which
paths exist that this application never links to?" - the directory/file layer where
backups, admin panels, API version prefixes, `.git`, actuator endpoints and upload
directories actually live. That is why runs on a deliberately vulnerable lab filled
their budget with parameterless fetches of `/` and never reached the vulnerable
routes.

This adapter performs exactly that one bounded job:

* it runs ffuf against one authorized origin with an operator-selected wordlist,
  always scope-pinned through the same `permitted()` predicate every other adapter
  uses, never following redirects out of scope;
* it converts matches into `web_routes` rows with explicit provenance
  (`kind='ffuf_discovery'`) so the planner can see them as observed endpoints;
* a discovered route is *evidence that a path answered*, never a finding.

Deliberate non-goals: no recursive brute force by default, no credential attack, no
body/parameter fuzzing. Parameter and value fuzzing belongs to `http_request`, where
each probe produces a comparable, signed trace.
"""
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit
import uuid

from src.adaptix.config import ROOT, config
from src.adaptix.evidence.storage import artifact_path, save_text
from src.adaptix.security.scope import endpoint_key, allowed_url
from src.adaptix.security.ports import ports_for_state
from src.adaptix.workflow.budget import record_tool_call, tool_budget_available, tool_timeout
from src.adaptix.workflow.events import log

# Bundled discovery wordlists, checked in beside the project and verified by hash.
WORDLIST_DIR = ROOT / 'work' / 'wordlists' / 'discovery'
# Named profiles the operator (and the model) may request. Each is a file plus the
# extension set it is meaningful for; nothing here is generated at runtime.
PROFILES = {
    'quick': {'file': 'quick.txt', 'extensions': '',
              'desc': 'curated high-signal names; fits the default time cap'},
    'common': {'file': 'common.txt', 'extensions': '', 'desc': 'generic directory/file names'},
    'raft-small-dirs': {'file': 'raft-small-directories.txt', 'extensions': '',
                        'desc': 'recursive directory names'},
    'api': {'file': 'api-endpoints.txt', 'extensions': '',
            'desc': 'API path prefixes and operations'},
    'backup': {'file': 'backup-files.txt', 'extensions': '',
               'desc': 'backup/archive/config leftovers'},
}
DEFAULT_PROFILE = 'quick'
MAX_WORDLIST_ENTRIES = 60_000
DEFAULT_MAX_BYTES = 30_000_000
# Status codes that indicate a real, distinct response for discovery purposes.
MATCH_CODES = '200,204,206,301,302,303,307,308,401,403,405,500'
# Paths whose discovery is a state-changing effect, not a read.
_DESTRUCTIVE = re.compile(r'/(?:logout|logoutall|reset|delete|destroy|drop|wipe|purge|shutdown)(?:/|$)', re.I)


def permitted(state, url):
    return allowed_url(url, state.get('hosts', []),
                       set(ports_for_state(state, config('scope.yaml')['limits'])),
                       state.get('scope_aliases'), state.get('scope_networks'))


def _origin(url):
    parsed = urlsplit(url)
    return f'{parsed.scheme}://{parsed.netloc}'


def _reachable(origin, timeout=2.0):
    """Cheap preflight: is anything actually answering on this origin?

    Without it, a sweep against an origin that is down (or a unit test's synthetic
    URL) spends its whole wall-clock budget in connection timeouts instead of
    recording a limitation and letting the run continue.
    """
    import socket
    parsed = urlsplit(origin)
    host = parsed.hostname
    if not host:
        return False
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _canary_probe(origin, prefix, token, timeout=4):
    """Fetch one path that cannot exist, to learn what "not found" looks like here.

    Applications routinely answer unknown paths with something other than 404: a
    SPA shell (200, constant length), a custom 500 error page, or a redirect to
    login. Fuzzing those without calibrating produces a route inventory full of
    paths that do not exist, and every later test spends its budget on them. That
    is a concrete reason a lab full of real bugs yields zero findings.
    """
    import urllib.error
    import urllib.request
    path = f'{prefix}/adaptix-canary-{token}'
    url = f'{origin}{path}'
    request = urllib.request.Request(url, method='GET', headers={'User-Agent': 'adaptix-discovery/1'})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(65_536)
            return {'status': response.status, 'length': len(body), 'body': body,
                    'url': url, 'path': path, 'token': token, 'prefix': prefix}
    except urllib.error.HTTPError as exc:
        body = exc.read(65_536) or b''
        return {'status': exc.code, 'length': len(body), 'body': body,
                'url': url, 'path': path, 'token': token, 'prefix': prefix}
    except Exception:
        return None


def _error_signature(probe):
    """Turn a canary response into a signature that recognises its siblings.

    Many error templates are a fixed skeleton wrapped around the requested path,
    so their body length is exactly ``base + len(path)``. Recording ``base`` lets
    every later row be checked arithmetically instead of by fuzzy heuristics -
    which matters because a page that merely echoes the path differs in length
    for every word in the wordlist and would otherwise never be filtered.
    """
    if not probe or not probe.get('body'):
        return {'status': probe.get('status') if probe else None, 'base': None,
                'length': probe.get('length') if probe else None, 'prefix': None}
    text = probe['body'].decode('utf-8', 'replace')
    path = probe['path']
    # Error templates commonly echo the path twice (page title and body heading).
    # Each echo contributes exactly len(path), so the skeleton is the remainder:
    # length == base + echoes * len(path). Verified against several path lengths.
    echoes = text.count(path)
    base = probe['length'] - echoes * len(path) if echoes else None
    return {'status': probe.get('status'), 'base': base, 'echoes': echoes,
            'length': probe['length'], 'prefix': probe['prefix'], 'path': path}


def _calibrate(origin, prefix, timeout=8):
    """One canary per distinct parent prefix; new prefixes inherit the root one."""
    return _error_signature(_canary_probe(origin, prefix, uuid.uuid4().hex[:12], timeout))


def _is_canary_echo(row, calibration):
    """True when a ffuf row is the calibrated error page, not a real path.

    ``length == base + len(path)`` is exact for skeletons that echo the path, and
    a plain equal-length match is exact for constant soft-404s.
    """
    status = row.get('status')
    length = row.get('length')
    if not isinstance(length, int):
        return False
    path = row.get('_path') or ''
    for sig in calibration:
        if not sig or sig.get('status') != status:
            continue
        if sig.get('base') is not None:
            echoes = sig.get('echoes') or 1
            if length == sig['base'] + echoes * len(path):
                return True
        elif sig.get('length') == length:
            return True
    return False


def _valid_wordlist(profile, explicit_entry):
    """A wordlist is valid when it is a readable file of sane size and content.

    Only a *relative* explicit entry is resolved inside the project, so an operator
    `--wordlist` cannot be turned into an arbitrary read by a model-authored value.
    """
    if explicit_entry is not None:
        candidate = Path(explicit_entry)
        if not candidate.is_absolute():
            candidate = (ROOT / candidate).resolve()
        if not candidate.is_relative_to(ROOT.resolve()):
            raise ValueError('wordlist outside the project tree')
    else:
        # The profile the caller asked for decides the file; falling back to the
        # default here would silently run 'common' for every sweep.
        candidate = WORDLIST_DIR / PROFILES[profile]['file']
    if not candidate.is_file():
        raise ValueError(f'wordlist not found: {candidate.name}')
    if candidate.stat().st_size > DEFAULT_MAX_BYTES:
        raise ValueError('wordlist exceeds the configured size bound')
    return candidate


def _wordlist(path, limit=MAX_WORDLIST_ENTRIES):
    raw = path.read_bytes()
    words = [line.strip() for line in raw.decode('utf-8', 'replace').splitlines() if line.strip()]
    return words[:limit], len(words)


def _ffuf_binary():
    override = os.environ.get('ADAPTIX_FFUF_PATH', '').strip()
    if override:
        return override if Path(override).is_file() and os.access(override, os.X_OK) else None
    return shutil.which('ffuf')


def static_discovery(state):
    """Run one bounded ffuf pass over one authorized origin and record the routes."""
    action = (state.get('planned_actions') or [{}])[0]
    target = str(action.get('target') or '')
    if '://' not in target:
        return {'errors': list(state.get('errors', [])) + ['Static Discovery: target must be an absolute URL'],
                'events': log(state, 'Static Discovery: rejected non-absolute target')}
    if not permitted(state, target):
        return {'errors': list(state.get('errors', [])) + ['Static Discovery: endpoint outside pinned scope'],
                'events': log(state, 'Static Discovery: rejected out-of-scope origin')}
    if not tool_budget_available(state):
        return {'events': log(state, 'Static Discovery: skipped, tool-call budget exhausted')}
    executable = _ffuf_binary()
    if not executable:
        return {'errors': list(state.get('errors', [])) + ['Static Discovery: ffuf binary unavailable'],
                'discovery_limitations': list(state.get('discovery_limitations', [])) + [
                    {'url': target, 'reason': 'ffuf_unavailable'}],
                'events': log(state, 'Static Discovery: ffuf missing')}
    if not _reachable(_origin(target)):
        # Recorded as a limitation rather than an error: an unreachable origin is a
        # fact about the target, and the run continues with the other phases.
        return {'discovery_limitations': list(state.get('discovery_limitations', [])) + [
                    {'url': target, 'reason': 'origin_unreachable'}],
                'static_discovery': {'profile': str(action.get('profile') or DEFAULT_PROFILE),
                                     'skipped': 'origin_unreachable'},
                'events': log(state, 'Static Discovery: skipped, origin unreachable')}

    profile = str(action.get('profile') or DEFAULT_PROFILE)
    if profile not in PROFILES:
        profile = DEFAULT_PROFILE
    try:
        wordlist_path = _valid_wordlist(profile, state.get('recon_wordlist'))
    except (OSError, ValueError) as exc:
        return {'errors': list(state.get('errors', [])) + [f'Static Discovery: {exc}'],
                'events': log(state, 'Static Discovery: invalid wordlist')}
    words, total_words = _wordlist(wordlist_path)
    if not words:
        return {'errors': list(state.get('errors', [])) + ['Static Discovery: wordlist is empty'],
                'events': log(state, 'Static Discovery: empty wordlist')}

    limits = config('scope.yaml')['limits']
    rate = max(1, int(limits.get('rate_per_second', 2)))
    max_seconds = int(config('baseline.yaml').get('static_discovery', {})
                      .get('max_seconds', 180) or 180)
    timeout = tool_timeout(state, max_seconds + 15)
    if timeout <= 1:
        return {'events': log(state, 'Static Discovery: skipped, no run time remaining')}
    # A sweep can only test what the operator's rate permits inside the cap. Sending
    # 4,750 words at 2 req/s into a 180s window silently returns the first ~360 and
    # looks like full coverage. Trim to what is affordable and record the trim.
    affordable = max(1, int(rate * max_seconds * 0.85))
    truncated = max(0, len(words) - affordable)
    if truncated:
        words = words[:affordable]

    # ffuf args come from constants and validated values only: the URL is pinned to
    # the authorized origin, the wordlist is a resolved project file, and no shell
    # is involved.
    runtime = artifact_path(state, 'ffuf-runtime', target, 'txt').parent
    input_path = artifact_path(state, 'ffuf-wordlist', target, 'txt')
    save_text(input_path, '\n'.join(words) + '\n')
    out_path = artifact_path(state, 'ffuf-results', target, 'json')
    config_path = runtime / f'ffufrc-{endpoint_key(target)[1]}-{endpoint_key(target)[2]}'
    config_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    config_path.write_text('', encoding='utf-8')

    argv = [executable, '-config', str(config_path),
            '-u', _origin(target) + '/FUZZ',
            '-w', str(input_path),
            '-of', 'json', '-o', str(out_path),
            '-mc', MATCH_CODES, '-fc', '404',
            '-t', '1', '-rate', str(rate), '-timeout', '5',
            '-maxtime', str(max_seconds), '-noninteractive', '-ac', '-s']
    if PROFILES[profile]['extensions']:
        argv.extend(['-e', PROFILES[profile]['extensions']])
    # Never inherit proxy/credential environment into the scanner process.
    env = {k: v for k, v in os.environ.items()
           if k.upper() in {'PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'HOME'}}
    env['XDG_CONFIG_HOME'] = str(runtime)
    started = time.monotonic()
    execution_metrics = record_tool_call(state, 'static_discovery')
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, errors='replace',
                                   timeout=timeout, env=env, shell=False, check=False)
        stdout, stderr, code = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode('utf-8', 'replace') if isinstance(exc.stdout, bytes) else (exc.stdout or '')
        stderr = exc.stderr.decode('utf-8', 'replace') if isinstance(exc.stderr, bytes) else (exc.stderr or '')
        code = -1
    except OSError as exc:
        return {'errors': list(state.get('errors', [])) + [f'Static Discovery: {type(exc).__name__}'],
                'events': log(state, 'Static Discovery: process failed to start')}

    errors = list(state.get('errors', []))
    if code != 0 and not out_path.exists():
        # A non-zero exit with retained JSONL is a partial run, not a fabricated
        # success; a non-zero exit with no output is a recorded limitation.
        return {'execution_metrics': execution_metrics,
                'errors': errors + [f'Static Discovery: ffuf exit {code}: {stderr.strip()[:160]}'],
                'discovery_limitations': list(state.get('discovery_limitations', [])) + [
                    {'url': target, 'reason': 'ffuf_failed'}],
                'events': log(state, 'Static Discovery: ffuf failed before producing results')}

    results = []
    try:
        payload = json.loads(out_path.read_text(encoding='utf-8-sig'))
        results = payload.get('results') or []
    except (OSError, ValueError):
        results = []

    origin = _origin(target)
    # Calibrate the "not found" shape for the root and for every parent prefix the
    # wordlist actually probes. ffuf's -ac only learns from the wordlist itself,
    # so on a target that answers 200-with-shell or 500-with-error-page it reports
    # hundreds of paths that do not exist - and the planner then spends its whole
    # budget testing them. That is a concrete reason a lab full of bugs scored zero.
    prefixes = [''] + sorted({('/' + '/'.join(w.split('/')[:1])).rstrip('/')
                              for w in words if '/' in w})
    calibration, calibration_cost = [], 0
    for prefix in prefixes[:8]:
        sig = _calibrate(origin, prefix)
        calibration_cost += 1
        if sig:
            calibration.append(sig)
    routes, rejected, soft_404 = [], 0, 0
    for row in results[:1000]:
        if not isinstance(row, dict):
            continue
        url = str(row.get('url') or '')
        # ffuf reports the URL it requested; re-check scope here instead of trusting it.
        if not url.startswith(origin) or not permitted(state, url):
            rejected += 1
            continue
        path = urlsplit(url).path
        if _DESTRUCTIVE.search(path):
            rejected += 1
            continue
        row['_path'] = path
        if _is_canary_echo(row, calibration):
            soft_404 += 1
            continue
        routes.append({'url': url, 'method': str(row.get('method') or 'GET').upper(),
                       'kind': 'ffuf_discovery', 'source': str(out_path),
                       'status_code': int(row.get('status') or 0) or None,
                       'length': row.get('length'), 'words': row.get('words'),
                       'static_asset': False})
    save_text(artifact_path(state, 'ffuf-summary', target, 'json'), json.dumps(
        {'profile': profile, 'wordlist': wordlist_path.name, 'wordlist_entries': total_words,
         'tested': len(words), 'trimmed_by_rate_cap': truncated,
         'matches': len(routes), 'rejected_out_of_scope': rejected,
         'rejected_soft_404': soft_404,
         'exit_code': code, 'seconds': round(time.monotonic() - started, 3),
         'rate_per_second': rate, 'max_seconds': max_seconds,
         'calibration': {'signatures': [{k: v for k, v in sig.items() if k != 'path'}
                                        for sig in calibration],
                         'canaries': len(calibration)},
         'match_codes': MATCH_CODES}, indent=2))
    return {'execution_metrics': execution_metrics,
            'web_routes': list(state.get('web_routes', [])) + routes,
            'discovered_documents': list(state.get('discovered_documents', [])) + [out_path.name],
            'static_discovery': {'profile': profile, 'wordlist': wordlist_path.name,
                                 'tested': len(words), 'wordlist_entries': total_words,
                                 'trimmed_by_rate_cap': truncated,
                                 'matches': len(routes),
                                 'rejected_out_of_scope': rejected,
                                 'rejected_soft_404': soft_404,
                                 'exit_code': code, 'partial': bool(code != 0)},
            'static_profiles': sorted(set(state.get('static_profiles') or []) | {profile}),
            'static_swept': sorted(set(state.get('static_swept') or []) | {profile}),
            'errors': errors,
            'events': log(state, f'Static Discovery: {len(routes)} match(es) from {len(words)} '
                                 f'{profile} wordlist entries (exit {code})'
                                 + (f'; {truncated} entries beyond the rate cap not tested'
                                    if truncated else ''))}
