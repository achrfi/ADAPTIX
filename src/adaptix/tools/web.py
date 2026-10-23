"""Generic, scope-pinned web reconnaissance and bounded HTTP request probes.

These adapters extend ADAPTIX beyond IDOR-specific testing: they discover an
application's routes and let the model issue controlled, budgeted requests whose
responses are reduced to structured traces. They never return raw tool output to
the model and never follow redirects.
"""
import json
import hashlib
import re
import time
from urllib.parse import parse_qsl, unquote_plus, urljoin, urlencode, urlsplit

import httpx

from src.adaptix.config import config
from src.adaptix.evidence.http_response import decoded_response
from src.adaptix.evidence.sanitize import response_record, sanitize, scenario_secrets
from src.adaptix.evidence.storage import artifact_path, save_text
from src.adaptix.evidence.web_signatures import detect, is_probe_value
from src.adaptix.security.ports import ports_for_state
from src.adaptix.security.ratelimit import slot, throttle
from src.adaptix.security.scope import allowed_url, endpoint_key
from src.adaptix.security.transport import bind_url
from src.adaptix.workflow.budget import record_tool_call, tool_budget_available, tool_timeout
from src.adaptix.workflow.events import log

MAX_BODY = 1_000_000
DETECTION_LIMIT = 200_000
SAFE_METHODS = ('GET', 'HEAD')
MUTATING_METHODS = ('POST', 'PUT', 'PATCH', 'DELETE')
# Bound script fetches so one discovery action cannot exhaust the tool budget.
SCRIPT_FETCH_LIMIT = 4
SCRIPT_BUNDLE_LIMIT = 2_000_000
ROUTE_LIMIT = 200
_LINK = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", re.I)
_FORM = re.compile(r"""<form[^>]*action\s*=\s*["']([^"']*)["'][^>]*>""", re.I)
_SITEMAP_LOC = re.compile(r'<loc>\s*([^<\s]+)\s*</loc>', re.I)
_ROBOTS_LINE = re.compile(r'(?im)^\s*(?:allow|disallow|sitemap)\s*:\s*(\S+)')
# Quoted absolute-path literals in JavaScript bundles often name real routes.
# Query strings, template interpolations and encoded characters are allowed so
# client-constructed API calls still surface; values are stripped later.
_JS_PATH = re.compile(r"""["'`](/[A-Za-z0-9_\-./{}:~%$?=&@+]*)["'`]""")
# Client-side bundle/font/image/stylesheet extensions are references, not endpoints.
_ASSET = re.compile(r'\.(?:js|mjs|css|map|ico|png|jpe?g|gif|svg|webp|avif|bmp|woff2?|ttf|otf|eot|mp4|webm|ogg|wav|mp3|pdf|zip)(?:$|\?)', re.I)
_API_LIKE = re.compile(r'^/(?:api|rest|graphql|gql|v[0-9]+|rpc|services?|data)(?:/|$)', re.I)


def permitted(state, url):
    return allowed_url(url, state.get('hosts', []),
                       set(ports_for_state(state, config('scope.yaml')['limits'])),
                       state.get('scope_aliases'), state.get('scope_networks'))


def _origin(url):
    parsed = urlsplit(url)
    return f'{parsed.scheme}://{parsed.netloc}'


def path_key(url):
    parsed = urlsplit(url)
    return f'{parsed.scheme}://{parsed.netloc}{parsed.path}'


def seed_urls(state):
    action = next((a for a in state.get('planned_actions', []) if a.get('tool') == 'web_discover'), None)
    if action:
        return [action['target']]
    targets = state.get('target', [])
    targets = [targets] if isinstance(targets, str) else targets
    seeds = [value for value in targets if '://' in value]
    if seeds:
        return list(dict.fromkeys(seeds))
    for row in state.get('http_services', []) + state.get('browser_evidence', []):
        if row.get('url'):
            seeds.append(row['url'])
    return list(dict.fromkeys(seeds))[:1]


def _request(state, url, method='GET', body=None, identity_headers=None, extra_headers=None):
    if not permitted(state, url):
        raise ValueError('Endpoint outside pinned scope')
    if not tool_budget_available(state):
        raise ValueError('Request budget exhausted')
    limits = config('scope.yaml')['limits']
    with slot():
        throttle()
        state['execution_metrics'] = record_tool_call(state, 'http_request')
        actual, host_headers, sni = bind_url(url, state)
        headers = {**host_headers, **(identity_headers or {}), **(extra_headers or {})}
        timeout = tool_timeout(state, min(int(limits.get('timeout_seconds', 45)), 30))
        body_limit = int(state.get('response_body_limit', MAX_BODY))
        with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client:
            with client.stream(method, actual, headers=headers,
                               content=body.encode('utf-8') if body else None,
                               extensions={'sni_hostname': sni} if sni else {}) as response:
                data = bytearray()
                for chunk in response.iter_bytes():
                    data.extend(chunk)
                    if len(data) > body_limit:
                        raise ValueError('Response exceeds evidence limit')
                return decoded_response(response, data)


def _static_asset(url, kind):
    if kind in ('robots', 'sitemap', 'document', 'form', 'script_route'):
        return False
    return bool(_ASSET.search(urlsplit(url).path))


def is_static_asset(url, kind='link'):
    """Reference assets (bundles, fonts, images) are not application endpoints."""
    return _static_asset(url, kind)


def is_api_like(url_or_path):
    """True for conventional application/API prefixes; a hint, never a filter."""
    path = urlsplit(url_or_path).path if '://' in str(url_or_path) else str(url_or_path)
    return bool(_API_LIKE.search(path))


def route_row(state, url, method, kind, source, status_code=None):
    """Build one deduplicated, scope-pinned route record shared by all discovery paths."""
    if not permitted(state, url):
        return None
    row = {'url': url, 'method': str(method).upper(), 'kind': kind, 'source': source,
           'status_code': status_code, 'static_asset': _static_asset(url, kind)}
    if kind in ('script_route', 'xhr', 'fetch', 'api'):
        row['api_like'] = is_api_like(url)
    return row


def _route(state, url, method, kind, source, status_code=None):
    return route_row(state, url, method, kind, source, status_code)


def _extract_routes(state, url, response, source, secrets):
    routes = []
    kind = 'link'
    text = sanitize(response.text, secrets)
    for match in _LINK.findall(text):
        target = urljoin(url, match)
        route = _route(state, target, 'GET', 'script' if match.lower().split('?')[0].endswith('.js') else 'link', source)
        if route:
            routes.append(route)
    for match in _FORM.findall(text):
        target = urljoin(url, match) if match else url
        route = _route(state, target, 'POST', 'form', source)
        if route:
            routes.append(route)
    if urlsplit(url).path.rstrip('/').endswith('robots.txt') or _ROBOTS_LINE.search(text):
        for match in _ROBOTS_LINE.findall(text):
            target = urljoin(url, match)
            if '://' not in target:
                target = urljoin(_origin(url) + '/', match)
            route = _route(state, target, 'GET', 'robots', source, response.status_code)
            if route:
                routes.append(route)
    for match in _SITEMAP_LOC.findall(text):
        route = _route(state, match, 'GET', 'sitemap', source, response.status_code)
        if route:
            routes.append(route)
    if urlsplit(url).path.rstrip('/').endswith('/') or kind:
        root = _route(state, url, 'GET', 'document', source, response.status_code)
        if root:
            routes.append(root)
    return routes


def _script_targets(routes):
    """Same-document script bundles that may carry client-side route literals."""
    targets = []
    for row in routes:
        if row.get('kind') == 'script' and row.get('url') not in targets:
            targets.append(row['url'])
    return targets


# Generic library/framework bundle names carry few application route literals.
_VENDOR_HINT = re.compile(r'(?:vendor|polyfill|runtime|chunk[-_]|common|framework|react|angular|vue|jquery|bootstrap|moment|lodash|underscore)', re.I)


def _bundle_priority(url):
    name = urlsplit(url).path.rsplit('/', 1)[-1]
    return (bool(_VENDOR_HINT.search(name)), name)


def normalize_script_path(raw):
    """Reduce a JS path literal to a routable endpoint with parameter names only.

    Client bundles build URLs like ``/rest/products/search?q=${term}`` or
    ``/api/Users/{id}``. The path stays, template/query values are dropped so the
    resulting endpoint can be probed without inventing identifiers.
    """
    raw = str(raw or '').strip()
    if len(raw) < 3 or '://' in raw or raw.startswith('//') or '..' in raw:
        return None
    path, _, query = raw.partition('?')
    path = path.split('#', 1)[0]
    path = re.sub(r'\$\{[^}]*\}', 'placeholder', path)
    path = re.sub(r'\{[^{}]+\}', 'placeholder', path)
    if not re.fullmatch(r'/[A-Za-z0-9_\-./~%]+', path):
        return None
    if _ASSET.search(path):
        return None
    params = [name for name, _ in parse_qsl(query.split('#', 1)[0], keep_blank_values=True) if name]
    endpoint = path + (('?' + '&'.join(f'{name}=' for name in dict.fromkeys(params))) if params else '')
    return endpoint


def _extract_script_routes(state, bundle_url, response, source, secrets):
    text = sanitize(response.text[:SCRIPT_BUNDLE_LIMIT], secrets)
    routes = []
    for match in _JS_PATH.findall(text):
        endpoint = normalize_script_path(match)
        if not endpoint:
            continue
        path = endpoint.split('?', 1)[0]
        if not _API_LIKE.search(path) and path.count('/') < 2:
            continue
        target = urljoin(_origin(bundle_url) + '/', endpoint)
        route = _route(state, target, 'GET', 'script_route', source)
        if route:
            routes.append(route)
        if len(routes) >= ROUTE_LIMIT:
            break
    return routes


def document_probes(state, seed):
    """Seed document plus the conventional machine-readable index documents."""
    probes = [seed]
    root = _origin(seed)
    for path in ('robots.txt', 'sitemap.xml'):
        candidate = urljoin(root + '/', path)
        if permitted(state, candidate) and candidate not in probes:
            probes.append(candidate)
    return probes


def _dedupe(items, key):
    unique = {}
    for item in items:
        if isinstance(item, dict):
            unique[key(item)] = item
    return list(unique.values())


def web_discover(state):
    """GET one seed document plus robots.txt/sitemap.xml, then mine referenced JS bundles.

    The seed response's own headers and body also yield deterministic technology
    fingerprints (`http_services` entries carry `tech`/`webserver` with
    `technology_source: 'response_signatures'`):  honest observations the target
    emitted, feeding evidence-driven Nuclei template selection. Nothing is
    synthesized and no match is ever promoted from a technology label.
    """
    seeds = seed_urls(state)
    if not seeds:
        return {'events': log(state, 'Web Discover: skipped; no in-scope seed URL')}
    working = dict(state)
    errors = list(state.get('errors', []))
    routes = list(state.get('web_routes', []))
    raw_bytes = int(state.get('raw_bytes', 0))
    base = seeds[0]
    probes = document_probes(state, base)
    completed = 0
    probed = list(state.get('discovered_documents', []))
    scripts = []
    tech_labels, tech_markers = {}, set()
    from src.adaptix.evidence.web_signatures import detect_technologies

    for probe in probes:
        if not tool_budget_available({**state, 'execution_metrics': working.get('execution_metrics', {})}):
            errors.append('Web Discover: tool-call budget exhausted')
            break
        try:
            response = _request(working, probe)
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f'Web Discover {probe}: {type(exc).__name__}')
            continue
        completed += 1
        if probe not in probed:
            probed.append(probe)
        raw_labels, markers = detect_technologies(
            response.text[:DETECTION_LIMIT], getattr(response, 'headers', {}))
        # First-seen field wins; a later document never overwrites the seed's
        # observed header with a different document's value.
        for field, value in raw_labels.items():
            tech_labels.setdefault(field, value)
        tech_markers.update(markers)
        secrets = scenario_secrets(state)
        path = artifact_path(state, 'web-discovery', probe, 'json')
        save_text(path, json.dumps({'url': sanitize(probe), **response_record(response, secrets)}, ensure_ascii=False))
        raw_bytes += len(response.content)
        discovered = _extract_routes(state, probe, response, str(path), secrets)
        routes.extend(discovered)
        scripts.extend(_script_targets(discovered))
    # Client-rendered applications hide their routes in bundles; fetch a few bounded bundles.
    # Application entry bundles are mined before generic framework/vendor chunks.
    # Bundle bodies are allowed up to the extraction cap (larger than a normal probe
    # response) so a single large application entry bundle is still mined once.
    working['response_body_limit'] = max(SCRIPT_BUNDLE_LIMIT, int(state.get('response_body_limit', MAX_BODY)))
    ordered_scripts = sorted(dict.fromkeys(scripts), key=_bundle_priority)
    for bundle in ordered_scripts[:SCRIPT_FETCH_LIMIT]:
        limit = state.get('tool_call_budget', 20)
        remaining = None if limit is None else limit - int(working.get('execution_metrics', {}).get('tool_calls_used', 0))
        if remaining is not None and (remaining <= 2 or not tool_budget_available({**state, 'execution_metrics': working.get('execution_metrics', {})})):
            break
        try:
            response = _request(working, bundle)
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f'Web Discover {bundle}: {type(exc).__name__}')
            continue
        raw_labels, markers = detect_technologies(
            response.text[:DETECTION_LIMIT], getattr(response, 'headers', {}))
        for field, value in raw_labels.items():
            tech_labels.setdefault(field, value)
        tech_markers.update(markers)
        secrets = scenario_secrets(state)
        path = artifact_path(state, 'web-bundle', bundle, 'js')
        save_text(path, sanitize(response.text[:SCRIPT_BUNDLE_LIMIT], secrets))
        raw_bytes += len(response.content)
        routes.extend(_extract_script_routes(state, bundle, response, str(path), secrets))
    routes = _dedupe(routes, lambda row: (endpoint_key(row['url']), row['method'], row['kind']))
    # Technology evidence rides on the response the seed served: verbatim header
    # product strings, generic framework markers observed in served HTML/JS, and
    # the raw server banner under `webserver`. Mapping to trusted Nuclei tags
    # happens in adaptive_profile - only products the configured map knows
    # become selection evidence; unmatched labels stay as honest observations.
    http_services = list(state.get('http_services', []))
    observed_labels = sorted({*tech_labels.values(), *tech_markers})
    services_updated = False
    for row in http_services:
        if endpoint_key(row.get('url', '')) == endpoint_key(base):
            src = row.get('tech')
            existing = ([value for value in src if isinstance(value, str)] if isinstance(src, list)
                        else [] if not isinstance(src, str) else [src])
            merged = sorted(set(existing) | set(observed_labels))
            if merged != existing or (tech_labels.get('server') and not row.get('webserver')):
                row = dict(row)
                row['tech'] = merged
                if tech_labels.get('server') and not row.get('webserver'):
                    row['webserver'] = tech_labels['server']
                row.setdefault('technology_source', 'response_signatures')
                http_services[http_services.index(next(r for r in http_services
                                                       if endpoint_key(r.get('url', '')) == endpoint_key(base)))] = row
                services_updated = True
            break
    else:
        if observed_labels:
            row = {'url': base, 'tech': observed_labels,
                   'webserver': tech_labels.get('server', ''),
                   'technology_source': 'response_signatures'}
            http_services.append(row)
            services_updated = True
    update = {'web_routes': routes, 'discovered_documents': probed,
              'execution_metrics': working.get('execution_metrics', state.get('execution_metrics', {})),
              'raw_bytes': raw_bytes, 'errors': errors,
              'events': log(state, f'Web Discover: {len(routes)} in-scope routes from {completed} documents'
                                    + (f'; {len(observed_labels)} technology signature(s)' if observed_labels else ''))}
    if services_updated:
        update['http_services'] = http_services
    return update


def _payload_candidates(url):
    parsed = urlsplit(url)
    values = []
    for _, value in parse_qsl(parsed.query, keep_blank_values=True):
        values.append(value)
        values.append(unquote_plus(value))
    return list(dict.fromkeys(value for value in values if value))


# Deterministic boolean-oracle companions: a truthy probe the model chose is
# re-issued (reproducibility) and paired with falsy/clean controls on the same
# parameter, so the recorded decision is a behavior difference the input caused,
# not an error string. GET-only companions: a state-changing request may never be
# replayed by deterministic machinery without its own exact human approval.
# Every truthy phrase has a deterministic falsy twin: or->and with a provably
# different right side (1->2, true->false), both swappable mechanically.
_BOOLEAN_ORACLE_PATTERNS = (
    re.compile(r'or\s+1\s*=\s*1\b', re.I),
    re.compile(r"or\s+['\"]1['\"]\s*=\s*['\"]1['\"]", re.I),
    re.compile(r"or\s+\(*\s*['\"]1['\"]\s*=\s*['\"]1['\"]?", re.I),
    re.compile(r'or\s+true\b', re.I),
)
_BOOLEAN_CLEAN = 'adaptix_control'


def _boolean_truthy(value):
    if not isinstance(value, str) or not value:
        return None
    match = next((pattern.search(value) for pattern in _BOOLEAN_ORACLE_PATTERNS
                  if pattern.search(value)), None)
    return match


def _truthy_token(value):
    match = _boolean_truthy(value)
    return match.group(0) if match else None


def _swap_param(url, name, value):
    parsed = urlsplit(url)
    pairs = [(key, value if key == name else current)
             for key, current in parse_qsl(parsed.query, keep_blank_values=True)]
    return parsed._replace(query=urlencode(pairs)).geturl()


def _falsy_token(value):
    """The falsy twin keeps the payload frame; only the oracle predicate flips."""
    match = _boolean_truthy(value)
    if not match:
        return None
    fragment = value[match.start():match.end()]
    falsy = re.sub(r'\bor\b', 'and', fragment, count=1, flags=re.I)
    falsy = re.sub(r'=\s*[\'"]1[\'"]?', lambda m: m.group(0).replace('1', '2'), falsy, count=1)
    falsy = re.sub(r'=\s*1\b', lambda m: m.group(0).replace('1', '2'), falsy, count=1)
    falsy = falsy.replace('true', 'false').replace('True', 'False').replace('TRUE', 'FALSE')
    return value[:match.start()] + falsy + value[match.end():]


def _boolean_companions(working, trace):
    """Issue bounded read-only companions for a truthy GET probe.

    Returns (companion responses, errors): [(kind, url, response_record, kind)]
    with kinds 'clean', 'falsy', 'repeat'. Any failure aborts companion issuance
    without inventing a response: missing data keeps the result inconclusive.
    """
    url = trace['url']
    method = trace.get('method') or 'GET'
    if method != 'GET' or trace.get('identity'):
        # Identity-scoped GETs exercise authorization state; companion replay is
        # out of scope for the boolean-oracle contract.
        return [], []
    probes = [(name, value) for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True)
              if _falsy_token(value)]
    if not probes:
        return [], []
    name = probes[0][0]
    falsy_value = _falsy_token(probes[0][1])
    companions, errors = [], []
    plans = [(_swap_param(url, name, falsy_value), 'falsy'),
             (_swap_param(url, name, _BOOLEAN_CLEAN), 'clean'),
             (url, 'repeat')]
    for companion_url, kind in plans:
        if not tool_budget_available(working) or not permitted(working, companion_url):
            errors.append('HTTP Request: boolean companion skipped (scope or budget)')
            break
        try:
            response = _request(working, companion_url, 'GET')
        except (httpx.HTTPError, ValueError) as exc:
            errors.append('HTTP Request: boolean companion failed: ' + type(exc).__name__)
            break
        companions.append((kind, companion_url, response_record(response, scenario_secrets(working))))
    return companions, errors


def _boolean_probe_verification(state, trace, companions, response_row):
    """Sign the boolean-oracle record for a reproduced truthy GET probe, or None.

    The model's own payload already produced the truthy observation; the
    deterministic companions prove the difference is the input: falsy and clean
    must behave identically, the repeated truthy response must be stable, and the
    truthy path must show no error signature (error signatures are the
    differential contract's evidence class).
    """
    from src.adaptix.evidence.verification import replay_result, CONTRACT_REQUIREMENTS, write_verification_record
    by_kind = {}
    for kind, companion_url, row in companions:
        by_kind.setdefault(kind, row)
    if not all(kind in by_kind for kind in ('falsy', 'clean', 'repeat')):
        return None
    method = trace.get('method') or 'GET'
    record = {
        'template_id': 'adaptix-boolean-' + (trace.get('request_fingerprint') or '')[:12],
        'url': trace['url'], 'method': method,
        'verification_method': 'deterministic_replay', 'verification_basis': 'boolean_injection',
        'requests': [
            {'method': method, 'url': trace['url'], 'identity': trace.get('identity')},
            {'method': method, 'url': trace['url'], 'identity': trace.get('identity')}],
        'responses': [
            {'status_code': trace['status_code'],
             'headers': {k: v for k, v in (response_row.get('headers') or {}).items()},
             'body_sha256': trace['body_sha256'], 'body_excerpt': trace.get('body_excerpt', ''),
             'body_truncated': bool(trace.get('excerpt_truncated'))},
            {'status_code': by_kind['repeat']['status_code'],
             'headers': dict(by_kind['repeat'].get('headers') or {}),
             'body_sha256': by_kind['repeat']['body_sha256'],
             'body_excerpt': (by_kind['repeat'].get('body_excerpt') or '')[:2048],
             'body_truncated': bool(by_kind['repeat'].get('body_truncated'))}],
        'boolean_oracle': {
            'truthy_sha256': [trace['body_sha256'], by_kind['repeat']['body_sha256']],
            'falsy_sha256': by_kind['falsy']['body_sha256'], 'clean_sha256': by_kind['clean']['body_sha256'],
            'statuses': {'truthy': [trace['status_code'], by_kind['repeat']['status_code']],
                         'falsy': by_kind['falsy']['status_code'], 'clean': by_kind['clean']['status_code']}},
        'controls': [{'url': companion_url, 'status_code': row['status_code'], 'control': True,
                      'detected': [], 'body_excerpt': (row.get('body_excerpt') or '')[:2048],
                      'excerpt_truncated': bool(row.get('body_truncated')), 'kind': kind}
                     for kind, companion_url, row in companions],
        'steps': ['Issue the recorded GET twice with the identical truthy payload (stability)',
                  'Compare against the deterministic falsy and clean companions on the identical parameter',
                  'Contract: ' + CONTRACT_REQUIREMENTS['boolean_injection']],
        'expected_behavior': 'The endpoint response is independent of the probe predicate',
        'actual_behavior': ('Truthy observation is stable and differs while falsy and clean match'
                           if trace['body_sha256'] == by_kind['repeat']['body_sha256']
                           else 'Truthy observations differ between repeats; the oracle is unstable'),
    }
    result = replay_result(record)
    if result is None:
        return None
    proof = write_verification_record(state, record)
    proof['signatures'] = ('boolean_oracle' if result == 'confirmed' else 'no_oracle_difference')
    return proof


def http_request(state):
    """Send one bounded request and reduce it to a structured, deterministic trace."""
    action = (state.get('planned_actions') or [{}])[0]
    url = action.get('target', '')
    method = str(action.get('method') or 'GET').upper()
    body = action.get('body')
    if method not in SAFE_METHODS + MUTATING_METHODS:
        return {'errors': list(state.get('errors', [])) + [f'HTTP Request: unsupported method {method}'],
                'events': log(state, 'HTTP Request: rejected unsupported method')}
    working = dict(state)
    errors = list(state.get('errors', []))
    # A model-authored relative path was resolved against the authorized origin at
    # approval time; tolerate an unresolved absolute or relative form defensively,
    # but never send anything the scope check does not approve.
    from src.adaptix.agents.capabilities import resolve_target
    url = url if '://' in url else (resolve_target(state, url) or '')
    if not url:
        return {'errors': errors + ['HTTP Request: target could not be resolved to an in-scope URL'],
                'events': log(state, 'HTTP Request: rejected unresolvable target')}
    if not permitted(state, url):
        return {'errors': errors + ['HTTP Request: endpoint outside pinned scope'],
                'events': log(state, 'HTTP Request: rejected out-of-scope endpoint')}
    # An acting identity is selected by name; its headers come verbatim from the
    # operator's identity_context, never from the model. Unknown names are refused
    # before any request, and identity never accompanies a state-changing request.
    identity_name = str(action.get('identity') or '').strip()
    identity_headers = {}
    if identity_name:
        if method not in SAFE_METHODS:
            return {'errors': errors + [f'HTTP Request: identity may not accompany a state-changing {method}'],
                    'events': log(state, 'HTTP Request: rejected identity on state-changing method')}
        identities = {row.get('name'): row
                      for row in (state.get('identity_context') or {}).get('identities', [])
                      if isinstance(row, dict) and row.get('name')}
        row = identities.get(identity_name)
        if row is None:
            return {'errors': errors + [f'HTTP Request: unknown identity {identity_name}'],
                    'events': log(state, f'HTTP Request: rejected unknown identity {identity_name}')}
        identity_headers = {str(k): str(v) for k, v in (row.get('headers') or {}).items()}
    # Model-authored headers are a chosen input location, not transport control:
    # their names/values were validated by the action schema; the runtime strips
    # any CR/LF defensively here too. The model never sets transport headers.
    model_headers = {}
    for name, value in ((action.get('headers') or {}).items()):
        model_headers[str(name).strip()] = str(value).replace('\r', ' ').replace('\n', ' ').strip()
    started = time.monotonic()
    # extra_headers is only forwarded when the model actually authored headers,
    # so the executor contract stays compatible with the identity-only path.
    try:
        if model_headers:
            response = _request(working, url, method, body, identity_headers=identity_headers,
                                extra_headers=model_headers)
        else:
            response = _request(working, url, method, body, identity_headers=identity_headers)
    except (httpx.HTTPError, ValueError) as exc:
        return {'execution_metrics': working.get('execution_metrics', state.get('execution_metrics', {})),
                'errors': errors + [f'HTTP Request {method}: {type(exc).__name__}'],
                'events': log(state, 'HTTP Request: failed before any evidence was recorded')}
    seconds = round(time.monotonic() - started, 4)
    secrets = scenario_secrets(state)
    record = response_record(response, secrets)
    parsed = urlsplit(url)
    payloads = _payload_candidates(url)
    # Probe scanning covers the sent request body too: a POST/PUT body value is as
    # attacker-controlled as a query value, so the same deterministic signatures
    # apply (body is fingerprinted, never echoed into evidence).
    body_members = []
    if isinstance(body, str):
        body_members = [body]
    elif isinstance(body, (dict, list)):
        body_members = [json.dumps(body, ensure_ascii=False)]
    payloads = list(dict.fromkeys(payloads + body_members))
    control = not any(is_probe_value(value) for value in payloads)
    content_type = response.headers.get('content-type', '')
    detected = detect(response.text[:DETECTION_LIMIT], content_type, payloads)
    path = artifact_path(state, 'probe', url + '#' + method, 'json')
    identity = str(action.get('identity') or '')[:120]
    request_body_sha256 = hashlib.sha256(body.encode('utf-8')).hexdigest() if body else None
    # Request identity: method + full URL (query included) + body + acting identity.
    fingerprint = hashlib.sha256(json.dumps(
        {'method': method, 'url': url, 'body': request_body_sha256, 'identity': identity},
        sort_keys=True, default=str).encode()).hexdigest()
    excerpt = record['body_excerpt'][:2048]
    # Whether the stored excerpt covers the whole response: an analysis that can only
    # see part of a control body must never conclude "no marker present" from it.
    excerpt_truncated = len(excerpt) < len(response.text)
    trace = {'url': sanitize(url), 'path_key': path_key(url), 'method': method,
             'parameter': ','.join(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))[:256],
             'payload': sanitize('&'.join(payloads))[:512], 'control': control,
             'status_code': response.status_code, 'content_type': content_type[:120],
             'body_sha256': record['body_sha256'], 'body_length': len(response.content),
             'body_excerpt': excerpt, 'excerpt_truncated': excerpt_truncated,
             'redirect_location': sanitize(response.headers.get('location', '')) or None,
             'identity': identity or None, 'request_body_sha256': request_body_sha256,
             'request_fingerprint': fingerprint,
             'detected': detected, 'seconds': seconds, 'timestamp': int(time.time()),
             'evidence_ref': str(path)}
    save_text(path, json.dumps({'request': {'method': method, 'url': sanitize(url),
                                            'body': sanitize(body or '')[:2048],
                                            'identity': identity},
                                **record, 'detected': detected}, ensure_ascii=False))
    from src.adaptix.processing.normalize import deduplicate
    traces = deduplicate('probe_traces', list(state.get('probe_traces', [])) + [trace])
    audit = deduplicate('request_audit', list(state.get('request_audit', [])) + [{
        'tool': 'http_request', 'method': method, 'path_key': path_key(url),
        'url': sanitize(url), 'parameter': trace['parameter'], 'payload': trace['payload'],
        'identity': identity or None, 'request_body_sha256': request_body_sha256,
        'request_fingerprint': fingerprint, 'status_code': response.status_code,
        'response_sha256': record['body_sha256'], 'response_bytes': len(response.content),
        'signatures': len(detected), 'seconds': seconds, 'timestamp': int(time.time()),
        'evidence_ref': str(path)}])
    # A detected signature is a hint until an objective contract over the stored trace
    # decides it. When contracts apply, sign a replayable record per contract-backed
    # category so each finding is verified from evidence, not from the scanner label
    # or the model's claim; a probe that trips two independent contracts proves both.
    verification = list(state.get('verification_evidence', []))
    if detected:
        from src.adaptix.evidence.verification import record_probe_verification, CATEGORY_BASIS
        controls = [{'detected': row.get('detected'), 'url': row.get('url'),
                     'status_code': row.get('status_code'), 'control': True,
                     'body_excerpt': row.get('body_excerpt', ''),
                     'excerpt_truncated': bool(row.get('excerpt_truncated')),
                     'content_type': row.get('content_type', '')}
                    for row in traces if row.get('control') and row.get('path_key') == trace['path_key']]
        # Deterministic clean control, generated by the verification engine when the
        # run has not observed one for this path yet: a response difference the
        # model's test value caused is only provable against a same-path read-only
        # control, and waiting for the model to think of one again wastes a pass.
        if any(CATEGORY_BASIS.get(d.get('category')) in ('differential_injection', 'path_traversal')
               for d in detected) and not controls and not trace.get('control') and method in SAFE_METHODS:
            control_url = url
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                control_url = _swap_param(control_url, name, _BOOLEAN_CLEAN)
            if parse_qsl(parsed.query, keep_blank_values=True) and tool_budget_available(working) and permitted(working, control_url):
                try:
                    control_response = _request(working, control_url, 'GET')
                except (httpx.HTTPError, ValueError) as control_exc:
                    errors.append('HTTP Request: control companion failed: ' + type(control_exc).__name__)
                else:
                    control_record = response_record(control_response, secrets)
                    control_path = artifact_path(state, 'probe', control_url + '#control', 'json')
                    control_trace = {
                        'url': sanitize(control_url), 'path_key': path_key(control_url), 'method': 'GET',
                        'parameter': ','.join(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))[:256],
                        'payload': sanitize(_BOOLEAN_CLEAN),                         'control': True, 'status_code': control_record['status_code'],
                        'content_type': control_response.headers.get('content-type', '')[:120],
                        'body_sha256': control_record['body_sha256'], 'body_length': len(control_response.content),
                        'body_excerpt': control_record['body_excerpt'], 'excerpt_truncated': False,
                        'redirect_location': sanitize(control_response.headers.get('location', '')) or None,
                        'identity': None, 'request_body_sha256': None,
                        'request_fingerprint': hashlib.sha256(json.dumps(
                            {'method': 'GET', 'url': control_url, 'body': None, 'identity': None},
                            sort_keys=True, default=str).encode()).hexdigest(),
                        'detected': [], 'seconds': None, 'timestamp': int(time.time()),
                        'evidence_ref': str(control_path)}
                    save_text(control_path, json.dumps({'request': {'method': 'GET', 'url': sanitize(control_url),
                                                                    'body': '', 'identity': None},
                                                        **control_record, 'detected': []}, ensure_ascii=False))
                    traces = deduplicate('probe_traces', traces + [control_trace])
                    controls = [{'detected': [], 'url': control_trace['url'], 'status_code': control_trace['status_code'],
                                 'control': True, 'body_excerpt': control_trace['body_excerpt'],
                                 'excerpt_truncated': bool(len(control_trace['body_excerpt']) < len(control_response.text)),
                                 'content_type': control_trace['content_type']}]
        by_category = {}
        for detection in detected:
            if CATEGORY_BASIS.get(detection.get('category')):
                by_category.setdefault(detection['category'], []).append(detection)
        for category, detections in sorted(by_category.items()):
            proof = record_probe_verification(
                state, 'adaptix-probe-' + fingerprint[:12] + '-' + category, sanitize(url), method,
                {'method': method, 'url': sanitize(url), 'identity': identity or None},
                record, detections, controls)
            if proof:
                verification.append(proof)
    # Boolean-oracle companions: no signature needed. When the model's GET probe
    # is a truthy SQL boolean payload, deterministic read-only companions decide
    # whether backend query behavior actually changed for that input.
    boolean_errors = []
    if not control and any(_truthy_token(value or '') for value in payloads):
        companions, boolean_errors = _boolean_companions(working, trace)
        boolean_proof = _boolean_probe_verification(state, trace, companions, record)
        if boolean_proof:
            verification.append(boolean_proof)
        companion_rows = [{'url': companion_url, 'kind': kind, 'status_code': row['status_code'],
                           'body_sha256': row['body_sha256']}
                          for kind, companion_url, row in companions]
    else:
        companion_rows = []
    return {'probe_traces': traces, 'request_audit': audit, 'verification_evidence': verification,
            'execution_metrics': working.get('execution_metrics', state.get('execution_metrics', {})),
            'raw_bytes': int(state.get('raw_bytes', 0)) + len(response.content),
            'boolean_companions': companion_rows,
            'errors': errors + boolean_errors,
            'events': log(state, f'HTTP Request: {method} {response.status_code}, {len(detected)} signatures')}
