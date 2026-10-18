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
from urllib.parse import parse_qsl, unquote_plus, urljoin, urlsplit

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


def _request(state, url, method='GET', body=None):
    if not permitted(state, url):
        raise ValueError('Endpoint outside pinned scope')
    if not tool_budget_available(state):
        raise ValueError('Request budget exhausted')
    limits = config('scope.yaml')['limits']
    with slot():
        throttle()
        state['execution_metrics'] = record_tool_call(state, 'http_request')
        actual, host_headers, sni = bind_url(url, state)
        timeout = tool_timeout(state, min(int(limits.get('timeout_seconds', 45)), 30))
        body_limit = int(state.get('response_body_limit', MAX_BODY))
        with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client:
            with client.stream(method, actual, headers=host_headers,
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
    """GET one seed document plus robots.txt/sitemap.xml, then mine referenced JS bundles."""
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
        remaining = int(state.get('tool_call_budget', 20)) - int(working.get('execution_metrics', {}).get('tool_calls_used', 0))
        if remaining <= 2 or not tool_budget_available({**state, 'execution_metrics': working.get('execution_metrics', {})}):
            break
        try:
            response = _request(working, bundle)
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f'Web Discover {bundle}: {type(exc).__name__}')
            continue
        secrets = scenario_secrets(state)
        path = artifact_path(state, 'web-bundle', bundle, 'js')
        save_text(path, sanitize(response.text[:SCRIPT_BUNDLE_LIMIT], secrets))
        raw_bytes += len(response.content)
        routes.extend(_extract_script_routes(state, bundle, response, str(path), secrets))
    routes = _dedupe(routes, lambda row: (endpoint_key(row['url']), row['method'], row['kind']))
    return {'web_routes': routes, 'discovered_documents': probed,
            'execution_metrics': working.get('execution_metrics', state.get('execution_metrics', {})),
            'raw_bytes': raw_bytes, 'errors': errors,
            'events': log(state, f'Web Discover: {len(routes)} in-scope routes from {completed} documents')}


def _payload_candidates(url):
    parsed = urlsplit(url)
    values = []
    for _, value in parse_qsl(parsed.query, keep_blank_values=True):
        values.append(value)
        values.append(unquote_plus(value))
    return list(dict.fromkeys(value for value in values if value))


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
    if not permitted(state, url):
        return {'errors': errors + ['HTTP Request: endpoint outside pinned scope'],
                'events': log(state, 'HTTP Request: rejected out-of-scope endpoint')}
    started = time.monotonic()
    try:
        response = _request(working, url, method, body)
    except (httpx.HTTPError, ValueError) as exc:
        return {'execution_metrics': working.get('execution_metrics', state.get('execution_metrics', {})),
                'errors': errors + [f'HTTP Request {method}: {type(exc).__name__}'],
                'events': log(state, 'HTTP Request: failed before any evidence was recorded')}
    seconds = round(time.monotonic() - started, 4)
    secrets = scenario_secrets(state)
    record = response_record(response, secrets)
    parsed = urlsplit(url)
    payloads = _payload_candidates(url)
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
    trace = {'url': sanitize(url), 'path_key': path_key(url), 'method': method,
             'parameter': ','.join(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))[:256],
             'payload': sanitize('&'.join(payloads))[:512], 'control': control,
             'status_code': response.status_code, 'content_type': content_type[:120],
             'body_sha256': record['body_sha256'], 'body_length': len(response.content),
             'body_excerpt': record['body_excerpt'][:2048],
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
    return {'probe_traces': traces, 'request_audit': audit,
            'execution_metrics': working.get('execution_metrics', state.get('execution_metrics', {})),
            'raw_bytes': int(state.get('raw_bytes', 0)) + len(response.content), 'errors': errors,
            'events': log(state, f'HTTP Request: {method} {response.status_code}, {len(detected)} signatures')}
