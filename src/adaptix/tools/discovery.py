"""Read API evidence and construct authorization scenarios without model-authored fixtures."""
import hashlib
import json
import re
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import httpx

from src.adaptix.config import config
from src.adaptix.evidence.storage import artifact_path, save_text
from src.adaptix.evidence.sanitize import sanitize, response_record, scenario_secrets
from src.adaptix.security.scope import allowed_url, endpoint_key
from src.adaptix.security.ports import ports_for_state
from src.adaptix.security.transport import bind_url
from src.adaptix.workflow.budget import record_tool_call, tool_timeout, tool_budget_available

DOC_PATHS = ('/openapi.json', '/swagger.json', '/api/openapi.json', '/api-docs')


def origin(url):
    u = urlsplit(url)
    return urlunsplit((u.scheme, u.netloc, '', '', ''))


def permitted(state, url):
    return allowed_url(url, state.get('hosts', []), set(ports_for_state(state, config('scope.yaml')['limits'])),
                       state.get('scope_aliases'), state.get('scope_networks'))


def key(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:16]


def known_endpoints(state):
    targets = state.get('target', [])
    targets = [targets] if isinstance(targets, str) else targets
    urls = {u for u in targets if '://' in u}
    for u in list(urls):
        urls.add(origin(u) + '/')
    for row in state.get('services', []):
        if 'http' in row.get('service', '').lower():
            host = row['host']
            host = '[' + host + ']' if ':' in host else host
            urls.add(f'{"https" if row.get("tunnel") == "ssl" or row["port"] == 443 else "http"}://{host}:{row["port"]}/')
    for kind in ('http_services', 'browser_evidence', 'api_observations'):
        for row in state.get(kind, []):
            if row.get('url'):
                urls.add(row['url'])
            urls.update(row.get('links', []))
    urls.update(row['url'] for row in state.get('api_operations', []) if '{' not in row['url'])
    urls.update(row['url'] for row in state.get('scenario_candidates', []))
    return {u for u in urls if permitted(state, u)}


def discovery_targets(state):
    """Conventional document paths are labelled probes, never claimed observations."""
    urls = known_endpoints(state)
    values = urls | {origin(u) + p for u in urls for p in DOC_PATHS if permitted(state, origin(u) + p)}
    return sorted(values, key=lambda u: (not u.endswith('/openapi.json'), u))


def read_get(state, url, headers=None):
    if not permitted(state, url):
        raise ValueError('Endpoint outside pinned scope')
    if not tool_budget_available(state):
        raise ValueError('Request budget exhausted')
    state['execution_metrics'] = record_tool_call(state, 'api_discover')
    actual, host_headers, sni = bind_url(url, state)
    with httpx.Client(timeout=tool_timeout(state, 10), follow_redirects=False, trust_env=False) as client:
        # Stream and bound documents before parsing; never follow server redirects.
        with client.stream('GET', actual, headers={**(headers or {}), **host_headers},
                           extensions={'sni_hostname': sni} if sni else {}) as response:
            data = bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data) > 1_000_000:
                    raise ValueError('API document exceeds evidence limit')
            return httpx.Response(response.status_code, headers=response.headers, content=bytes(data), request=response.request)


def records(body):
    if isinstance(body, list):
        return [r for r in body if isinstance(r, dict)][:128]
    if isinstance(body, dict):
        found = [r for v in body.values() if isinstance(v, list) for r in v if isinstance(r, dict)]
        return found[:128] if found else [body]
    return []


def derive_candidates(state):
    """Join observed collection values with a documented single path parameter."""
    names = {i.get('name') for i in state.get('identity_context', {}).get('identities', [])}
    result = {}
    for op in state.get('api_operations', []):
        params = re.findall(r'\{([^{}]+)\}', op['url'])
        if op['method'] != 'GET' or len(params) != 1 or not op.get('authenticated'):
            continue
        param = params[0]
        # Only a direct documented collection/detail relationship; no guessed routes or IDs.
        collection = op['url'].split('/{' + param + '}')[0].rstrip('/')
        if op['url'] != collection + '/{' + param + '}':
            continue
        for observation in state.get('api_observations', []):
            if observation.get('status_code') != 200 or observation['url'].rstrip('/') != collection:
                continue
            for row in observation.get('records', []):
                object_id = row.get(param)
                owners = {str(row[k]) for k in ('owner', 'user', 'username', 'user_id') if k in row}
                matched = owners & names
                if isinstance(object_id, bool) or not isinstance(object_id, (str, int)) or len(matched) != 1:
                    continue
                url = op['url'].replace('{' + param + '}', quote(str(object_id), safe=''))
                if not permitted(state, url):
                    continue
                candidate = {'url': url, 'object_id': str(object_id), 'owner': matched.pop(),
                             'path_template': urlsplit(op['url']).path.replace('{' + param + '}', '{object_id}'),
                             'base_url': origin(url), 'source_refs': [op['source_ref'], observation['evidence_ref']],
                             'status': 'hypothesis', 'reason': 'Observed collection ownership and documented GET detail; privacy and sessions require validation'}
                candidate['name'] = 'observed-' + key(candidate)
                result[candidate['name']] = candidate
    return list(result.values())


def api_discover(state):
    url = state['planned_actions'][0]['target']
    if url not in discovery_targets(state) or re.search(r'/(?:createdb|reset|delete|logout|shutdown)(?:/|$)', urlsplit(url).path, re.I):
        raise ValueError('Unobserved endpoint; use a listed discovery target')
    working = dict(state)
    try:
        response = read_get(working, url)
        secrets = scenario_secrets(state)
        trace = response_record(response, secrets)
        path = artifact_path(state, 'api-observation', url, 'json')
        save_text(path, json.dumps({'url': sanitize(url), **trace}, ensure_ascii=False))
        row = {'url': url, 'status_code': response.status_code, 'evidence_ref': str(path), 'links': [], 'records': []}
        operations = list(state.get('api_operations', []))
        if response.is_success:
            try:
                body = response.json()
            except ValueError:
                body = None
            if isinstance(body, dict) and isinstance(body.get('paths'), dict) and ('openapi' in body or 'swagger' in body):
                # OpenAPI servers/basePath may point elsewhere. Resolve, then pin every URL.
                servers = body.get('servers') or []
                base = urljoin(url, servers[0].get('url', '/')) if servers else origin(url) + body.get('basePath', '')
                for route, methods in list(body['paths'].items())[:512]:
                    if not isinstance(route, str) or not route.startswith('/') or not isinstance(methods, dict):
                        continue
                    for method, spec in methods.items():
                        if method.lower() != 'get' or not isinstance(spec, dict):
                            continue
                        endpoint = base.rstrip('/') + route
                        probe = re.sub(r'\{[^{}]+\}', 'placeholder', endpoint)
                        if not permitted(state, probe):
                            continue
                        if re.search(r'/(?:createdb|reset|delete|logout|shutdown)(?:/|$)', route, re.I):
                            continue
                        operations.append({'url': endpoint, 'method': 'GET',
                            'authenticated': bool(spec.get('security', body.get('security', []))),
                            'summary': str(spec.get('summary', ''))[:160], 'source_ref': str(path)})
                row['document_kind'] = 'openapi'
            else:
                row['records'] = sanitize(records(body), secrets)
                # Links must appear in actual response data, never schema example values.
                if isinstance(body, (dict, list)):
                    def links(value):
                        if isinstance(value, dict):
                            for k, v in value.items():
                                if k.lower() in ('url', 'href', 'openapi', 'swagger', 'docs') and isinstance(v, str):
                                    yield urljoin(url, v)
                                elif isinstance(v, (dict, list)):
                                    yield from links(v)
                        elif isinstance(value, list):
                            for v in value:
                                yield from links(v)
                    row['links'] = [u for u in links(body) if permitted(state, u)][:64]
                elif body is None:
                    # Covers actual HTML links and Swagger UI's explicit document URL.
                    for match in re.findall(r'''(?:href\s*=|\burl\s*:)\s*["']([^"']+)["']''', response.text):
                        u = urljoin(url, match)
                        if permitted(state, u):
                            row['links'].append(u)
        observations = state.get('api_observations', []) + [row]
        operations = list({(o['url'], o['method']): o for o in operations}.values())
        collections = {o['url'].split('/{')[0] for o in operations if '{' in o['url'] and o['authenticated']}
        operations.sort(key=lambda o: (not (o['url'] in collections or ('{' in o['url'] and o['authenticated'])), o['url']))
        update = {'api_observations': observations, 'api_operations': operations,
                  'execution_metrics': working.get('execution_metrics', {}),
                  'raw_bytes': int(state.get('raw_bytes', 0)) + len(response.content)}
        update['scenario_candidates'] = derive_candidates({**state, **update})
        return update
    except (httpx.HTTPError, ValueError) as exc:
        return {'execution_metrics': working.get('execution_metrics', {}),
                'discovery_limitations': state.get('discovery_limitations', []) + [{'url': url, 'reason': type(exc).__name__}]}


def at_path(body, parts):
    for part in parts:
        if not isinstance(body, dict) or part not in body:
            return None
        body = body[part]
    return body


def build_scenario(state):
    """Validate two sessions and actual ownership/private content before making a fixture."""
    name = state['planned_actions'][0]['target']
    candidates = {c['name']: c for c in derive_candidates(state)}
    if name not in candidates:
        raise ValueError('Scenario candidate lacks observed provenance')
    candidate = candidates[name]
    context = state.get('identity_context', {})
    identities = context.get('identities', [])
    working = dict(state)
    traces = []
    reason = None
    try:
        if len(identities) != 2 or len({i['name'] for i in identities}) != 2:
            raise ValueError('Two distinct configured identities required')
        if not context.get('private_fields') or not context.get('identity_json_path'):
            raise ValueError('Explicit private-field policy and identity response path required')
        auth = [{k.lower(): v for k, v in i.get('headers', {}).items() if k.lower() in ('authorization', 'cookie', 'x-api-key')} for i in identities]
        if not all(auth) or auth[0] == auth[1]:
            raise ValueError('Distinct authenticated sessions required')
        check = context['identity_url']
        if origin(check) != origin(candidate['url']):
            raise ValueError('Identity endpoint must belong to the candidate origin')
        if int(working.get('execution_metrics', {}).get('tool_calls_used', 0)) + 3 > int(state.get('tool_call_budget', 20)):
            raise ValueError('Three validation requests must fit remaining budget')
        for identity in identities:
            r = read_get(working, check, identity['headers'])
            traces.append({'identity': identity['name'], 'url': check, **response_record(r, scenario_secrets(state))})
            if not r.is_success or at_path(r.json(), context['identity_json_path']) != identity['name']:
                raise ValueError('Session identity not validated; refresh credentials outside the planner')
        owner = next(i for i in identities if i['name'] == candidate['owner'])
        other = next(i for i in identities if i['name'] != owner['name'])
        r = read_get(working, candidate['url'], owner['headers'])
        traces.append({'identity': owner['name'], 'url': candidate['url'], **response_record(r, scenario_secrets(state))})
        body = r.json()
        if not r.is_success or not isinstance(body, dict) or body.get('owner', body.get('user')) != owner['name']:
            raise ValueError('Owner detail response does not establish observed ownership')
        if not all(field in body and body[field] not in (None, '', '[REDACTED]') for field in context['private_fields']):
            raise ValueError('Configured private fields not present in owner response')
        sc = {k: candidate[k] for k in ('name', 'base_url', 'path_template', 'object_id', 'source_refs')}
        sc.update(method='GET', owner_identity=owner, other_identity=other,
                  ground_truth={'private': True, 'identities_valid': True, 'owner': owner['name'],
                                'object_id': candidate['object_id'], 'basis': 'observed ownership, validated sessions and operator private-field policy'})
    except (ValueError, KeyError, StopIteration, TypeError, httpx.HTTPError) as exc:
        reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
    path = artifact_path(state, 'scenario-validation', name, 'json')
    save_text(path, json.dumps(sanitize({'candidate': candidate, 'validated': reason is None,
                'reason': reason, 'responses': traces}, scenario_secrets(state)), ensure_ascii=False))
    validations = state.get('scenario_validations', []) + [{'name': name, 'validated': reason is None,
                                                          'reason': reason, 'evidence_ref': str(path)}]
    update = {'execution_metrics': working.get('execution_metrics', {}), 'scenario_validations': validations}
    if reason is None:
        sc['source_refs'] = sc['source_refs'] + [str(path)]
        update['idor_scenarios'] = state.get('idor_scenarios', []) + [sc]
    else:
        update['policy_feedback'] = [{'action': {'tool': 'scenario', 'target': name}, 'reason': reason}]
    return update
