"""Read API evidence and construct authorization scenarios without model-authored fixtures."""
import hashlib
import json
import re
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import httpx

from src.adaptix.config import config
from src.adaptix.evidence.http_response import decoded_response
from src.adaptix.evidence.storage import artifact_path, save_text
from src.adaptix.evidence.sanitize import sanitize, response_record, scenario_secrets
from src.adaptix.agents.capabilities import (DOC_PATHS, document_probes, documentation_attempts,
                                            endpoint_provenance, is_destructive)
from src.adaptix.security.scope import allowed_url, endpoint_key
from src.adaptix.security.ports import ports_for_state
from src.adaptix.security.transport import bind_url
from src.adaptix.workflow.budget import record_tool_call, tool_timeout, tool_budget_available


def origin(url):
    u = urlsplit(url)
    return urlunsplit((u.scheme, u.netloc, '', '', ''))


def permitted(state, url):
    return allowed_url(url, state.get('hosts', []), set(ports_for_state(state, config('scope.yaml')['limits'])),
                       state.get('scope_aliases'), state.get('scope_networks'))


def key(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:16]


def known_endpoints(state):
    """Every in-scope endpoint this run has observed, with its provenance.

    Discovered references count. A route literal found in a JavaScript bundle is
    observed evidence that the application names the endpoint, which makes it
    eligible for a bounded request; it is not a claim that the endpoint answered.
    """
    provenance = endpoint_provenance(state)
    urls = set()
    for row in provenance.values():
        urls.update(row['urls'])
    return {u for u in urls if permitted(state, u)}


def validated_endpoints(state):
    """Endpoints for which an actual response was recorded."""
    provenance = endpoint_provenance(state)
    return {(row['urls'][0] if row['urls'] else '')
            for row in provenance.values() if row['validated'] and permitted(state, row['urls'][0])}


def discovery_targets(state):
    """Endpoints ``api_discover`` may fetch: every observed endpoint plus labelled probes.

    Conventional document paths are hypotheses, not observations; a probe that was
    already fetched and did not yield a usable document stays visible as a recorded
    limitation instead of silently disappearing or being fetched again.
    """
    values = known_endpoints(state) | set(document_probes(state))
    return sorted(values, key=lambda u: (not u.endswith(('/openapi.json', '/openapi.yaml')), u))


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
            return decoded_response(response, data)


def records(body):
    if isinstance(body, list):
        return [r for r in body if isinstance(r, dict)][:128]
    if isinstance(body, dict):
        found = [r for v in body.values() if isinstance(v, list) for r in v if isinstance(r, dict)]
        return found[:128] if found else [body]
    return []


def json_links(value, base):
    """Links must appear in actual response data, never schema example values."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in ('url', 'href', 'openapi', 'swagger', 'docs') and isinstance(item, str):
                yield urljoin(base, item)
            elif isinstance(item, (dict, list)):
                yield from json_links(item, base)
    elif isinstance(value, list):
        for item in value:
            yield from json_links(item, base)


def html_links(text, base):
    for match in re.findall(r'''(?:href\s*=|\burl\s*:)\s*["']([^"']+)["']''', text):
        yield urljoin(base, match)


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
    if url not in discovery_targets(state) or is_destructive(url):
        raise ValueError('Endpoint outside the discovered set or a state-changing path')
    working = dict(state)
    try:
        response = read_get(working, url)
        secrets = scenario_secrets(state)
        trace = response_record(response, secrets)
        path = artifact_path(state, 'api-observation', url, 'json')
        save_text(path, json.dumps({'url': sanitize(url), **trace}, ensure_ascii=False))
        content_type = response.headers.get('content-type', '').split(';')[0].strip().lower()[:120]
        row = {'url': url, 'status_code': response.status_code, 'content_type': content_type,
               'evidence_ref': str(path), 'links': [], 'records': []}
        operations = list(state.get('api_operations', []))
        try:
            body = response.json()
        except (ValueError, httpx.HTTPError):
            body = None
        if not response.is_success:
            row['document_kind'] = 'http_error'
            row['reason'] = f'Documentation probe returned HTTP {response.status_code}; no usable API document'
        elif isinstance(body, dict) and isinstance(body.get('paths'), dict) and ('openapi' in body or 'swagger' in body):
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
                    if is_destructive(route):
                        continue
                    operations.append({'url': endpoint, 'method': 'GET',
                        'authenticated': bool(spec.get('security', body.get('security', []))),
                        'summary': str(spec.get('summary', ''))[:160], 'source_ref': str(path)})
            row['document_kind'] = 'openapi'
        elif isinstance(body, (dict, list)):
            row['document_kind'] = 'json'
            row['records'] = sanitize(records(body), secrets)
            # Links must appear in actual response data, never schema example values.
            row['links'] = [u for u in json_links(body, url) if permitted(state, u)][:64]
        elif 'json' in content_type:
            row['document_kind'] = 'invalid_json'
            row['reason'] = 'Response declared JSON but the body could not be parsed'
        else:
            html = 'html' in content_type or bool(re.search(r'<\s*html', response.text[:512], re.I))
            row['document_kind'] = 'html' if html else 'unstructured'
            row['reason'] = ('HTML/SPA document returned for an API probe; no structured records' if html
                             else 'Unrecognized document type; no structured records')
            # Covers actual HTML links and Swagger UI's explicit document URL.
            row['links'] = [u for u in html_links(response.text, url) if permitted(state, u)][:64]
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
        reason = str(exc)[:200] if isinstance(exc, ValueError) else type(exc).__name__
        return {'execution_metrics': working.get('execution_metrics', {}),
                'discovery_limitations': state.get('discovery_limitations', []) + [{'url': url, 'reason': reason}]}


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
        limit = state.get('tool_call_budget', 20)
        if limit is not None and int(working.get('execution_metrics', {}).get('tool_calls_used', 0)) + 3 > limit:
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
