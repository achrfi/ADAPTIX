"""Regression coverage for the web assessment chain:
discovery -> grounded hypotheses -> targeted testing -> verification.

The flow is exercised through the deterministic adapters only; no LLM is called.
"""
import httpx

from src.adaptix.agents import hypotheses as hy
from src.adaptix.agents import planner
from src.adaptix.agents.evidence_context import evidence_key
from src.adaptix.evidence.web_signatures import build_findings
from src.adaptix.tools import web

BASE = 'http://127.0.0.1:18080'
HOSTS = ['127.0.0.1']


def _response(url, body, content_type='application/javascript'):
    return httpx.Response(200, headers={'content-type': content_type},
                          content=body.encode(), request=httpx.Request('GET', url))


def _state(**extra):
    state = {'hosts': HOSTS, 'scope_ports': [18080], 'execution_metrics': {},
             'errors': [], 'events': [], 'tool_call_budget': 20}
    state.update(extra)
    return state


# --- Discovery: client bundles yield application endpoints -------------------

def test_bundle_priority_orders_application_before_vendor():
    app = BASE + '/main.abc123.js'
    vendor = BASE + '/vendor.js'
    chunk = BASE + '/chunk-xyz.js'
    order = sorted([vendor, chunk, app], key=web._bundle_priority)
    assert order[0] == app


def test_script_bundle_extracts_api_routes_and_normalizes_parameters():
    state = _state()
    body = ("const a='/rest/products/search?q=';"
            "const b='/api/Users/{id}';"
            "const c='/assets/i18n/en.json';")
    routes = web._extract_script_routes(state, BASE + '/main.js', _response(BASE + '/main.js', body),
                                        'bundle', {})
    urls = {row['url']: row for row in routes}
    search = next(url for url in urls if url.startswith(BASE + '/rest/products/search'))
    assert search.endswith('search?q=')
    assert urls[search]['kind'] == 'script_route'
    assert urls[search]['api_like'] is True
    assert any(url.startswith(BASE + '/api/Users') for url in urls)


def test_route_row_marks_static_assets_and_api_paths():
    state = _state()
    asset = web.route_row(state, BASE + '/main.js', 'GET', 'script', 'bundle')
    api = web.route_row(state, BASE + '/api/Challenges', 'GET', 'xhr', 'browser')
    assert asset['static_asset'] is True and 'api_like' not in asset
    assert api['static_asset'] is False and api['api_like'] is True


def test_route_row_rejects_out_of_scope_url():
    assert web.route_row(_state(), 'http://evil.example/api', 'GET', 'xhr', 'browser') is None


def test_normalize_observed_url_keeps_parameters_drops_runtime_values():
    from src.adaptix.tools import playwright
    assert playwright.normalize_observed_url(BASE + '/rest/products/search?q=term') == \
        BASE + '/rest/products/search?q='
    first = playwright.normalize_observed_url(BASE + '/socket.io/?EIO=4&transport=polling&t=abc')
    second = playwright.normalize_observed_url(BASE + '/socket.io/?EIO=4&transport=polling&t=xyz')
    assert first == second == BASE + '/socket.io/?EIO=&transport=&t='
    assert playwright.normalize_observed_url(BASE + '/api/Users') == BASE + '/api/Users'


# --- Prioritization: probe unprobed app endpoints, never visited documents ----

def test_available_endpoints_excludes_visited_documents_and_probed_paths():
    state = _state(
        discovered_documents=[BASE + '/', BASE + '/robots.txt'],
        web_routes=[
            {'url': BASE + '/', 'method': 'GET', 'kind': 'document', 'static_asset': False},
            {'url': BASE + '/main.js', 'method': 'GET', 'kind': 'script', 'static_asset': True},
            {'url': BASE + '/login', 'method': 'GET', 'kind': 'link', 'static_asset': False, 'api_like': False},
            {'url': BASE + '/api/Users', 'method': 'GET', 'kind': 'xhr', 'static_asset': False, 'api_like': True},
        ],
        probe_traces=[{'url': BASE + '/login', 'method': 'GET'}])
    options = planner.available_endpoints(state)
    urls = [row['url'] for row in options]
    assert BASE + '/api/Users' in urls
    assert BASE + '/' not in urls
    assert BASE + '/main.js' not in urls
    assert BASE + '/login' not in urls
    assert urls[0] == BASE + '/api/Users'


def test_control_probe_to_discovered_document_is_rejected():
    state = _state(discovered_documents=[BASE + '/'])
    action = {'tool': 'http_request', 'target': BASE + '/', 'method': 'GET', 'reason': 'retry root'}
    reason = planner.action_rejection(state, action, {'http_request'})
    assert reason and 'already fetched' in reason


def test_payload_probe_to_application_endpoint_is_allowed():
    state = _state(discovered_documents=[BASE + '/'])
    action = {'tool': 'http_request', 'target': BASE + '/rest/products/search?q=1',
              'method': 'GET', 'reason': 'test search'}
    assert planner.action_rejection(state, action, {'http_request'}) is None


# --- Evidence-grounded hypotheses -------------------------------------------

def _sql_traces():
    control = {'url': BASE + '/rest/products/search?q=1', 'path_key': BASE + '/rest/products/search',
               'method': 'GET', 'parameter': 'q', 'payload': '1', 'control': True,
               'status_code': 200, 'content_type': 'application/json', 'detected': []}
    attack = {**control, 'url': BASE + "/rest/products/search?q=1'", 'payload': "1'", 'control': False,
              'detected': [{'category': 'sql_injection', 'signature': 'mysql_syntax'}]}
    return control, attack


def test_evidence_hypotheses_derive_from_detected_signature_only():
    _, attack = _sql_traces()
    state = _state(probe_traces=[attack])
    derived = hy.evidence_hypotheses(state)
    assert len(derived) == 1
    assert derived[0]['category'] == 'sql_injection'
    assert derived[0]['target'] == BASE + '/rest/products/search'
    assert derived[0]['evidence_refs'] == [evidence_key('probe_traces', attack)]
    assert hy.evidence_hypotheses(_state(probe_traces=[{**attack, 'detected': []}])) == []


def test_evidence_hypotheses_filters_unknown_refs_but_keeps_class():
    _, attack = _sql_traces()
    derived = hy.evidence_hypotheses(_state(probe_traces=[attack]), valid_refs=set())
    assert derived[0]['category'] == 'sql_injection' and derived[0]['evidence_refs'] == []


def test_diagnose_hypotheses_distinguishes_evidence_from_absence():
    _, attack = _sql_traces()
    present = hy.diagnose_hypotheses(_state(probe_traces=[attack]), model=0, evidence=1, merged=1)
    assert present['origin'] == 'evidence' and present['reason'] == 'hypotheses_present'
    absent = hy.diagnose_hypotheses(_state())
    assert absent['origin'] == 'none' and absent['reason'] == 'no_observations_yet'


def test_merge_canonicalizes_free_text_categories_and_dedupes():
    proposed = [
        {'category': 'Broken Access Control (IDOR)', 'target': BASE + '/api/Challenges', 'rationale': 'a'},
        {'category': 'idor_bola', 'target': BASE + '/api/Challenges', 'rationale': 'b'},
    ]
    merged = hy.merge_hypotheses([], proposed)
    assert len(merged) == 1
    assert merged[0]['category'] == 'idor_bola'


# --- End-to-end chain: discover -> hypothesize -> test -> verify ------------

def test_discovery_to_verified_finding_chain():
    control, attack = _sql_traces()
    state = _state(probe_traces=[control, attack], attempted_actions=[
        {'tool': 'http_request', 'target': attack['url'], 'hypothesis': 'possible SQL injection in q'}])

    derived = hy.evidence_hypotheses(state)
    state['hypotheses'] = hy.merge_hypotheses([], derived)
    assert state['hypotheses'][0]['status'] == 'candidate'

    findings = build_findings(state)
    assert findings and findings[0]['category'] == 'sql_injection'
    assert findings[0]['verification_status'] == 'confirmed'

    resolved = hy.update_hypotheses(state)
    assert resolved[0]['status'] == 'supported'
