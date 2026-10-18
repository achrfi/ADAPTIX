"""Goal-directed assessment: hypotheses, honest progress, repeat avoidance, context."""
import httpx

from src.adaptix.agents import hypotheses as hy
from src.adaptix.agents import planner
from src.adaptix.agents.context import compact_context
from src.adaptix.agents.progress import progress_assessment
from src.adaptix.tools import web

BASE = 'http://127.0.0.1:18080'


def _response(url, body, content_type='text/html'):
    return httpx.Response(200, headers={'content-type': content_type},
                          content=body.encode(), request=httpx.Request('GET', url))


def test_progress_zero_when_action_adds_no_new_evidence():
    state = {'hosts': ['127.0.0.1'],
             'web_routes': [{'url': BASE + '/a', 'method': 'GET', 'kind': 'link'},
                            {'url': BASE + '/b', 'method': 'GET', 'kind': 'link'}],
             'probe_traces': [{'path_key': BASE + '/a', 'method': 'GET', 'body_sha256': 'x'}]}
    assert progress_assessment(state, {})['goal_progress'] == 0
    assert progress_assessment(state, {'web_routes': []})['goal_progress'] == 0
    reduced = progress_assessment(state, {'web_routes': state['web_routes'][:1]})
    assert reduced['goal_progress'] == 0


def test_static_asset_only_discovery_scores_below_application_routes():
    state = {'hosts': ['127.0.0.1']}
    static = {'web_routes': [{'url': BASE + '/chunk.js', 'method': 'GET', 'kind': 'script', 'static_asset': True}]}
    application = {'web_routes': [{'url': BASE + '/rest/x', 'method': 'GET', 'kind': 'script_route', 'static_asset': False}]}
    assert progress_assessment(state, application)['goal_progress'] > progress_assessment(state, static)['goal_progress']


def test_repeated_payload_probe_is_rejected():
    state = {'hosts': ['127.0.0.1'], 'scope_ports': [18080],
             'probe_traces': [{'path_key': BASE + '/search', 'method': 'GET', 'payload': '1'}]}
    action = {'tool': 'http_request', 'target': BASE + '/search?q=1', 'method': 'GET', 'reason': 'retry'}
    reason = planner.action_rejection(state, action, {'http_request'})
    assert reason and 'already probed' in reason


def test_repeated_web_discovery_document_set_is_rejected():
    state = {'hosts': ['127.0.0.1'], 'scope_ports': [18080],
             'discovered_documents': [BASE + '/', BASE + '/robots.txt', BASE + '/sitemap.xml']}
    action = {'tool': 'web_discover', 'target': BASE + '/', 'reason': 'retry'}
    reason = planner.action_rejection(state, action, {'web_discover'})
    assert reason and 'already covered' in reason


def test_no_new_payload_probe_on_same_path_is_allowed():
    state = {'hosts': ['127.0.0.1'], 'scope_ports': [18080],
             'probe_traces': [{'path_key': BASE + '/search', 'method': 'GET', 'payload': 'x'}]}
    action = {'tool': 'http_request', 'target': BASE + "/search?q=1'", 'method': 'GET', 'reason': 'new payload'}
    assert planner.action_rejection(state, action, {'http_request'}) is None


def _sql_injection_state(monkeypatch):
    def fake(state, url, method='GET', body=None):
        return _response(url, "You have an error in your SQL syntax" if "'" in url else 'ok')
    monkeypatch.setattr(web, '_request', fake)
    state = {'run_id': 'web-assessment', 'hosts': ['127.0.0.1'], 'scope_ports': [18080], 'target': [BASE + '/'],
             'scope_manifest': {'hosts': ['127.0.0.1'], 'networks': [], 'aliases': {}},
             'execution_metrics': {}, 'errors': [], 'events': [], 'tool_call_budget': 20}
    for url in (BASE + '/search', BASE + "/search?q=1'"):
        state.update(web.http_request({**state, 'planned_actions': [
            {'tool': 'http_request', 'target': url, 'method': 'GET'}]}))
    return state


def test_hypothesis_supported_by_confirmed_deterministic_finding(monkeypatch):
    state = _sql_injection_state(monkeypatch)
    state['hypotheses'] = [{'category': 'SQL injection', 'target': BASE + '/search',
                            'rationale': 'errors on quote', 'evidence_refs': [], 'status': 'candidate'}]
    result = hy.update_hypotheses(state)
    assert result[0]['status'] == 'supported'


def test_hypothesis_refuted_by_clean_encoded_reflection():
    state = {'hosts': ['127.0.0.1'], 'hypotheses': [
        {'category': 'cross_site_scripting', 'target': BASE + '/x', 'rationale': 'reflection', 'status': 'candidate'}],
        'probe_traces': [{'url': BASE + '/x?q=<script>', 'method': 'GET', 'control': False,
                          'detected': [{'category': 'cross_site_scripting', 'signature': 'html_encoded_reflection'}]}]}
    assert hy.update_hypotheses(state)[0]['status'] == 'refuted'


def test_hypothesis_without_evidence_stays_candidate_or_testing():
    state = {'hosts': ['127.0.0.1'], 'probe_traces': [],
             'hypotheses': [{'category': 'path_traversal', 'target': BASE + '/x',
                             'rationale': 'maybe', 'status': 'candidate'}],
             'attempted_actions': [{'tool': 'http_request', 'target': BASE + '/x?f=../', 'hypothesis': 'path_traversal'}]}
    assert hy.update_hypotheses(state)[0]['status'] == 'testing'


def test_categorize_maps_free_text_to_canonical_slug():
    assert hy.categorize('The API may be vulnerable to IDOR or broken access control') == 'idor_bola'
    assert hy.categorize('possible SQL injection in the search parameter') == 'sql_injection'
    assert hy.categorize('reflected XSS risk') == 'cross_site_scripting'
    assert hy.categorize('inventory the documented routes') is None


def test_hypotheses_derived_from_action_hypothesis_when_model_omits_array():
    proposed = [{'tool': 'http_request', 'target': BASE + '/rest/products/search?q=1',
                 'hypothesis': 'The API may expose objects vulnerable to IDOR or access control weaknesses',
                 'method': 'GET'},
                {'tool': 'web_discover', 'target': BASE + '/', 'hypothesis': 'inventory documented routes'}]
    derived = hy.hypotheses_from_actions(proposed)
    assert len(derived) == 1
    assert derived[0]['category'] == 'idor_bola'
    assert derived[0]['target'] == BASE + '/rest/products/search?q=1'


def test_merge_hypotheses_filters_unknown_evidence_refs():
    merged = hy.merge_hypotheses([], [{'category': 'auth', 'target': BASE + '/x',
                                       'rationale': 'r', 'evidence_refs': ['EV-1', 'web_routes:abc']}],
                                 valid_refs={'web_routes:abc'})
    assert merged[0]['evidence_refs'] == ['web_routes:abc']
    assert merged[0]['status'] == 'candidate'


def test_compact_context_degrades_bulk_but_preserves_reflection_and_evidence():
    payload = {'services': [], 'known_urls': [], 'attempted_actions': [
                   {'tool': 'httpx', 'target': BASE, 'reason': 'r' * 400}],
               'idor_findings': [], 'api_operations': [], 'scenario_candidates': [],
               'discovery_targets': [], 'discovery_limitations': [{'url': BASE, 'reason': 'Line' * 100}],
               'observations': {'web_routes': [{'url': BASE + '/a', 'kind': 'link', 'static_asset': False}],
                                'http_services': [{'url': BASE, 'status_code': 200}]},
               'scope_window': [BASE], 'requested_endpoints': [BASE], 'domain_aliases': {},
               'reflection': {'progress': 1, 'guidance': 'g', 'last_action': [{'tool': 'httpx'}],
                              'policy_feedback': [{'reason': 'dup'}]},
               'tool_profiles': {'httpx': {'mean_seconds': 1, 'note': 'x' * 400}},
               'tool_registry': {'httpx': {'description': 'y' * 400}},
               'rejected_actions': [{'tool': 'httpx', 'target': BASE, 'reason': 'z' * 400}],
               'policy_feedback': [{'action': {}, 'reason': 'w' * 400}],
               'recent_action_outcomes': [{'progress_reason': 'q' * 400}]}
    count = lambda system, content: (len(system) + len(content)) // 4
    encoded, metrics = compact_context(payload, 'system', 450, count)
    context = __import__('json').loads(encoded)
    assert encoded is not None and metrics['removed_context_records'] > 0
    assert context['reflection']['progress'] == 1 and 'last_action' not in context['reflection']
    assert context['observations']['web_routes'] == payload['observations']['web_routes']


def test_compact_context_returns_none_when_only_instruction_fits():
    payload = {'services': [], 'known_urls': [], 'attempted_actions': [], 'idor_findings': [],
               'api_operations': [], 'scenario_candidates': [], 'discovery_targets': [],
               'discovery_limitations': [], 'observations': {}, 'scope_window': [],
               'requested_endpoints': [], 'domain_aliases': {}, 'reflection': {},
               'tool_profiles': {}, 'tool_registry': {}, 'rejected_actions': [],
               'policy_feedback': [], 'recent_action_outcomes': []}
    assert compact_context(payload, 'system', 0, lambda *a: 999)[0] is None
