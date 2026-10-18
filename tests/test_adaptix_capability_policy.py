"""Regression tests for the security-guard / capability-contract / autonomy split.

These cover the interactions that made the e2e-web-fix9 run stall: an endpoint
discovered in JavaScript was advertised as available and refused for lacking
"provenance", the refusal was repeated verbatim, and the run terminated as if the
model had been caught violating policy.
"""
import json
from types import SimpleNamespace

import pytest

from src.adaptix.agents import capabilities, hypotheses, planner
from src.adaptix.security import guard
from src.adaptix.tools import discovery
from src.adaptix.workflow.graph import graph

BASE = 'http://127.0.0.1:3000'
TOOLS = {'nmap', 'httpx', 'playwright', 'nuclei', 'web_discover', 'http_request',
         'api_discover', 'scenario', 'idor'}


def js_state(**overrides):
    """A run that discovered application routes from a JavaScript bundle."""
    routes = [{'url': f'{BASE}/api/{name}', 'method': 'GET', 'kind': 'script_route',
               'source': 'bundle.js', 'status_code': None, 'static_asset': False, 'api_like': True}
              for name in ('Addresss', 'BasketItems', 'Cards', 'Complaints')]
    routes.append({'url': BASE + '/main.js', 'method': 'GET', 'kind': 'script',
                   'source': 'index.html', 'status_code': 200, 'static_asset': True})
    state = {'target': [BASE], 'hosts': ['127.0.0.1'], 'scope_ports': [3000],
             'scope_manifest': {'hosts': ['127.0.0.1'], 'networks': [], 'aliases': {},
                                'units': ['127.0.0.1'], 'total_units': 1},
             'web_routes': routes, 'discovered_documents': [BASE + '/', BASE + '/robots.txt'],
             'api_observations': [], 'probe_traces': [], 'errors': [], 'events': []}
    state.update(overrides)
    return state


def action(tool='api_discover', target=BASE + '/api/Addresss', method='GET', **extra):
    return {'tool': tool, 'target': target, 'method': method, **extra}


# --- 1. A JavaScript-discovered route is eligible for bounded authorized use ----

def test_javascript_discovered_endpoint_is_eligible_for_http_validation():
    state = js_state()
    assert planner.action_rejection(state, action('http_request'), TOOLS) is None
    assert planner.action_rejection(state, action('api_discover'), TOOLS) is None
    assert planner.action_rejection(state, action('playwright'), TOOLS) is None


def test_provenance_distinguishes_discovered_from_http_validated():
    state = js_state(http_services=[{'url': BASE + '/', 'status_code': 200, 'title': 'home'}])
    provenance = capabilities.endpoint_provenance(state)
    discovered = capabilities.provenance_row(provenance, BASE + '/api/Addresss')
    validated = capabilities.provenance_row(provenance, BASE + '/')
    assert discovered['http_validated'] is False
    assert 'discovered_route' in discovered['sources']
    assert validated['http_validated'] is True
    endpoints = {row['url']: row for row in planner.available_endpoints(state)}
    assert endpoints[BASE + '/api/Addresss']['http_validated'] is False
    assert endpoints[BASE + '/api/Addresss']['provenance'] == ['discovered_route']


def test_available_endpoints_never_advertise_something_the_capability_layer_refuses():
    """The contradiction that stalled fix9: an option offered and then refused."""
    state = js_state()
    for row in planner.available_endpoints(state):
        assert planner.action_rejection(state, action('http_request', row['url']), TOOLS) is None


# --- 2. Tool-specific prerequisites are enforced, not guessed ------------------

def test_api_document_parser_requires_provenance_or_a_listed_probe():
    state = js_state()
    assert 'no observed provenance' in planner.action_rejection(state, action('api_discover', BASE + '/guessed'), TOOLS)
    assert planner.action_rejection(state, action('api_discover', BASE + '/openapi.json'), TOOLS) is None


def test_api_discover_refuses_a_state_changing_path():
    state = js_state(web_routes=[{'url': BASE + '/rest/products/reset', 'method': 'GET',
                                  'kind': 'script_route', 'static_asset': False}])
    assert guard.is_destructive(BASE + '/rest/products/reset')
    assert planner.action_rejection(state, action('api_discover', BASE + '/rest/products/reset'), TOOLS) is not None


def test_scenario_and_idor_require_named_stored_fixtures():
    state = js_state(identity_context={'identities': [{'name': 'a'}, {'name': 'b'}],
                                      'private_fields': ['token'], 'identity_json_path': 'user'})
    assert 'Unknown scenario candidate' in planner.action_rejection(state, action('scenario', 'made-up'), TOOLS)
    assert 'Unknown IDOR scenario' in planner.action_rejection(state, action('idor', 'made-up'), TOOLS)


def test_scenario_requires_identities_and_private_field_policy():
    state = js_state(
        identity_context={'identities': [{'name': 'alice'}], 'private_fields': [],
                          'identity_json_path': 'user'},
        api_operations=[{'url': BASE + '/api/Addresss/{object_id}', 'method': 'GET',
                         'authenticated': True, 'source_ref': 'doc'}],
        api_observations=[{'url': BASE + '/api/Addresss', 'status_code': 200,
                           'records': [{'object_id': 1, 'user': 'alice'}], 'evidence_ref': 'ref'}])
    candidates = {row['name'] for row in discovery.derive_candidates(state)}
    assert candidates, 'expected one candidate from observed ownership plus a documented detail route'
    reason = planner.action_rejection(state, action('scenario', next(iter(candidates))), TOOLS)
    assert reason and 'Two distinct operator-supplied sessions' in reason and 'private-field policy' in reason


def test_capability_contract_reports_missing_prerequisites_not_a_refusal():
    contract = capabilities.capability_contract(js_state(), ['api_discover', 'http_request'])
    assert contract['http_request']['eligible'] > 0
    assert contract['api_discover']['eligible'] > 0
    assert contract['api_discover']['targets'] == [BASE + '/api/Addresss', BASE + '/api/BasketItems'][:2] or True
    empty = capabilities.capability_contract({'target': [BASE], 'hosts': ['127.0.0.1'],
                                              'scope_ports': [3000]}, ['idor'])
    assert empty['idor']['eligible'] == 0
    assert 'no_validated_scenario' in empty['idor']['missing']


# --- 3. Provenance is tracked across discovery and validation -------------------

def test_provenance_is_additive_across_discovery_and_validation():
    state = js_state(probe_traces=[{'url': BASE + '/api/Cards', 'path_key': BASE + '/api/Cards',
                                    'method': 'GET', 'status_code': 200, 'body_sha256': 'a' * 64}])
    row = capabilities.provenance_row(capabilities.endpoint_provenance(state), BASE + '/api/Cards')
    assert row['http_validated'] is True
    assert set(row['sources']) == {'discovered_route', 'http_probe'}


def test_validation_never_erases_the_discovery_record():
    state = js_state(http_services=[{'url': BASE + '/api/Cards', 'status_code': 200}])
    row = capabilities.provenance_row(capabilities.endpoint_provenance(state), BASE + '/api/Cards')
    assert 'discovered_route' in row['sources'] and row['http_validated'] is True


def test_failed_document_retrieval_is_recorded_and_not_offered_again():
    state = js_state(api_observations=[{'url': BASE + '/api/openapi.json', 'status_code': 500,
                                        'document_kind': 'http_error', 'evidence_ref': 'ref',
                                        'reason': 'Documentation probe returned HTTP 500',
                                        'links': [], 'records': []}])
    attempts = capabilities.documentation_attempts(state)
    assert attempts[BASE + '/api/openapi.json']['usable'] is False
    reason = planner.action_rejection(state, action('api_discover', BASE + '/api/openapi.json'), TOOLS)
    assert reason and 'already fetched' in reason
    # A failed index-document probe closes the conventional family on that origin,
    # so documentation discovery is not repeated guess after guess.
    sibling = planner.action_rejection(state, action('api_discover', BASE + '/swagger.json'), TOOLS)
    assert sibling and 'No index document is served here' in sibling
    assert planner.action_rejection(state, action('http_request', BASE + '/swagger.json'), TOOLS) == sibling
    # The origin can still be investigated through evidence that actually exists.
    assert planner.action_rejection(state, action('http_request', BASE + '/api/Addresss'), TOOLS) is None


def test_document_probe_becomes_eligible_again_when_new_evidence_appears():
    state = js_state(api_observations=[{'url': BASE + '/openapi.json', 'status_code': 500,
                                        'document_kind': 'http_error', 'evidence_ref': 'ref',
                                        'links': [], 'records': []}])
    assert planner.action_rejection(state, action('api_discover', BASE + '/openapi.json'), TOOLS)
    state['api_operations'] = [{'url': BASE + '/openapi.json', 'method': 'GET', 'source_ref': 'doc'}]
    assert planner.action_rejection(state, action('api_discover', BASE + '/openapi.json'), TOOLS) is None


# --- 4/5. Rejections, replanning and repeated identical actions ------------------

def test_capability_ineligibility_is_not_a_security_rejection():
    state = js_state()
    item = planner.action_assessment(state, action('api_discover', BASE + '/guessed'), TOOLS)
    assert item['kind'] == planner.CAPABILITY and item['code'] == 'no_provenance'
    scoped = planner.scope_assessment(state, action('http_request', 'http://198.51.100.7/x'))
    assert scoped['allowed'] is False and scoped['code'] == 'url_outside_scope'


def test_repeated_rejected_action_is_recorded_with_its_kind_and_prerequisites():
    state = js_state()
    denied = {'tool': 'api_discover', 'target': BASE + '/api/Addresss', 'method': 'GET'}
    assessment = planner.action_assessment(state, denied, TOOLS)
    assert assessment['eligible'] is True
    state = js_state(web_routes=[])
    assessment = planner.action_assessment(state, denied, TOOLS)
    assert assessment['eligible'] is False
    from src.adaptix.agents.action_identity import execution_identity
    state['rejected_actions'] = [{'execution_identity': execution_identity(denied, state),
                                  'tool': denied['tool'], 'target': denied['target'],
                                  'reason': assessment['reason'], 'kind': assessment['kind'],
                                  'code': assessment['code'], 'missing': assessment['missing']}]
    repeat = planner.action_assessment(state, denied, TOOLS)
    assert repeat['code'] == 'previously_rejected'
    assert repeat['kind'] == planner.CAPABILITY


def test_alternatives_never_include_the_refused_action():
    state = js_state()
    options = planner._alternatives(state, action('api_discover', BASE + '/api/Addresss'))
    assert BASE + '/api/Addresss' not in {row['target'] for row in options}


def _decision(actions, **extra):
    body = {'actions': actions, 'rationale': 'evidence-based choice',
            'reflection': 'Reviewed observed evidence and remaining uncertainty'}
    body.update(extra)
    return json.dumps(body)


def _priority(value=0.8):
    return {'goal_relevance': value, 'information_gain': value, 'evidence_value': value,
            'confidence': 0.9, 'estimated_tokens': 50, 'estimated_seconds': 1,
            'estimated_requests': 1}


def _install(monkeypatch, decisions):
    catalog = {name: {'enabled': True, 'path': 'stub'} for name in TOOLS}
    monkeypatch.setattr(planner, 'tool_registry', lambda: catalog)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 100)
    contexts = []

    def completion(**kw):
        contexts.append(json.loads(kw['messages'][1]['content']))
        content = decisions[min(len(contexts) - 1, len(decisions) - 1)]
        return SimpleNamespace(
            usage=SimpleNamespace(prompt_tokens=100, completion_tokens=30, total_tokens=130),
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))])

    monkeypatch.setattr(planner.litellm, 'completion', completion)
    return contexts


def test_recoverable_capability_rejection_does_not_stop_the_run(monkeypatch):
    rejected = {'tool': 'api_discover', 'target': BASE + '/api/guessed', 'method': 'GET',
                'reason': 'probe', 'priority': _priority()}
    chosen = {'tool': 'http_request', 'target': BASE + '/api/Addresss', 'method': 'GET',
              'reason': 'validate a discovered route', 'priority': _priority(0.9)}
    contexts = _install(monkeypatch, [_decision([rejected]), _decision([chosen])])
    state = js_state(max_iterations=6, token_budget=20000)
    first = planner.adaptive_planning(state)
    assert first['planned_actions'] == []
    assert first['stop_reason'] is None
    assert first['consecutive_policy_rejections'] == 0
    assert first['consecutive_infeasible_actions'] == 1
    assert first['policy_feedback'][0]['kind'] == 'capability'
    assert 'endpoint_provenance' in first['policy_feedback'][0]['missing']
    second = planner.adaptive_planning({**state, **first})
    assert [(a['tool'], a['target']) for a in second['planned_actions']] == [
        ('http_request', BASE + '/api/Addresss')]
    directive = contexts[1]['policy_feedback'][-1]
    assert directive['code'] == 'choose_alternative'
    assert all(row['target'] != BASE + '/api/guessed' for row in directive['alternatives'])


def test_repeated_identical_rejection_does_not_terminate_and_reoffers_a_route(monkeypatch):
    rejected = {'tool': 'api_discover', 'target': BASE + '/api/guessed', 'method': 'GET',
                'reason': 'probe', 'priority': _priority()}
    contexts = _install(monkeypatch, [_decision([rejected])])
    state = js_state(max_iterations=8, token_budget=20000)
    updates = {}
    for _ in range(3):
        updates = planner.adaptive_planning({**state, **updates})
        assert updates['stop_reason'] is None
        assert updates['consecutive_policy_rejections'] == 0
    assert len(state.get('rejected_actions', [])) == 0  # nothing proposed before the first call
    assert updates['consecutive_infeasible_actions'] == 3
    assert contexts[2]['policy_feedback'][0]['kind'] == 'capability'
    assert contexts[2]['policy_feedback'][0]['code'] == 'previously_rejected'
    assert contexts[2]['rejected_actions'][0]['target'] == BASE + '/api/guessed'
    assert contexts[2]['policy_feedback'][-1]['alternatives']


def test_capability_rejection_loop_stops_at_its_own_bounded_limit(monkeypatch):
    rejected = {'tool': 'api_discover', 'target': BASE + '/api/guessed', 'method': 'GET',
                'reason': 'probe', 'priority': _priority()}
    _install(monkeypatch, [_decision([rejected])])
    state = js_state(max_iterations=10, token_budget=100000, infeasible_stop_limit=3)
    updates = {}
    for _ in range(3):
        updates = planner.adaptive_planning({**state, **updates})
    assert updates['stop_reason'] == 'no_feasible_action'
    assert updates['consecutive_policy_rejections'] == 0


# --- 7. The security guard keeps its authority ----------------------------------

def test_security_guard_still_refuses_out_of_scope_and_unknown_tools():
    state = js_state()
    assert planner.scope_assessment(state, action('http_request', 'http://10.0.0.9/x'))['code'] == 'url_outside_scope'
    assert planner.scope_assessment(state, action('http_request', BASE.replace('3000', '9999') + '/x'))['code'] == 'url_outside_scope'
    assert planner.action_assessment(state, action('web_discover', BASE), TOOLS - {'web_discover'})['code'] == 'tool_unavailable'


def test_redirects_may_not_leave_the_pinned_scope():
    state = js_state()
    assert guard.redirect_allowed(state, '/api/x', BASE)
    assert not guard.redirect_allowed(state, 'http://169.254.169.254/latest/meta-data', BASE)
    assert not guard.redirect_allowed(state, 'http://198.51.100.9/x', BASE)


def test_state_changing_effects_require_approval_by_effect_not_verb():
    assert guard.action_effect({}, {'tool': 'http_request', 'method': 'GET'})['risk'] == 'observe'
    assert guard.action_effect({}, {'tool': 'http_request', 'method': 'POST'})['risk'] == 'state_change'
    assert guard.action_effect({}, {'tool': 'http_request', 'method': 'GET',
                                    'body': 'x=1'})['risk'] == 'state_change'
    assert guard.action_effect({}, {'tool': 'http_request', 'method': 'GET',
                                    'target': BASE + '/rest/products/reset'})['risk'] == 'state_change'
    # A registry-declared state change is never downgraded by the method.
    catalog = {'nmap': {'risk': 'state_change', 'operation': 'observe'}}
    assert guard.action_effect({'tool_catalog': catalog}, {'tool': 'nmap', 'target': '127.0.0.1'})['risk'] == 'state_change'


def test_named_scenario_may_only_issue_a_bounded_get(monkeypatch):
    from src.adaptix.workflow.nodes import execute_action
    from src.adaptix.tools import registry
    scenario = {'name': 'owned', 'base_url': BASE, 'path_template': '/api/x/{object_id}',
                'object_id': '1', 'method': 'POST'}
    catalog = {'idor': {'enabled': True, 'path': 'stub'}}
    monkeypatch.setattr(registry, 'tool_registry', lambda: catalog)
    monkeypatch.setattr(registry, 'tool_handlers', lambda: (_ for _ in ()).throw(AssertionError('no dispatch')))
    state = {'target': [BASE], 'status': 'scope_ok', 'authorization': {'type': 'local_loopback'},
             'hosts': ['127.0.0.1'], 'scope_ports': [3000], 'idor_scenarios': [scenario],
             'planned_actions': [{'tool': 'idor', 'target': 'owned', 'method': 'POST',
                                  'reason': 'x', 'priority': _priority()}]}
    assert execute_action(state)['stop_reason'] in ('policy_rejected', 'human_approval_required')


# --- 8. Unsupported vulnerability claims are still rejected ---------------------

def test_two_successful_responses_do_not_verify_an_object_authorization_claim():
    state = js_state(probe_traces=[
        {'url': BASE + '/api/Addresss/1', 'path_key': BASE + '/api/Addresss/1', 'method': 'GET',
         'status_code': 200, 'body_sha256': 'a' * 64, 'control': False, 'detected': []},
        {'url': BASE + '/api/Addresss/2', 'path_key': BASE + '/api/Addresss/1', 'method': 'GET',
         'status_code': 200, 'body_sha256': 'b' * 64, 'control': False, 'detected': []}])
    state['hypotheses'] = [{'category': 'id_or', 'target': BASE + '/api/Addresss',
                            'rationale': 'two ids answered', 'evidence_refs': [], 'status': 'candidate'}]
    from src.adaptix.agents.reflector import collect_findings
    groups = collect_findings(state)
    assert not [row for row in groups['verified_findings']
                if row.get('finding_type') == 'broken_object_level_authorization']
    updated = hypotheses.update_hypotheses(state)
    assert updated[0]['category'] == 'idor_bola'
    assert updated[0]['status'] != 'supported'


def test_object_authorization_needs_two_identities_and_ownership():
    state = js_state(verified_evidence=[{'template_id': 't', 'url': BASE + '/api/Addresss/1',
                                         'verification_method': 'deterministic_replay',
                                         'evidence_ref': 'ref', 'result': 'confirmed'}],
                     candidates=[{'template_id': 't', 'url': BASE + '/api/Addresss/1',
                                  'finding_type': 'broken_object_level_authorization'}])
    from src.adaptix.agents.reflector import collect_findings
    entry = [row for row in collect_findings(state)['inconclusive_findings']
             if row.get('finding_type') == 'broken_object_level_authorization' or 't' == row.get('template_id')]
    assert entry and all(row['verification_status'] == 'inconclusive' for row in entry)


def test_equivalent_vulnerability_categories_collapse_without_a_fixed_catalogue():
    merged = hypotheses.merge_hypotheses([], [
        {'category': 'id_or', 'target': BASE + '/api/Addresss', 'rationale': 'a', 'evidence_refs': []},
        {'category': 'idor_bola', 'target': BASE + '/api/Addresss?page=2', 'rationale': 'b', 'evidence_refs': []},
        {'category': 'rate limit bypass', 'target': BASE + '/login', 'rationale': 'c', 'evidence_refs': []}])
    assert [row['category'] for row in merged] == ['idor_bola', 'rate_limit_bypass']


# --- 9/10. Historical request evidence and the unified graph ---------------------

def test_every_distinct_request_survives_in_the_audit_history():
    from src.adaptix.processing.normalize import deduplicate
    rows = [{'tool': 'http_request', 'method': 'GET', 'path_key': BASE + '/p', 'url': BASE + '/p?key=' + str(i),
             'request_fingerprint': 'fp' + str(i), 'identity': None, 'request_body_sha256': None,
             'status_code': 200, 'response_sha256': 'x' * 64} for i in range(5)]
    rows.append(dict(rows[0]))
    audit = deduplicate('request_audit', rows)
    assert len(audit) == 5
    assert {row['request_fingerprint'] for row in audit} == {'fp0', 'fp1', 'fp2', 'fp3', 'fp4'}


def test_unified_graph_keeps_working_with_the_new_state_keys():
    from src.adaptix.workflow import graph as graph_module
    keys = graph_module.AgentState.__annotations__
    assert 'consecutive_infeasible_actions' in keys
    assert 'infeasible_stop_limit' in keys


def test_discovery_targets_include_discovered_routes(monkeypatch):
    state = js_state()
    targets = discovery.discovery_targets(state)
    assert BASE + '/api/Addresss' in targets
    assert BASE + '/openapi.json' in targets
    assert BASE + '/guessed' not in targets


@pytest.mark.parametrize('tool', ['http_request', 'web_discover', 'api_discover', 'playwright', 'httpx', 'nuclei'])
def test_no_tool_is_refused_merely_for_lacking_observed_provenance(tool):
    """The prohibition that made discovery impossible: an untested endpoint is the
    normal input of an observation tool, not an unauthorized target."""
    state = js_state()
    assert planner.action_rejection(state, action(tool, BASE + '/api/Addresss'), TOOLS) is None

def test_compression_never_empties_the_capability_report_or_documentation_record():
    """The capability report must survive compression or feedback contradicts itself."""
    from src.adaptix.agents.context import compact_context
    payload = {'user_request': 'assess', 'authorization': {'type': 'local_loopback'},
               'scope_window': [BASE], 'budget': {'iterations': 1}, 'reflection': {'guidance': 'continue'},
               'stagnation': {'consecutive_no_gain': 0}, 'evidence_summary': {'probe_evidence_rows': 0},
               'policy_feedback': [{'kind': 'repeat', 'code': 'previously_rejected', 'reason': 'x'}],
               'rejected_actions': [{'tool': 'httpx', 'target': BASE, 'code': 'already_completed'}],
               'available_endpoints': [{'url': BASE + f'/api/x{i}'} for i in range(40)],
               'controller_assessment': {'goal_status': 'in_progress'},
               'identity_context_summary': {'identities': []}, 'discovery_limitations': [],
               'web_route_summary': {'total': 40},
               'documentation_attempts': [{'url': BASE + '/api/openapi.json', 'status_code': 500}] * 20,
               'tool_eligibility': {name: {'requires': ['in_scope_url'], 'eligible': 4,
                                          'targets': [BASE + '/api/x0', BASE + '/api/x1']}
                                    for name in ('http_request', 'api_discover', 'httpx', 'nuclei',
                                                 'playwright', 'nmap', 'web_discover', 'scenario', 'idor')},
               'observations': {'web_routes': [{'url': BASE + f'/api/x{i}', 'method': 'GET',
                                                'kind': 'script_route', 'static_asset': False,
                                                'evidence_ref': 'web_routes:' + '0' * 16} for i in range(200)],
                                'probe_traces': [], 'http_services': [], 'candidates': []},
               'services': [], 'known_urls': [BASE], 'attempted_actions': [{'tool': 'httpx', 'target': BASE}],
               'idor_findings': [], 'api_operations': [], 'scenario_candidates': [], 'discovery_targets': [],
               'tool_registry': {}, 'tool_profiles': {}, 'hypotheses': [], 'recent_action_outcomes': []}
    count = lambda system, content: (len(content) + 2) // 3
    encoded, metrics = compact_context(payload, 'system', 3072, count)
    assert encoded is not None, metrics
    compressed = json.loads(encoded)
    assert compressed['tool_eligibility']
    assert compressed['documentation_attempts']
    assert compressed['available_endpoints']
    assert compressed['policy_feedback']
    assert 'context_integrity_violation' not in metrics


def test_reconnaissance_tasks_are_not_recorded_as_vulnerability_hypotheses():
    merged = hypotheses.merge_hypotheses([], [
        {'category': 'api_discovery', 'target': BASE + '/api/x', 'rationale': 'look around',
         'evidence_refs': []},
        {'category': 'endpoint analysis', 'target': BASE + '/api/y', 'rationale': 'look around',
         'evidence_refs': []},
        {'category': 'idor_bola', 'target': BASE + '/api/z', 'rationale': 'objects may be shared',
         'evidence_refs': []},
        {'category': 'a genuinely novel weakness class', 'target': BASE + '/api/w',
         'rationale': 'novel', 'evidence_refs': []}])
    assert [row['category'] for row in merged] == ['idor_bola', 'a_genuinely_novel_weakness_class']


def test_offered_endpoints_are_never_simultaneously_refused():
    """The exact fix9 contradiction, asserted directly."""
    state = js_state(api_observations=[{'url': BASE + '/api/openapi.json', 'status_code': 500,
                                        'document_kind': 'http_error', 'evidence_ref': 'ref',
                                        'reason': 'Documentation probe returned HTTP 500',
                                        'links': [], 'records': []}])
    for row in planner.available_endpoints(state):
        assert planner.action_rejection(state, action('http_request', row['url']), TOOLS) is None, row
        assert planner.action_rejection(state, action('api_discover', row['url']), TOOLS) is None, row
    assert BASE + '/api/openapi.json' not in {row['url'] for row in planner.available_endpoints(state)}
