"""Regression coverage for e2e-web-fix7.

The failed run discovered 63 web routes, then stopped the second planning pass
with ``context_budget_exhausted`` before any provider call: the uncompressed
pass required 6616 tokens while only 3072 were available inside a 4096-token
model context, and the pre-fix compressor could not shrink the payload below
its 4185-token floor (system prompt 1663 tokens + 7567 payload bytes). These
tests pin the adaptive compression, the recorded required/available/compressed
token metrics, and that the second pass now reaches the model.
"""
import json
import time
from types import SimpleNamespace

from src.adaptix.agents import context as context_module
from src.adaptix.agents import planner
from src.adaptix.agents.context import compact_context

BASE = 'http://127.0.0.1:18080'
MODEL_CONTEXT_TOKENS = 4096
TOKEN_BUDGET = 35000
TOKENS_USED = 2156
CONTEXT_BUDGET = MODEL_CONTEXT_TOKENS - 1024  # planner reserve for completion tokens


def _byte_counter(system, content):
    """Deterministic stand-in for the local tokenizer (UTF-8 bytes / 3)."""
    return (len(system.encode('utf-8')) + len(content.encode('utf-8')) + 2) // 3


def _routes(count=63):
    rows = []
    for index in range(count):
        kind = 'script' if index % 5 == 0 else ('xhr' if index % 2 else 'link')
        rows.append({'url': f'{BASE}/app/section-{index}/resource-{index}', 'method': 'GET',
                     'kind': kind, 'static_asset': kind == 'script',
                     'api_like': kind in ('xhr', 'script'), 'status_code': 200})
    return rows


def _planner_payload(routes):
    """Pass-2 shaped payload: route inventory plus untested endpoint candidates."""
    return {
        'user_request': 'Authorized assessment of the local application under the signed scope.',
        'authorization': {'type': 'signed_grant', 'principal': 'operator', 'scope_units': 1},
        'scope_window': [BASE + '/'],
        'requested_endpoints': [BASE + '/'],
        'scope_summary': {'total_units': 1, 'touched': 0, 'deferred': 0, 'remaining': 1},
        'domain_aliases': {},
        'budget': {'iteration_limit': 10, 'tool_call_limit': 20, 'token_limit': TOKEN_BUDGET,
                   'iterations': 1, 'tool_calls': 1, 'tokens': TOKENS_USED, 'seconds_remaining': 700},
        'tool_registry': {f'tool-{i}': {'description': f'Capability description number {i} ' + 'x' * 120}
                          for i in range(12)},
        'reflection': {'progress': 1, 'uncertainty': ['route inventory not yet tested'],
                       'errors': [], 'guidance': 'test a listed untested endpoint'},
        'stagnation': {'consecutive_no_gain': 0},
        'evidence_summary': {'probe_evidence_rows': 0, 'request_attempts': 0,
                             'distinct_responses': 0, 'signature_rows': 0},
        'policy_feedback': [{'action': 'web_discover', 'reason': 'pass one completed'}],
        'rejected_actions': [],
        'api_operations': [],
        'scenario_candidates': [],
        'hypotheses': [],
        'hypothesis_seeds': [],
        'findings': [],
        'discovery_targets': [],
        'identity_context_summary': {'identities': [], 'privacy_policy_configured': False},
        'discovery_limitations': [],
        'previous_self_reflection': '',
        'tool_profiles': {},
        'recent_action_outcomes': [{'tool': 'web_discover', 'target': BASE + '/', 'seconds': 12.0,
                                    'new_facts': 63, 'context_tokens_estimate': 400, 'failed': False,
                                    'goal_progress': 0.3, 'verification_gain': 0,
                                    'progress_reason': 'discovered the route inventory'}],
        'idor_scenarios': [],
        'known_urls': [BASE + '/'],
        'services': [],
        'observations': {'web_routes': [{'url': row['url'], 'method': row['method'], 'kind': row['kind'],
                                         'static_asset': row['static_asset'], 'api_like': row['api_like'],
                                         'status_code': row['status_code'],
                                         'evidence_ref': f'web_routes:{index:016x}'}
                                        for index, row in enumerate(routes[:30])],
                         'probe_traces': [], 'http_services': [], 'candidates': [],
                         'browser_evidence': [], 'nuclei_template_selections': [],
                         'api_observations': [], 'scenario_validations': []},
        'web_route_summary': {'total': len(routes), 'application': len(routes), 'static_assets': 0,
                              'api_like': len(routes)},
        'idor_findings': [],
        'attempted_actions': [{'tool': 'web_discover', 'target': BASE + '/',
                               'reason': 'inventory the routes offered by the seed document',
                               'hypothesis': 'the seed document links application endpoints worth testing'}],
        'available_endpoints': [{'url': f'{BASE}/app/section-{index}/resource-{index}', 'method': 'GET',
                                 'kind': 'xhr', 'api_like': True} for index in range(24)],
        'stalled_actions': [],
        'controller_assessment': {'objective_kind': 'security_assessment', 'goal_status': 'in_progress',
                                  'evidence_refs': [f'web_routes:{index:016x}' for index in range(12)],
                                  'uncertainty': 'no endpoint has been probed yet',
                                  'failure': ''},
    }


def test_compact_context_diagnoses_fix7_minimum_and_compresses():
    payload = _planner_payload(_routes())
    system = 'Authorized web/API planner. ' + 'Control text ' * 100
    required = _byte_counter(system, json.dumps(payload, ensure_ascii=False, separators=(',', ':'), default=str))
    # Diagnosis: the uncompressed pass exceeded the 3072-token context budget.
    assert required > CONTEXT_BUDGET
    encoded, metrics = compact_context(payload, system, CONTEXT_BUDGET, _byte_counter)
    assert encoded is not None
    assert metrics['context_available_tokens'] == CONTEXT_BUDGET
    assert metrics['context_required_tokens'] == required
    assert metrics['context_required_tokens'] > metrics['context_available_tokens']
    assert metrics['context_compressed_tokens'] <= metrics['context_available_tokens']
    assert metrics['removed_context_records'] > 0
    assert metrics['context_compression_stages']
    context = json.loads(encoded)
    # Objective, authorization and scope survive compression.
    assert context['user_request'] == payload['user_request']
    assert context['authorization']['type'] == 'signed_grant'
    assert context['scope_summary']['total_units'] == 1
    # Route inventories are summarized, not repeated at full length.
    assert context['web_route_summary']['total'] == 63
    assert len(context['observations']['web_routes']) < 30
    # Untested endpoint candidates stay prioritized, recent evidence and feedback stay.
    assert context['available_endpoints'] and context['available_endpoints'][0]['api_like']
    assert context['recent_action_outcomes'] and context['policy_feedback']
    assert context['reflection']['uncertainty']
    assert context['controller_assessment']['goal_status'] == 'in_progress'


def test_compact_context_stops_with_metrics_when_no_adequate_context_exists():
    payload = _planner_payload(_routes())
    system = 'system instruction'
    encoded, metrics = compact_context(payload, system, 0, _byte_counter)
    assert encoded is None
    assert metrics['context_required_tokens'] > metrics['context_available_tokens']
    assert metrics['context_compressed_tokens'] >= metrics['context_available_tokens']
    assert 'context_integrity_violation' not in metrics


def test_compact_context_fails_closed_when_a_stage_empties_essential_data(monkeypatch):
    payload = _planner_payload(_routes())
    system = 'system instruction'

    def destructive(state):
        state['user_request'] = ''
        return True

    monkeypatch.setattr(context_module, 'STAGES', (('destructive', destructive),))
    encoded, metrics = compact_context(payload, system, CONTEXT_BUDGET, _byte_counter)
    assert encoded is None
    assert metrics['context_integrity_violation'] == 'user_request'


def _fix7_state():
    return {'run_id': 'e2e-web-fix7', 'hosts': ['127.0.0.1'], 'scope_ports': [18080],
            'target': [BASE + '/'], 'user_prompt': 'Authorized assessment of the local application.',
            'authorization': {'type': 'signed_grant', 'grant_id': 'grant-fix7'}, 'principal': 'operator',
            'scope_manifest': {'units': [BASE + '/'], 'hosts': ['127.0.0.1'], 'networks': [], 'aliases': {},
                               'total_units': 1},
            'web_routes': _routes(), 'discovered_documents': [BASE + '/', BASE + '/robots.txt'],
            'attempted_actions': [{'tool': 'web_discover', 'target': BASE + '/',
                                   'reason': 'inventory the seed document',
                                   'hypothesis': 'the seed document links application endpoints'}],
            'reflection': {'progress': 1, 'uncertainty': [], 'errors': [], 'guidance': 'continue',
                           'consecutive_no_gain': 0, 'policy_feedback': [], 'last_outcome': []},
            'execution_metrics': {'tool_calls_used': 1}, 'errors': [], 'events': [],
            'iterations': 1, 'max_iterations': 10, 'tool_call_budget': 20, 'token_budget': TOKEN_BUDGET,
            'model_context_tokens': MODEL_CONTEXT_TOKENS, 'time_budget_seconds': 1800,
            'run_started_at': time.time(),
            'planner_metrics': {'tokens_used': TOKENS_USED, 'llm_calls': 1, 'mode': 'llm'}}


def _install_model(monkeypatch, captured):
    def completion(**kwargs):
        captured.update(kwargs)
        content = json.dumps({'actions': [], 'rationale': 'evaluate the stored route inventory',
                              'reflection': 'routes are inventoried but untested',
                              'review': {'goal_status': 'in_progress', 'evidence_refs': [],
                                         'uncertainty': 'no endpoint has been probed',
                                         'failure': '', 'decision_change': 'probe a listed endpoint'}})
        return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=900, completion_tokens=60, total_tokens=960),
                               choices=[SimpleNamespace(message=SimpleNamespace(content=content))])
    monkeypatch.setattr(planner, 'tool_registry', lambda: {'httpx': {'enabled': True, 'path': 'cli'}})
    monkeypatch.setattr(planner.litellm, 'token_counter',
                        lambda **kw: sum(len((m.get('content') or '').encode('utf-8')) for m in kw['messages']) // 3)
    monkeypatch.setattr(planner.litellm, 'completion', completion)


def test_e2e_web_fix7_second_planning_pass_reaches_the_model(monkeypatch):
    captured = {}
    _install_model(monkeypatch, captured)
    result = planner.adaptive_planning(_fix7_state())
    assert captured, 'the second planning pass must reach the provider'
    metrics = result['planner_metrics']
    assert metrics['mode'] == 'llm'
    assert result['stop_reason'] != 'context_budget_exhausted'
    # The uncompressed context did not fit; compression made it fit and reported both.
    assert metrics['context_available_tokens'] == CONTEXT_BUDGET
    assert metrics['context_required_tokens'] > metrics['context_available_tokens']
    assert metrics['context_compressed_tokens'] <= metrics['context_available_tokens']
    assert metrics['removed_context_records'] > 0
    context = json.loads(captured['messages'][1]['content'])
    assert context['user_request'] == 'Authorized assessment of the local application.'
    assert context['authorization']['type'] == 'signed_grant'
    assert context['web_route_summary']['total'] == 63
    assert 0 < len(context['observations']['web_routes']) < 30
    assert context['available_endpoints']
    system = captured['messages'][0]['content']
    assert 'Allowed TCP ports: 18080.' in system
    assert 'exact human approval' in system and 'Never send credentials' in system


def test_e2e_web_fix7_still_stops_before_provider_when_context_cannot_fit(monkeypatch):
    captured = {}
    _install_model(monkeypatch, captured)
    state = {**_fix7_state(), 'model_context_tokens': 50}
    result = planner.adaptive_planning(state)
    assert not captured
    assert result['stop_reason'] == 'context_budget_exhausted'
    metrics = result['planner_metrics']
    assert metrics['context_available_tokens'] == 0
    assert metrics['context_required_tokens'] > 0
    assert 'context_integrity_violation' not in metrics


def test_e2e_web_fix7_hypothesis_refs_survive_route_summarization(monkeypatch):
    from src.adaptix.agents.evidence_context import evidence_key
    routes = _routes()
    shown = {}
    _install_model(monkeypatch, shown)
    planner.adaptive_planning(_fix7_state())
    visible = {row.get('evidence_ref') for row in
               json.loads(shown['messages'][1]['content'])['observations']['web_routes']}
    hidden = [evidence_key('web_routes', row) for row in routes
              if evidence_key('web_routes', row) not in visible]
    assert hidden, 'summarization must leave most of the 63-route inventory out of the prompt'
    captured = {}
    _install_model(monkeypatch, captured)
    state = _fix7_state()
    state['hypotheses'] = [{'category': 'idor_bola', 'target': f'{BASE}/app/section-9/resource-9',
                            'rationale': 'listed route collection object', 'status': 'candidate',
                            'evidence_refs': hidden[:1]}]
    result = planner.adaptive_planning(state)
    assert result['planner_metrics']['mode'] == 'llm'
    merged = {ref for row in result['hypotheses'] for ref in row.get('evidence_refs', [])}
    assert hidden[0] in merged
    context = json.loads(captured['messages'][1]['content'])
    assert context['web_route_summary']['total'] == 63
    assert len(context['observations']['web_routes']) < 30
