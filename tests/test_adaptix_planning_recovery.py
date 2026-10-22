"""Decision recovery: schema repair, bounded replanning and honest planning-failure reports.

The planner must never treat a formatting failure or an empty decision as a security
result, must keep the LLM in charge of strategy, and must stop with a diagnostic
planning failure instead of `no_new_actions` when it cannot decide.
"""
import inspect
import json
import time

import pytest
from pydantic import ValidationError

from src.adaptix.agents import decisions, planner, priority, reflector
from src.adaptix.agents.action_identity import execution_identity
from src.adaptix.agents.reflector import collect_findings
from src.adaptix.agents.schema import PlannerDecision
from src.adaptix.reporting.report import _termination, final_report
from src.adaptix.security.action_policy import approval_for

BASE = 'http://127.0.0.1:3000'
CATALOG = {'http_request': {'enabled': True, 'path': 'python-module'},
           'web_discover': {'enabled': True, 'path': 'python-module'},
           'nmap': {'enabled': True, 'path': '/usr/bin/nmap'}}


def _priority(**over):
    value = {'goal_relevance': .9, 'information_gain': .8, 'evidence_value': .7, 'confidence': .9,
             'estimated_tokens': 120, 'estimated_seconds': .5, 'estimated_requests': 1}
    value.update(over)
    return value


def _action(tool='http_request', target=None, **priority_over):
    return {'tool': tool, 'target': target or f'{BASE}/api/orders',
            'reason': 'bounded follow-up on observed evidence',
            'priority': _priority(**priority_over)}


def _decision(actions=(), **over):
    payload = {'actions': list(actions), 'rationale': 'Evidence-driven next step',
               'reflection': 'Assess stored evidence and remaining limits',
               'review': {'goal_status': 'in_progress', 'evidence_refs': [], 'uncertainty': '',
                          'failure': '', 'decision_change': 'Continue the bounded assessment'}}
    payload.update(over)
    return payload


def _routes(count=6):
    return [{'url': f'{BASE}/api/resource-{i}', 'method': 'GET', 'kind': 'xhr',
             'static_asset': False, 'api_like': True, 'status_code': 200}
            for i in range(count)]


def _state(**over):
    state = {'target': [BASE], 'hosts': ['127.0.0.1'], 'scope_ports': [3000],
             'authorization': {'type': 'local_loopback'}, 'status': 'scope_ok',
             'max_iterations': 8, 'tool_call_budget': 10, 'token_budget': 50000,
             'web_routes': _routes()}
    state.update(over)
    return state


def _response(payload, finish='stop'):
    content = payload if isinstance(payload, str) else json.dumps(payload)
    return {'choices': [{'message': {'content': content}, 'finish_reason': finish}],
            'usage': {'prompt_tokens': 100, 'completion_tokens': 30, 'total_tokens': 130}}


def _model_response(payload, finish='stop'):
    from types import SimpleNamespace
    content = payload if isinstance(payload, str) else json.dumps(payload)
    return SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=100, completion_tokens=30, total_tokens=130),
        choices=[SimpleNamespace(message=SimpleNamespace(content=content), finish_reason=finish)])


def _install(monkeypatch, payloads):
    """Scripted provider: one JSON payload (or exception) per call, oldest first."""
    monkeypatch.setattr(planner, 'tool_registry', lambda: CATALOG)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 100)
    calls = []

    def completion(**kwargs):
        calls.append(kwargs)
        item = payloads[min(len(calls) - 1, len(payloads) - 1)]
        if isinstance(item, Exception):
            raise item
        return _model_response(item)

    monkeypatch.setattr(planner.litellm, 'completion', completion)
    return calls


# A. An out-of-range priority is a formatting error, not a stop and not a fallback.
def test_priority_above_one_is_repaired_within_the_same_pass(monkeypatch):
    route = _routes()[0]['url']
    calls = _install(monkeypatch, [_decision([_action('http_request', route, goal_relevance=1.5)]),
                                   _decision([_action('http_request', route)])])
    result = planner.adaptive_planning(_state(planner_retry_limit=1))
    assert len(calls) == 2
    assert [row['tool'] for row in result['planned_actions']] == ['http_request']
    assert result['stop_reason'] is None
    assert result['consecutive_schema_failures'] == 0
    failed = [row for row in result['token_ledger'] if row.get('error_class') == 'validation']
    assert failed
    assert failed[0]['validation_fields'] == [
        {'field': 'actions.0.priority.goal_relevance', 'type': 'less_than_equal'}]


# B. The repair explains the schema failure and keeps the original request intact.
def test_validation_repair_preserves_objective_and_evidence(monkeypatch):
    route = _routes()[0]['url']
    calls = []
    payloads = [_decision([_action('http_request', route, goal_relevance=1.2)]),
                _decision([_action('http_request', route)])]

    def completion(**kwargs):
        calls.append(kwargs)
        return _model_response(payloads[min(len(calls) - 1, 1)])

    monkeypatch.setattr(decisions.litellm, 'completion', completion)
    monkeypatch.setattr(decisions.litellm, 'token_counter', lambda **kw: 80)
    kwargs = {'model': 'ollama_chat/qwen3:9b',
              'messages': [{'role': 'system', 'content': 'SYSTEM'},
                           {'role': 'user',
                            'content': 'Assess authorization on http://127.0.0.1:3000/api/orders'}],
              'max_tokens': 512, 'timeout': 30}
    decision, metrics, cache, ledger, error = decisions.request_decision(
        {'planner_retry_limit': 2, 'token_budget': 40000}, kwargs, {}, 80)
    assert decision is not None and error is None
    assert len(calls) == 2
    assert calls[1]['messages'][:2] == calls[0]['messages'][:2]
    repair = calls[1]['messages'][-1]['content']
    assert 'objective and observed evidence' in repair
    assert 'failed Pydantic validation, not authorization' in repair
    assert 'less_than_equal' in repair
    assert 'must be within 0.0 to 1.0' in repair
    assert 'do not treat this formatting error as a reason to stop the assessment' in repair
    assert 'Do not fabricate security observations' in repair
    for phrase in ('review.decision_change', 'including stopping', 'absent failure/uncertainty'):
        assert phrase in repair
    entry = [row for row in ledger if row.get('error_class') == 'validation'][0]
    assert entry['validation_fields'] == [
        {'field': 'actions.0.priority.goal_relevance', 'type': 'less_than_equal'}]


# C. Re-proposing reconnaissance after reconnaissance happened no longer stalls in
# a directive loop: the recovery tier executes the top evidence-ranked alternative
# the feedback either way names, then the model's follow-up proposal runs normally.
def test_repeated_web_discover_after_reconnaissance_plans_a_route(monkeypatch):
    _install(monkeypatch, [_decision([_action('web_discover', BASE)]),
                           _decision([_action('http_request', _routes()[1]['url'])])])
    state = _state(attempted_actions=[{'tool': 'web_discover', 'target': BASE}])
    first = planner.adaptive_planning(state)
    denial = next(row for row in first['policy_feedback'] if row.get('code') == 'already_completed')
    assert denial['alternatives']
    recovery = first['planned_actions']
    assert [row['tool'] for row in recovery] == ['http_request']
    assert recovery[0]['action_source'] == 'policy_recovery'
    assert recovery[0]['target'] in [row['url'] for row in _routes()]
    assert recovery[0]['target'] != BASE
    second = planner.adaptive_planning({**state, **first})
    assert [row['tool'] for row in second['planned_actions']] == ['http_request']
    assert second['stop_reason'] is None


# D. After a completed action, the model may choose a different eligible target;
# the deterministic recovery keeps the pass from idling on the rejected repeat by
# trying the next unattempted observed route.
def test_completed_action_proposal_replans_to_a_different_route(monkeypatch):
    route_a, route_b = _routes()[0]['url'], _routes()[2]['url']
    _install(monkeypatch, [_decision([_action('http_request', route_a)]),
                           _decision([_action('http_request', route_b)])])
    state = _state(attempted_actions=[{'tool': 'http_request', 'target': route_a}])
    first = planner.adaptive_planning(state)
    recovery = first['planned_actions']
    assert [row['tool'] for row in recovery] == ['http_request']
    assert recovery[0]['action_source'] == 'policy_recovery'
    assert recovery[0]['target'] != route_a
    assert recovery[0]['target'] in [row['url'] for row in _routes()]
    second = planner.adaptive_planning({**state, **first})
    assert [row['target'] for row in second['planned_actions']] == [route_b]


# D4. tool_eligibility must agree with the alternatives: a configured named tool
# is reported eligible with its executable scenario names, never as 'no inputs'.
def test_capability_contract_reflects_named_tool_readiness():
    from src.adaptix.agents.capabilities import capability_contract
    scenarios = [{'name': 'vampi-private-book', 'base_url': f'{BASE}/books/v1/obj-1'}]
    state = _state(idor_scenarios=scenarios)
    contract = capability_contract(state, ['idor', 'http_request'])
    assert contract['idor']['eligible'] == 1
    assert contract['idor']['targets'] == ['vampi-private-book']
    # Without a configured scenario the tool is honestly reported as unusable.
    empty = capability_contract(_state(), ['idor'])
    assert empty['idor']['eligible'] == 0 and empty['idor']['missing']


# E. actions=[] while executable alternatives exist is a replan, never a result.
def test_empty_decision_with_alternatives_does_not_stop_the_run(monkeypatch):
    _install(monkeypatch, [_decision([])])
    state = _state(attempted_actions=[{'tool': 'web_discover', 'target': BASE}])
    result = planner.adaptive_planning(state)
    assert result['stop_reason'] is None
    assert result['planned_actions'] == []
    assert result['consecutive_empty_plans'] == 1
    directive = next(row for row in result['policy_feedback']
                     if row.get('code') == 'empty_decision_with_alternatives')
    assert directive['alternatives']
    assert directive['tools_with_eligible_inputs']


# D2. A configured named tool is executable advice too: it takes a scenario name, not an
# endpoint, so the URL-driven target scan can never surface it on its own. Leaving it out
# of alternatives is what let an authorization run circle through endpoint discovery
# without ever running the prepared ownership test.
def test_configured_named_tool_is_offered_when_url_probes_are_exhausted():
    catalog = {**CATALOG, 'idor': {'enabled': True, 'path': 'python-module'}}
    name, target = 'vampi-private-book', f'{BASE}/books/v1/obj-1'
    state = _state(idor_scenarios=[{'name': name, 'base_url': target}],
                   hypotheses=[{'category': 'broken_object_level_authorization',
                                'target': target, 'evidence_refs': ['EV-1']}])
    pairs = planner._alternatives(state, {'tool': 'http_request', 'target': None},
                                  sorted(catalog), limit=8)
    idor = [row for row in pairs if row['tool'] == 'idor']
    assert idor == [{'tool': 'idor', 'target': name, 'http_validated': False,
                     'tests_hypothesis': 'broken_object_level_authorization'}]
    # The pair is executable under the same guards as any other alternative.
    assert planner._approved_actions(state, [{'tool': 'idor', 'target': name}], sorted(catalog))

    # A scenario whose result is already recorded is never advertised again.
    executed = [{'tool': 'idor', 'target': name,
                 'execution_identity': execution_identity({'tool': 'idor', 'target': name}, {})}]
    done = planner._alternatives(_state(idor_scenarios=[{'name': name, 'base_url': target}],
                                        attempted_actions=executed),
                                 {'target': None}, ['idor'], limit=8)
    assert not [row for row in done if row['tool'] == 'idor']

    # An unavailable tool or an unsatisfiable named tool is never advertised.
    assert not [row for row in planner._alternatives(state, {'target': None}, ['http_request'])
                if row['tool'] == 'idor']
    # An unconfigured scenario name is never advertised as executable: the model's
    # own proposed pair is exactly the one the guard refuses.
    assert not [row for row in planner._alternatives(
        _state(idor_scenarios=[{'name': name, 'base_url': target}]),
        {'tool': 'idor', 'target': 'not-configured'}, ['idor'], limit=8)
        if row['target'] == 'not-configured']


# D3. A prepared scenario must not be cropped from the alternatives by the pair cap
# purely because the model has not voiced a hypothesis yet: while no hypothesis is
# open, named scenarios outrank generic endpoint probes instead of trailing them.
def test_named_scenario_not_cropped_when_no_hypothesis_is_open():
    catalog = {**CATALOG, 'idor': {'enabled': True, 'path': 'python-module'}}
    scenarios = [{'name': 'observed-scenario-0', 'base_url': f'{BASE}/books/v1/obj-0'}]
    pairs = planner._alternatives(_state(idor_scenarios=scenarios), {'target': None},
                                  sorted(catalog), limit=6)
    named = [row for row in pairs if row['tool'] == 'idor']
    assert named, 'a prepared scenario was cropped from the alternatives cap'
    # Unlinked named scenarios rank ahead of unlinked generic endpoint probes.
    generic = [row for row in pairs if row['tool'] not in ('scenario', 'idor')]
    assert generic and pairs.index(named[0]) < pairs.index(generic[0])
    # The scenario tool also needs the private-field policy, not just a candidate name.
    candidate = [{'name': 'observed-abc', 'url': f'{BASE}/orders/42'}]
    assert not [row for row in planner._alternatives(_state(scenario_candidates=candidate),
                                                     {'target': None}, ['scenario'], limit=8)
                if row['tool'] == 'scenario']


# F. Repeated failed replanning stops as a reported planning failure, not success.
def test_repeated_failed_replanning_stops_with_planning_failure(monkeypatch):
    _install(monkeypatch, [_decision([])])
    state = _state(attempted_actions=[{'tool': 'web_discover', 'target': BASE}],
                   consecutive_empty_plans=1)
    result = planner.adaptive_planning(state)
    assert result['stop_reason'] == 'planning_failure_no_decision'
    assert result['consecutive_empty_plans'] == 2
    assert any('replanning is exhausted' in message for message in result['errors'])
    assert _termination({**state, **result}, result['stop_reason'])['cause'] == 'planning_stagnation'
    report = final_report({**state, **result})
    assert report['status'] == 'completed_with_errors'
    diagnostics = report['report']['planning_diagnostics']
    assert diagnostics['zero_action_passes'] >= 1
    assert diagnostics['consecutive_empty_plans'] == 2
    assert 'not completed assessment coverage' in diagnostics['meaning']


# G. A schema failure and its repair never become a finding or a hypothesis.
def test_schema_failure_never_creates_a_finding(monkeypatch):
    route = _routes()[0]['url']
    _install(monkeypatch, [_decision([_action('http_request', route, goal_relevance=9)]),
                           _decision([])])
    state = _state(planner_retry_limit=1,
                   attempted_actions=[{'tool': 'web_discover', 'target': BASE}])
    result = planner.adaptive_planning(state)
    merged = {**state, **result}
    groups = collect_findings(merged)
    assert groups['verified_findings'] == []
    assert groups['rejected_findings'] == []
    assert groups['inconclusive_findings'] == []
    assert groups['findings'] == []
    assert not merged.get('candidates')
    assert merged.get('attempted_actions') == state['attempted_actions']
    validation_failures = [row for row in merged.get('token_ledger', [])
                           if row.get('error_class') == 'validation']
    assert validation_failures and validation_failures[0].get('result') == 'failed'


# H. Scope and human approval still bind every replanned alternative.
def test_scope_and_approval_still_bound_replanning(monkeypatch):
    outside = 'http://10.0.0.9/api/orders'
    verdict = planner.scope_assessment(_state(), _action('http_request', outside))
    assert verdict['allowed'] is False and verdict['code'] == 'url_outside_scope'
    _install(monkeypatch, [_decision([])])
    result = planner.adaptive_planning(_state(attempted_actions=[{'tool': 'web_discover',
                                                                  'target': BASE}]))
    directive = next(row for row in result['policy_feedback']
                     if row.get('code') == 'empty_decision_with_alternatives')
    for pair in directive['alternatives']:
        assert planner.scope_assessment(
            _state(), {'tool': pair['tool'], 'target': pair['target']})['allowed']
    # Capability is satisfied; only the guard refuses it, and approval is separate.
    assert planner.action_assessment(_state(), _action('http_request', outside),
                                     sorted(CATALOG))['eligible'] is True
    assert planner._approved_actions(_state(), [_action('http_request', outside)],
                                     sorted(CATALOG)) == []
    approval = approval_for({'run_id': 'r', 'principal': 'lab'},
                            {'tool': 'http_request', 'target': f'{BASE}/api/orders',
                             'method': 'POST'}, {'risk': 'state_change'})
    assert approval['result'] == 'denied'


# H. Alternatives answer the questions still being tested, not one generic list.
def test_alternatives_link_open_hypotheses_to_their_endpoint():
    state = _state(hypotheses=[{'category': 'idor_bola', 'target': f'{BASE}/api/resource-3',
                                'rationale': 'objects may be shared', 'evidence_refs': [],
                                'status': 'testing'}])
    pairs = planner._alternatives(state, {'target': None}, sorted(CATALOG), limit=6)
    linked = [row for row in pairs if row.get('tests_hypothesis') == 'idor_bola']
    assert linked and linked[0]['target'] == f'{BASE}/api/resource-3'


def test_alternatives_ignore_settled_hypotheses():
    state = _state(hypotheses=[{'category': 'idor_bola', 'target': f'{BASE}/api/resource-3',
                                'rationale': 'resolved', 'evidence_refs': [], 'status': 'refuted'}])
    pairs = planner._alternatives(state, {'target': None}, sorted(CATALOG), limit=6)
    assert not any(row.get('tests_hypothesis') for row in pairs)


def test_empty_decision_feedback_names_the_open_hypothesis(monkeypatch):
    state = _state(hypotheses=[{'category': 'idor_bola', 'target': f'{BASE}/api/resource-2',
                                'rationale': 'objects may be shared', 'evidence_refs': [],
                                'status': 'testing'}])
    _install(monkeypatch, [_decision([]), _decision([_action('http_request', f'{BASE}/api/resource-2')])])
    result = planner.adaptive_planning(state)
    directive = next(row for row in result['policy_feedback']
                     if row.get('code') == 'empty_decision_with_alternatives')
    assert directive['tests_hypothesis'] == 'idor_bola'
    assert any(pair.get('tests_hypothesis') == 'idor_bola' for pair in directive['alternatives'])


# I. Recovery carries no vulnerability catalogue, payload list or fixed attack order.def test_no_static_attack_sequence_or_payload_catalogue(monkeypatch):
    from src.adaptix.agents import capabilities, priority as priority_module, progress
    from src.adaptix.reporting import report as report_module
    modules = (planner, capabilities, decisions, priority_module, reflector, progress, report_module)
    sources = '\n'.join(inspect.getsource(module) for module in modules).lower()
    for needle in ('union select', '<script', "' or 1=1", ' or 1=1', 'sqlmap', 'attack_chain',
                   'follow_up_tool', 'next_tool', 'command injection', 'payload_for', 'exploit_order'):
        assert needle not in sources
    state = _state(attempted_actions=[{'tool': 'web_discover', 'target': BASE}])
    pairs = planner._alternatives(state, {'target': None}, sorted(CATALOG), limit=4)
    assert pairs and all(row['target'].startswith(BASE) for row in pairs)
    # The tool that runs comes from the model, not from a fixed sequence.
    _install(monkeypatch, [_decision([_action('nmap', '127.0.0.1')])])
    result = planner.adaptive_planning(_state(hosts=['127.0.0.1']))
    assert [row['tool'] for row in result['planned_actions']] == ['nmap']


# J. Replanning and ranking stay inside the run's token, call and resource bounds.
def test_replanning_stays_inside_token_call_and_resource_budgets(monkeypatch):
    budget = {'iteration_limit': 10, 'tool_call_limit': 5, 'token_limit': 10000,
              'iterations': 0, 'tool_calls': 0, 'tokens': 0, 'seconds_remaining': 900}
    ranked, deferred = priority.rank_actions(_state(), [_action(estimated_tokens=10 ** 9)], budget)
    assert ranked == [] and deferred
    ranked, deferred = priority.rank_actions(_state(), [_action(goal_relevance=float('nan'))], budget)
    assert ranked == [] and deferred
    ranked, deferred = priority.rank_actions(
        _state(), [_action(estimated_seconds=float('inf'))], budget)
    assert ranked == [] and deferred
    with pytest.raises(ValidationError):
        PlannerDecision.model_validate(_decision([_action(estimated_tokens=10 ** 9)]))
    with pytest.raises(ValidationError):
        PlannerDecision.model_validate(_decision([_action(goal_relevance=float('nan'))]))
    with pytest.raises(ValidationError):
        PlannerDecision.model_validate(_decision([_action(estimated_seconds=float('inf'))]))
    calls = _install(monkeypatch, [_decision([])])
    exhausted = planner.adaptive_planning(_state(tool_call_budget=1,
                                                 execution_metrics={'tool_calls_used': 1}))
    assert calls == [] and exhausted['stop_reason'] == 'tool_call_budget_exhausted'
    calls = _install(monkeypatch, [_decision([])])
    spent = planner.adaptive_planning(_state(token_budget=50000,
                                             planner_metrics={'tokens_used': 60000}))
    assert calls == [] and spent['stop_reason'] == 'token_budget_exhausted'


# The planner and reflection separate decision failures from test outcomes.
def test_planning_failures_are_reported_separately_from_test_errors(monkeypatch):
    _install(monkeypatch, [_decision([])])
    state = _state(attempted_actions=[{'tool': 'web_discover', 'target': BASE}],
                   consecutive_empty_plans=1, errors=['httpx failed: connection refused'])
    result = planner.adaptive_planning(state)
    assert result['stop_reason'] == 'planning_failure_no_decision'
    reflection = reflector.reflection_verification({**state, **result})
    assert reflection['reflection']['planning']['consecutive_empty_plans'] == 2
    assert any('replanning is exhausted' in message
               for message in reflection['reflection']['planning_failures'])
    assert any('connection refused' in message for message in reflection['reflection']['errors'])
    assert 'not a security result' in reflection['reflection']['guidance']
    stagnation = planner.stagnation_report({**state, **result})
    assert stagnation['zero_action_plans'] >= 1
    assert stagnation['planning_passes'] >= 1


# The executor boundary must attribute a refused plan honestly: when run time is the
# binding constraint the stop is a time budget stop, and the deferral reason is
# recorded (evidence for diagnosis instead of an unexplained stop).
import time as _time


def _execute_state(priority_cost, seconds_used=10.0, time_budget=780.0):
    return {'target': ['127.0.0.1'], 'status': 'scope_ok',
            'authorization': {'type': 'local_loopback'}, 'hosts': ['127.0.0.1'],
            'time_budget_seconds': time_budget,
            'run_started_at': _time.time() - seconds_used,
            'planned_actions': [{'tool': 'http_request', 'target': f'{BASE}/api/Items',
                                 'method': 'GET',
                                 'priority': {'goal_relevance': 0.9, 'information_gain': 0.8,
                                              'evidence_value': 0.7, 'confidence': 0.6,
                                              'estimated_tokens': 500,
                                              'estimated_seconds': priority_cost,
                                              'estimated_requests': 1}}]}


def test_executor_reports_time_budget_stop_when_clock_is_the_binding_constraint():
    from src.adaptix.workflow.nodes import execute_action
    result = execute_action(_execute_state(priority_cost=4000.0, seconds_used=720.0))
    assert result['stop_reason'] == 'time_budget_exhausted'
    assert any('refused' in message for message in result['errors'])


def test_executor_records_the_refusal_reason_of_an_infeasible_plan():
    from src.adaptix.workflow.nodes import execute_action
    result = execute_action(_execute_state(priority_cost=760.0, seconds_used=30.0))
    assert result['stop_reason'] == 'budget_insufficient_for_candidates'
    assert any('Estimated cost does not fit remaining token/time/tool-call budget'
               in message for message in result['errors'])
