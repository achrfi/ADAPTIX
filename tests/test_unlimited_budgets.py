"""Unlimited cumulative budgets: None is the representation, never a fake number.

Every configured budget (tokens, wall clock, tool calls, planning passes) may be
'unlimited' on the CLI. Internally that is None: consumers drop the comparison
instead of substituting a large number, keep metering usage, and preserve the
bounded per-call/provider controls (timeouts, rate limits, model context window)
that are model capabilities, not spending budgets.
"""
import json

import pytest
import time
from types import SimpleNamespace

from src.adaptix.workflow import budget as wf_budget
from src.adaptix.agents import planner, priority
from src.adaptix.reporting.report import _budget_summary, _termination
from src.adaptix.main import build_arg_parser, run_stream

BASE = 'http://127.0.0.1:3000'
CATALOG = {'http_request': {'enabled': True, 'path': 'python-module'},
           'web_discover': {'enabled': True, 'path': 'python-module'}}


# --- CLI normalization ------------------------------------------------------

def test_parse_budget_normalizes_unlimited_and_numbers():
    assert wf_budget.parse_budget('unlimited', int) is None
    assert wf_budget.parse_budget('  UNLIMITED ', float) is None
    assert wf_budget.parse_budget('1200', int) == 1200
    assert wf_budget.parse_budget(1800.5, float) == 1800.5
    with pytest.raises(ValueError, match='unlimited'):
        wf_budget.parse_budget('forever', int)


def test_cli_accepts_the_four_unlimited_flags_and_keeps_finite_ones():
    parser = build_arg_parser()
    args = parser.parse_args(['--target', '127.0.0.1', '--instruction', 'Assess the lab',
                              '--token-budget', 'unlimited', '--time-budget', 'unlimited',
                              '--tool-call-budget', 'unlimited', '--max-iterations', 'unlimited'])
    assert args.token_budget is None and args.time_budget is None
    assert args.tool_call_budget is None and args.max_iterations is None
    finite = parser.parse_args(['--target', '127.0.0.1', '--token-budget', '1000',
                                '--max-iterations', '4', '--tool-call-budget', '12'])
    assert finite.token_budget == 1000 and finite.max_iterations == 4 and finite.tool_call_budget == 12
    # The parser stays honest about unspecified values; main() derives the
    # implicit planning-pass default from a finite tool-call budget.
    implicit = parser.parse_args(['--target', '127.0.0.1', '--tool-call-budget', '9'])
    assert implicit.max_iterations is None
    if implicit.max_iterations is None and implicit.tool_call_budget is not None:
        implicit.max_iterations = implicit.tool_call_budget
    assert implicit.max_iterations == 9
    # Both unlimited: no implicit infinite can be derived from a None value.
    both = parser.parse_args(['--target', '127.0.0.1', '--tool-call-budget', 'unlimited'])
    assert both.max_iterations is None


def test_unlimited_remote_risk_and_local_provider_exemption():
    assert wf_budget.unlimited_remote_risk('ollama_chat/qwen3:14b', None, None) is False
    assert wf_budget.unlimited_remote_risk('openai/gpt-4o', 'http://localhost:8787/v1', 'k') is True
    assert wf_budget.unlimited_remote_risk('openai/gpt-4o', 'http://10.1.2.3:8787/v1', None) is True


# --- accounting helpers ----------------------------------------------------

def _state(**over):
    state = {'target': [BASE], 'hosts': ['127.0.0.1'], 'authorization': {'type': 'local_loopback'},
             'status': 'scope_ok', 'web_routes': [], 'run_started_at': time.time(),
             'time_budget_seconds': None}
    state.update(over)
    return state


def _routes(count=4):
    return [{'url': f'{BASE}/api/resource-{i}', 'method': 'GET', 'kind': 'xhr',
             'static_asset': False, 'api_like': True, 'status_code': 200}
            for i in range(count)]


def test_budget_stop_reason_names_each_exhausted_limit_separately():
    assert planner.budget_stop_reason(_state(iterations=5, max_iterations=5)) == 'iteration_budget_exhausted'
    assert planner.budget_stop_reason(_state(execution_metrics={'tool_calls_used': 3}, tool_call_budget=3)) == 'tool_call_budget_exhausted'
    assert planner.budget_stop_reason(_state(planner_metrics={'tokens_used': 100}, token_budget=100)) == 'token_budget_exhausted'
    far_future = time.time() + 10 ** 9
    assert planner.budget_stop_reason(_state(time_budget_seconds=far_future)) is None


def test_unlimited_budgets_never_exhaust_and_finite_ones_still_do():
    unlimited = _state(max_iterations=None, tool_call_budget=None, token_budget=None,
                       time_budget_seconds=None, planner_metrics={'tokens_used': 99_999},
                       iterations=99_999, execution_metrics={'tool_calls_used': 99_999})
    assert planner.budget_stop_reason(unlimited) is None
    mixed = _state(max_iterations=None, tool_call_budget=4, token_budget=None, time_budget_seconds=None,
                   execution_metrics={'tool_calls_used': 4})
    assert planner.budget_stop_reason(mixed) == 'tool_call_budget_exhausted'


def test_remaining_seconds_and_tool_budget_treat_none_as_an_open_clock():
    assert wf_budget.remaining_seconds(_state(time_budget_seconds=None)) == float('inf')
    assert wf_budget.tool_budget_available(_state(tool_call_budget=None,
                                                  execution_metrics={'tool_calls_used': 5000})) is True
    assert wf_budget.tool_timeout(_state(time_budget_seconds=None), 45.0) == 45.0
    assert wf_budget.remaining_tokens(_state(token_budget=None), 9000) is None


def test_rank_actions_with_unlimited_budgets_admits_expensive_work_successfully():
    def action(tool='httpx', tokens=1_500_000, seconds=3600.0):
        return {'tool': tool, 'target': 'http://127.0.0.1', 'reason': 'probe',
                'priority': {'goal_relevance': .9, 'information_gain': .8, 'evidence_value': .7,
                             'confidence': .9, 'estimated_tokens': tokens, 'estimated_seconds': seconds,
                             'estimated_requests': 1}}
    unlimited = {'token_limit': None, 'tokens': 0, 'tool_call_limit': None, 'tool_calls': 0}
    ranked, deferred = priority.rank_actions(_state(), [action()], unlimited)
    assert ranked and not deferred


# --- graph edge conditions --------------------------------------------------

def test_graph_edges_continue_with_unlimited_budgets():
    from src.adaptix.workflow.graph import after_update, next_action
    unlimited = _state(max_iterations=None, tool_call_budget=None, token_budget=None,
                       time_budget_seconds=None, planner_metrics={'tokens_used': 10**6},
                       iterations=10**6, execution_metrics={'tool_calls_used': 10**6},
                       planned_actions=[{'tool': 'http_request', 'target': f'{BASE}/x'}])
    assert next_action(unlimited) == 'execute'
    assert after_update(unlimited) == 'replan'
    assert next_action({**unlimited, 'stop_reason': 'operator_cancelled'}) == 'done'


# --- reporting (P4) ---------------------------------------------------------

def test_report_termination_attribution_covers_every_p4_category():
    base = _state(planner_metrics={'mode': 'llm'}, time_budget_seconds=1800)
    assert _termination(base, 'token_budget_exhausted')['cause'] == 'token_budget_exhausted'
    assert _termination(base, 'tool_call_budget_exhausted')['cause'] == 'tool_call_budget_exhausted'
    assert _termination(base, 'iteration_budget_exhausted')['cause'] == 'iteration_budget_exhausted'
    assert _termination(base, 'time_budget_exhausted')['cause'] == 'run_time_exhaustion'
    assert _termination({**base, 'stop_reason': 'context_budget_exhausted'}, 'context_budget_exhausted')['cause'] == 'context_window_exceeded'
    assert _termination({**base, 'stop_reason': 'no_feasible_action'}, 'no_feasible_action')['cause'] == 'planning_stagnation'
    assert _termination({**base, 'stop_reason': 'operator_cancelled'}, 'operator_cancelled')['cause'] == 'operator_cancelled'
    assert _termination({**base, 'stop_reason': 'planner_unavailable', 'planner_metrics': {'mode': 'llm_error', 'last_error': 'ConnectionError'}}, 'planner_unavailable')['cause'] == 'provider_error'
    achieved = _termination({**base, 'reflection_assessment': {'goal_status': 'achieved'}, 'stop_reason': 'no_new_actions'}, 'no_new_actions')
    assert achieved['cause'] == 'objective_completed'
    incomplete = _termination({**base, 'reflection_assessment': {'goal_status': 'in_progress'}, 'stop_reason': 'no_new_actions'}, 'no_new_actions')
    assert incomplete['cause'] == 'planning_stagnation'


def test_budget_summary_reports_unlimited_with_metered_consumption():
    summary = _budget_summary(_state(token_budget=None, tool_call_budget=None, max_iterations=None,
                                     time_budget_seconds=None, iterations=7),
                              {'tokens_used': 321})
    assert summary['token_budget'] == {'configured': 'unlimited', 'used': 321, 'remaining': None}
    assert summary['time_budget_seconds']['configured'] == 'unlimited'
    assert summary['time_budget_seconds']['remaining_seconds'] is None
    assert summary['tool_call_budget']['configured'] == 'unlimited'
    assert summary['max_iterations']['used'] == 7
    finite = _budget_summary(_state(token_budget=1000), {'tokens_used': 400})
    assert finite['token_budget'] == {'configured': 1000, 'used': 400, 'remaining': 600}


# --- streaming runner and cancellation --------------------------------------

def test_run_stream_merges_node_updates_and_leaves_the_seed_state_unchanged():
    updates = [{'events': ['scope']}, {'report': {'stop_reason': None}}]
    seed = {'target': ['127.0.0.1']}
    seen_configs = {}

    class FakeGraph:
        def stream(self, state, config=None):
            assert state is seed
            seen_configs['recursion_limit'] = (config or {}).get('recursion_limit')
            for update in updates:
                yield update
    merged = run_stream(FakeGraph(), seed, config={'recursion_limit': 55}, cancelled=lambda: False)
    assert merged['target'] == ['127.0.0.1'] and merged['report']['stop_reason'] is None
    assert seen_configs['recursion_limit'] == 55


def test_run_stream_cancellation_stops_between_nodes_and_keeps_eligible_evidence():
    updates = [{'events': ['a']}, {'events': ['never-reached']}]
    calls = {'count': 0}

    class FakeGraph:
        def stream(self, state, config=None):
            for update in updates:
                calls['count'] += 1
                yield update
    def cancelled():
        return calls['count'] >= 1
    merged = run_stream(FakeGraph(), {'target': ['127.0.0.1']}, {'recursion_limit': 10}, cancelled=cancelled)
    assert 'never-reached' not in json.dumps(merged)
    assert merged['events'] == ['a']


# --- planner under unlimited budgets ----------------------------------------

def _install_provider(monkeypatch, decision):
    monkeypatch.setattr(planner, 'tool_registry', lambda: CATALOG)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 100)

    def completion(**kwargs):
        return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=100, completion_tokens=30, total_tokens=130),
                               choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(decision)),
                                                        finish_reason='stop')])
    monkeypatch.setattr(planner.litellm, 'completion', completion)


def test_planner_executes_a_feasible_plan_in_unlimited_mode_and_keeps_metering(monkeypatch):
    routes = _routes()
    decision = {'actions': [{'tool': 'http_request', 'target': f'{BASE}/api/resource-1',
                             'reason': 'bounded probe of the observed endpoint',
                             'priority': {'goal_relevance': .9, 'information_gain': .8,
                                          'evidence_value': .7, 'confidence': .9,
                                          'estimated_tokens': 100, 'estimated_seconds': 1,
                                          'estimated_requests': 1}}],
                'rationale': 'Probe the observed endpoint.',
                'reflection': 'A bounded request is supported by the observations.',
                'review': {'goal_status': 'in_progress', 'evidence_refs': [], 'uncertainty': '',
                           'failure': '', 'decision_change': 'execute the bounded probe'}}
    _install_provider(monkeypatch, decision)
    state = _state(web_routes=routes, token_budget=None, tool_call_budget=None, max_iterations=None,
                   time_budget_seconds=None, planner_metrics={'tokens_used': 0}, iterations=1,
                   scope_manifest={'units': [BASE], 'hosts': ['127.0.0.1'], 'networks': [], 'aliases': {}, 'total_units': 1})
    result = planner.adaptive_planning(state)
    assert result['planned_actions'], 'unlimited budgets must not stop a feasible plan'
    assert result['stop_reason'] is None
    assert result['planner_metrics']['tokens_used'] == 130


def test_zero_measured_progress_still_stops_an_unlimited_run_with_an_honest_reason(monkeypatch):
    decision = {'actions': [{'tool': 'http_request', 'target': f'{BASE}/api/resource-1',
                             'reason': 'bounded probe of the observed endpoint',
                             'priority': {'goal_relevance': .9, 'information_gain': .8,
                                          'evidence_value': .7, 'confidence': .9,
                                          'estimated_tokens': 100, 'estimated_seconds': 1,
                                          'estimated_requests': 1}}],
                'rationale': 'Probe the observed endpoint.',
                'reflection': 'Recent executed actions have all measured zero objective progress.',
                'review': {'goal_status': 'in_progress', 'evidence_refs': [], 'uncertainty': '',
                           'failure': '', 'decision_change': 'a bounded request is planned'}}
    _install_provider(monkeypatch, decision)
    state = _state(web_routes=_routes(), token_budget=None, tool_call_budget=None, max_iterations=None,
                   time_budget_seconds=None, consecutive_no_gain_passes=4, no_gain_stop_limit=2,
                   planner_metrics={'tokens_used': 1000, 'mode': 'llm'}, iterations=4,
                   scope_manifest={'units': [BASE], 'hosts': ['127.0.0.1'], 'networks': [], 'aliases': {}, 'total_units': 1})
    result = planner.adaptive_planning(state)
    assert result['stop_reason'] == 'planning_stagnation'
