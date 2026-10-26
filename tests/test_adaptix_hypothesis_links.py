"""Hypothesis-driven testing: the planner must connect observations, hypotheses,
evidence contracts and executable actions honestly - never by hardcoding tactics."""
import json

from tests.test_adaptix_planning_recovery import _decision, _install, _state
from src.adaptix.agents import planner
from src.adaptix.agents.capabilities import capability_contract
from src.adaptix.agents.hypotheses import update_hypotheses
from src.adaptix.evidence.audit import checkpoint
from src.adaptix.evidence.verification import CONTRACT_REQUIREMENTS
from src.adaptix.reporting.report import _termination, final_report
from src.adaptix.workflow.graph import _timed

BASE = 'http://127.0.0.1:3000'


def _hyp_state(**over):
    return _state(hypotheses=[
        {'category': 'sql_injection', 'target': f'{BASE}/api/Addresss?q=x',
         'rationale': 'observed signature', 'evidence_refs': ['probe_traces:aa11'],
         'status': 'candidate'},
        {'category': 'idor_bola', 'target': f'{BASE}/books/v1/adaptix_private_x',
         'rationale': 'private named object', 'evidence_refs': ['probe_traces:bb22'],
         'status': 'inconclusive'},
        {'category': 'sqli-free-form', 'target': f'{BASE}/api/Cards',
         'rationale': 'model free text', 'evidence_refs': [], 'status': 'candidate'},
        {'category': 'nosql_injection', 'target': f'{BASE}/api/Cards',
         'rationale': 'done', 'evidence_refs': [], 'status': 'supported'},
    ], probe_traces=[
        {'url': f'{BASE}/api/Addresss?q=x', 'path_key': f'{BASE}/api/Addresss', 'method': 'GET',
         'status_code': 401, 'payload': 'x', 'parameter': 'q', 'detected': []},
    ], **over)


def test_capability_contract_exposes_runtime_http_inputs():
    contract = capability_contract(_state(), ['http_request'])
    inputs = contract['http_request'].get('inputs') or {}
    assert inputs['methods_without_approval'] == ['GET', 'HEAD']
    assert inputs['methods_with_human_approval'] == ['POST', 'PUT', 'PATCH', 'DELETE']
    assert inputs['body_max_chars'] == 600
    assert 'hypothesis_field' in inputs


def test_hypothesis_tests_link_open_hypotheses_to_their_evidence_contracts():
    rows = planner.hypothesis_tests(_hyp_state())
    by_target = {row['target']: row for row in rows}
    sqli = by_target[f'{BASE}/api/Addresss?q=x']
    assert sqli['verification_contract'] == 'differential_injection'
    assert 'control' in (sqli['required_evidence'] or '')
    assert sqli['probed']['status_code'] == 401
    assert 'probe_traces:' in sqli['probed']['evidence_ref']
    bola = by_target[f'{BASE}/books/v1/adaptix_private_x']
    assert bola['verification_contract'] == 'private_object_access'
    assert 'two-identity' in (bola['required_evidence'] or '')
    # An analyst free-text class keeps its row and stays honest about being
    # unconfirmable today: no invented verification contract.
    free = [row for row in rows if row['category'] == 'sqli-free-form']
    assert free and 'verification_contract' not in free[0]
    # Completed hypotheses are not re-planned as tests.
    assert all(row['target'] != f'{BASE}/api/Cards' or row['category'] != 'nosql_injection'
               for row in rows)
    for row in rows:
        basis = row.get('verification_contract')
        if basis:
            assert row['required_evidence'] == CONTRACT_REQUIREMENTS[basis]


def test_probed_signatureless_hypothesis_is_inconclusive_never_refuted():
    result = update_hypotheses(_hyp_state())
    statuses = {(row['category'], row['status']) for row in result}
    # A probe that answered without a supporting signature leaves its hypothesis
    # inconclusive (another input shape may still decide it) - never refuted.
    assert ('sql_injection', 'inconclusive') in statuses
    assert not any(status == 'refuted' for _, status in statuses)


def test_planner_context_carries_hypothesis_tests(monkeypatch):
    calls = _install(monkeypatch, [_decision([])])
    planner.adaptive_planning(_hyp_state(planner_retry_limit=0))
    user_prompt = calls[0]['messages'][1]['content']
    assert 'hypothesis_tests' in user_prompt
    assert 'private_object_access' in user_prompt or 'required_evidence' in user_prompt


def test_checkpoint_refuses_a_foreign_session_overwrite(tmp_path, monkeypatch):
    import time as _time
    monkeypatch.setattr('src.adaptix.evidence.audit.artifact_path',
                        lambda state, stage, key, ext: tmp_path / f'{stage}.{ext}')
    first = _time.time()
    state_a = {'run_id': 'guard-checkpoint', 'iterations': 1, 'run_started_at': first,
               'events': []}
    assert checkpoint(state_a)
    # A different session (diagnostic replay) must not rewrite another run's evidence.
    state_b = {'run_id': 'guard-checkpoint-replay', 'iterations': 1,
               'run_started_at': first + 1200.0, 'events': []}
    assert checkpoint(state_b) is None
    # The same session may still rewrite its own checkpoint.
    assert checkpoint({**state_a, 'iterations': 1})


def test_termination_reports_time_exhaustion_when_the_clock_ran_out():
    import time as _time
    state = {'stop_reason': 'budget_insufficient_for_candidates',
             'run_started_at': _time.time() - 1000.0, 'time_budget_seconds': 780.0,
             'planner_metrics': {'mode': 'llm'}}
    termination = _termination(state, 'budget_insufficient_for_candidates')
    assert termination['run_time_exhausted'] is True
    assert termination['cause'] == 'run_time_exhaustion'
    # Token exhaustion with time remaining keeps its own cause.
    state = {'stop_reason': 'budget_exhausted',
             'run_started_at': _time.time() - 120.0, 'time_budget_seconds': 780.0,
             'planner_metrics': {'mode': 'stopped_budget_exhausted'}}
    termination = _termination(state, 'budget_exhausted')
    assert termination['cause'] == 'budget_exhausted'
    assert termination['run_time_exhausted'] is False


def test_final_report_metrics_summarize_executions_and_unrecorded_wall_time():
    state = {'run_id': 'phase-metrics', 'phase_runtime': [
                 {'pass': 0, 'phase': 'adaptive_planning', 'seconds': 40.0},
                 {'pass': 0, 'phase': 'execute_action', 'seconds': 2.0},
                 {'pass': 0, 'phase': 'final_report', 'seconds': 0.1}],
             'action_outcomes': [{'action': {'tool': 'http_request', 'target': f'{BASE}/api/A'}},
                                 {'action': {'tool': 'http_request', 'target': f'{BASE}/api/B'}},
                                 {'action': {'tool': 'web_discover', 'target': BASE}}],
             'metrics': {'planner_seconds': 39.0},
             'run_started_at': 0.0, 'time_budget_seconds': 100.0, 'planner_metrics': {}}
    report = final_report(state)
    metrics = report['report']['metrics']
    assert metrics['executions_by_tool'] == {'http_request': 2, 'web_discover': 1}
    assert metrics['recorded_phase_seconds'] == 42.1
    assert 'outside_recorded_phases_seconds' in metrics


def test_timed_phase_wrapper_records_and_carries_prior_rows():
    def node(state):
        return {'iterations': state.get('iterations', 0) + 1}
    wrapped = _timed('execute_action', node)
    result = wrapped({'iterations': 0,
                      'phase_runtime': [{'pass': 7, 'phase': 'scope_guard', 'seconds': 0.5}]})
    rows = result['phase_runtime']
    assert rows[0]['phase'] == 'scope_guard'
    assert rows[-1]['phase'] == 'execute_action'
    assert rows[-1]['pass'] == 0 and rows[-1]['seconds'] >= 0


def test_graph_pipeline_records_phase_runtime(monkeypatch):
    """One offline graph pass must produce attributable per-phase timing rows."""
    from src.adaptix.workflow.graph import graph
    from src.adaptix.agents import planner
    from src.adaptix.tools import httpx as ht, nuclei as nu, playwright as pw
    from src.adaptix.tools import registry as reg
    from unittest.mock import MagicMock
    fake_registry = lambda: {
        'httpx': {'path': '/bin/httpx', 'enabled': True},
        'nuclei': {'path': '/bin/nuclei', 'enabled': True},
        'playwright': {'path': None, 'enabled': False}}
    for mod in (ht, nu, pw, planner, reg):
        monkeypatch.setattr(mod, 'tool_registry', fake_registry)

    def fake_run(argv, timeout=45, stdin=None):
        if 'httpx' in argv[0]:
            payload = json.dumps({'url': 'http://127.0.0.1:18080', 'status_code': 200}) + '\n'
        else:
            payload = json.dumps({'matched-at': 'http://127.0.0.1:18080/',
                                  'template-id': 'adaptix-http-baseline', 'info': {'severity': 'info'}}) + '\n'
        return {'returncode': 0, 'stdout': payload, 'stderr': ''}
    for mod in (ht, nu):
        monkeypatch.setattr(mod, 'run_tool', fake_run)
    empty = {'actions': [], 'reflection': 'Assess stored evidence and remaining limits',
             'rationale': 'no untested evidence', 'hypotheses': [],
             'review': {'goal_status': 'in_progress', 'evidence_refs': [], 'uncertainty': 'none stored',
                        'failure': '', 'decision_change': 'replan'}}
    decisions = iter([empty, empty, empty])
    def completion(**kwargs):
        mock = MagicMock()
        mock.choices[0].message.content = json.dumps(next(decisions))
        mock.usage.total_tokens = 60
        mock.usage.prompt_tokens = 40
        mock.usage.completion_tokens = 20
        return mock
    monkeypatch.setattr(planner.litellm, 'completion', completion)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 120)
    state = graph.invoke({'target': ['127.0.0.1'], 'authorization_confirmed': True,
                          'run_id': 'phase-runtime-check', 'errors': [], 'events': [],
                          'max_iterations': 2, 'tool_call_budget': 10, 'token_budget': 4000},
                         config={'recursion_limit': 100})
    phases = state['phase_runtime']
    names = [row['phase'] for row in phases]
    assert 'scope_guard' in names and 'adaptive_planning' in names
    assert 'final_report' in names or 'blocked_report' in names
    assert all(row['seconds'] >= 0 for row in phases)
    assert state['report']['metrics']['recorded_phase_seconds'] > 0


def test_authorization_hypothesis_states_whether_the_run_can_decide_it():
    rows = planner.hypothesis_tests(_hyp_state())
    row = {r['target']: r for r in rows}[f'{BASE}/books/v1/adaptix_private_x']
    assert row['verification_contract'] == 'private_object_access'
    # No operator two-identity context: the row must say so plainly instead of
    # inviting a probe that can only end inconclusive.
    assert row['testable_now'] is False
    assert 'two-identity' in row['missing_grounding']

    ready = _hyp_state(identity_context={'identities': [
        {'name': 'owner', 'headers': {'Cookie': 'a'}}, {'name': 'other', 'headers': {'Cookie': 'b'}}],
        'private_fields': ['email'], 'identity_json_path': 'data.email'})
    row = {r['target']: r for r in planner.hypothesis_tests(ready)}[f'{BASE}/books/v1/adaptix_private_x']
    assert row['testable_now'] is True
    assert 'missing_grounding' not in row


def test_signature_hypotheses_are_testable_without_identity_context():
    rows = planner.hypothesis_tests(_hyp_state())
    sqli = {r['target']: r for r in rows}[f'{BASE}/api/Addresss?q=x']
    assert sqli['testable_now'] is True


def test_capability_inputs_advertise_identity_names_from_operator_config():
    state = _state(identity_context={'identities': [
        {'name': 'owner', 'headers': {'Cookie': 'a'}}, {'name': 'other', 'headers': {'Cookie': 'b'}}]})
    inputs = capability_contract(state, ['http_request'])['http_request']['inputs']
    assert inputs['identity_names'] == ['other', 'owner']
    assert 'headers arrive from operator configuration' in inputs['identity_field']
