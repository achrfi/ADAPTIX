"""Regression coverage for adaptive evidence handling.

The failed e2e run collapsed six distinct ``?key=1``..``?key=6`` requests into one
stored trace, produced six near-identical ``idor_bola`` hypotheses, reported a
provider timeout when the run had actually exhausted its wall-clock budget, and
never stopped a zero-gain probing loop. These tests pin the fixes.
"""
import json
import time
from types import SimpleNamespace

import httpx

from src.adaptix.agents import hypotheses as hy
from src.adaptix.agents import planner
from src.adaptix.agents import decisions
from src.adaptix.agents.evidence_context import grouped_probe_traces
from src.adaptix.agents.progress import parameter_variation_no_gain, stagnation_report
from src.adaptix.processing.normalize import deduplicate
from src.adaptix.reporting.report import _termination
from src.adaptix.tools import web

BASE = 'http://127.0.0.1:18080'


def _response(url, body, content_type='application/json', status=200):
    return httpx.Response(status, headers={'content-type': content_type},
                          content=body.encode(), request=httpx.Request('GET', url))


def _state(**extra):
    state = {'run_id': 'adaptive-evidence', 'hosts': ['127.0.0.1'], 'scope_ports': [18080],
             'scope_manifest': {'hosts': ['127.0.0.1'], 'networks': [], 'aliases': {}},
             'execution_metrics': {}, 'raw_bytes': 0, 'errors': [], 'events': [],
             'tool_call_budget': 20, 'target': [BASE + '/']}
    state.update(extra)
    return state


def _probe(state, url, method='GET'):
    return web.http_request({**state, 'planned_actions': [
        {'tool': 'http_request', 'target': url, 'method': method}]})


# --- R1/R2: per-request evidence and separate request audit -----------------

def test_distinct_query_requests_are_separate_traces(monkeypatch):
    monkeypatch.setattr(web, '_request', lambda state, url, method='GET', body=None, identity_headers=None: _response(url, '[]'))
    state = _state()
    for key in range(1, 7):
        state.update(_probe(state, f'{BASE}/api/Challenges/?key={key}'))
    assert len(state['probe_traces']) == 6
    assert {row['payload'] for row in state['probe_traces']} == {str(i) for i in range(1, 7)}
    assert len({row['evidence_ref'] for row in state['probe_traces']}) == 6
    assert len(state['request_audit']) == 6
    assert len({row['request_fingerprint'] for row in state['request_audit']}) == 6


def test_exact_repeat_request_is_deduplicated(monkeypatch):
    monkeypatch.setattr(web, '_request', lambda state, url, method='GET', body=None, identity_headers=None: _response(url, 'ok'))
    state = _state()
    state.update(_probe(state, f'{BASE}/p?x=1'))
    state.update(_probe(state, f'{BASE}/p?x=1'))
    assert len(state['probe_traces']) == 1
    assert len(state['request_audit']) == 1


def test_probe_trace_record_key_includes_request_identity():
    first = {'path_key': BASE + '/p', 'method': 'GET', 'body_sha256': 'a' * 64,
             'request_fingerprint': 'fp-1', 'identity': None, 'request_body_sha256': None}
    second = {**first, 'request_fingerprint': 'fp-2'}
    rows = deduplicate('probe_traces', [first, second])
    assert len(rows) == 2


# --- R3: stagnation measurement and rejection -------------------------------

def test_parameter_variation_with_identical_responses_is_measured_as_stagnant():
    traces = [{'path_key': BASE + '/p', 'method': 'GET', 'parameter': 'key', 'url': f'{BASE}/p?key={i}',
               'request_fingerprint': f'fp{i}', 'status_code': 200, 'body_sha256': 'b' * 64, 'detected': []}
              for i in range(1, 3)]
    state = {'probe_traces': traces}
    assert parameter_variation_no_gain(state, {'tool': 'http_request', 'method': 'GET', 'target': f'{BASE}/p?key=3'})
    assert not parameter_variation_no_gain(state, {'tool': 'http_request', 'method': 'GET', 'target': f'{BASE}/p?id=3'})
    assert not parameter_variation_no_gain(state, {'tool': 'http_request', 'method': 'GET', 'target': f'{BASE}/other?key=3'})


def test_parameter_variation_with_different_response_is_not_stagnant():
    traces = [{'path_key': BASE + '/p', 'method': 'GET', 'parameter': 'q', 'url': f'{BASE}/p?q={i}',
               'request_fingerprint': f'fp{i}', 'status_code': 200, 'body_sha256': str(i) * 64, 'detected': []}
              for i in (1, 2)]
    assert not parameter_variation_no_gain({'probe_traces': traces},
                                           {'tool': 'http_request', 'method': 'GET', 'target': f'{BASE}/p?q=3'})


def test_action_rejection_blocks_zero_gain_value_variation():
    traces = [{'path_key': BASE + '/api/Challenges/', 'method': 'GET', 'parameter': 'key',
               'url': f'{BASE}/api/Challenges/?key={i}', 'request_fingerprint': f'fp{i}',
               'status_code': 200, 'body_sha256': 'b' * 64, 'detected': []} for i in range(1, 3)]
    state = _state(probe_traces=traces)
    action = {'tool': 'http_request', 'target': f'{BASE}/api/Challenges/?key=3', 'method': 'GET', 'priority': {}}
    reason = planner.action_rejection(state, action, {'http_request'})
    assert reason and 'information gain is zero' in reason


def test_stagnation_report_counts_consecutive_zero_gain():
    state = {'action_outcomes': [{'action': {'tool': 'http_request', 'target': 'u'}, 'goal_progress': 0, 'reason': 'no'},
                                 {'action': {'tool': 'http_request', 'target': 'u'}, 'goal_progress': 0, 'reason': 'no'}]}
    report = stagnation_report(state)
    assert report['consecutive_no_gain'] == 2 and len(report['recent']) == 2


# --- R5: grouped evidence for the model, full audit retained ----------------

def test_grouped_probe_traces_collapse_identical_responses():
    rows = [{'url': f'{BASE}/p?key={i}', 'path_key': BASE + '/p', 'method': 'GET', 'parameter': 'key',
             'payload': str(i), 'request_fingerprint': f'fp{i}', 'status_code': 200, 'body_sha256': 'b' * 64,
             'control': True, 'detected': [], 'evidence_ref': f'ref{i}'} for i in range(1, 7)]
    grouped = grouped_probe_traces({'probe_traces': rows})
    assert len(grouped) == 1
    assert grouped[0]['attempts'] == 6 and grouped[0]['identical_responses'] is True
    assert grouped[0]['values_tried'] == ['1', '2', '3', '4', '5', '6']
    assert len(grouped[0]['evidence_refs']) == 6
    assert len(rows) == 6  # nothing removed from the audit itself


# --- R4: hypothesis dedupe, provenance and authorization gate ---------------

def test_merge_hypotheses_collapses_path_level_duplicates():
    proposed = [{'category': 'idor_bola', 'target': f'{BASE}/api/Challenges/?key={i}'} for i in range(1, 7)]
    merged = hy.merge_hypotheses([], proposed)
    assert len(merged) == 1


def test_merge_hypotheses_drops_all_invalid_provenance():
    proposed = [{'category': 'sql_injection', 'target': BASE + '/p', 'evidence_refs': ['nope:1', 'nope:2']}]
    assert hy.merge_hypotheses([], proposed, valid_refs={'real:1'}) == []
    kept = hy.merge_hypotheses([], [{'category': 'sql_injection', 'target': BASE + '/p', 'evidence_refs': []}],
                               valid_refs={'real:1'})
    assert len(kept) == 1 and kept[0]['evidence_refs'] == []


def test_authorization_hypothesis_needs_two_identity_evidence_for_support():
    trace = {'url': BASE + '/x', 'path_key': BASE + '/x', 'method': 'GET', 'detected': []}
    hypothesis = {'category': 'idor_bola', 'target': BASE + '/x'}
    without = hy._status(hypothesis, [{'category': 'idor_bola', 'target': BASE + '/x',
                                       'verification_status': 'confirmed'}], [trace], [])
    assert without == 'inconclusive'
    with_identities = hy._status(hypothesis, [{'category': 'idor_bola', 'target': BASE + '/x',
                                               'verification_status': 'confirmed',
                                               'owner_identity': 'userA', 'other_identity': 'userB'}], [trace], [])
    assert with_identities == 'supported'


def test_manual_review_label_cannot_verify_authorization_without_identities():
    finding = {'verification_basis': 'private_object_access', 'verification_method': 'manual_review',
               'result': 'confirmed', 'reviewer': 'analyst', 'reason': 'looks broken',
               'requests': [], 'responses': []}
    from src.adaptix.agents.reflector import _private_object_evidence
    assert _private_object_evidence(finding) is None


# --- R6: reflection carries measured stagnation -----------------------------

def test_reflection_includes_stagnation_and_guidance(monkeypatch):
    from src.adaptix.agents import reflector
    monkeypatch.setattr(reflector, 'collect_findings', lambda state: {
        'verified_findings': [], 'rejected_findings': [], 'inconclusive_findings': []})
    state = _state(attempted_actions=[{'tool': 'http_request', 'target': 'u'}],
                   action_outcomes=[{'action': {'tool': 'http_request', 'target': 'u'},
                                     'goal_progress': 0, 'new_evidence_keys': ['k'], 'reason': 'no new evidence'},
                                    {'action': {'tool': 'http_request', 'target': 'u'},
                                     'goal_progress': 0, 'new_evidence_keys': [], 'reason': 'no new evidence'}])
    result = reflector.reflection_verification(state)
    assert result['reflection']['consecutive_no_gain'] == 2
    assert result['reflection']['last_outcome']
    assert 'measured progress' in result['reflection']['guidance']


# --- R9: deadline guard and provider ledger fields --------------------------

def test_deadline_guard_stops_before_provider_call(monkeypatch):
    monkeypatch.setattr(planner.litellm, 'completion',
                        lambda **kw: (_ for _ in ()).throw(AssertionError('must not call')))
    state = {'hosts': ['127.0.0.1'], 'run_started_at': time.time() - 10, 'time_budget_seconds': 30}
    result = planner.adaptive_planning(state)
    assert result['stop_reason'] == 'time_budget_exhausted'
    assert result['planner_metrics']['mode'] == 'stopped_deadline'


def test_provider_ledger_records_timeout_and_deadline_clamp(monkeypatch):
    def fail(**kw):
        raise TimeoutError('slow provider')
    monkeypatch.setattr(decisions.litellm, 'completion', fail)
    monkeypatch.setattr(decisions.litellm, 'token_counter', lambda **kw: 100)
    state = {'planner_retry_limit': 2, 'token_budget': 50000, 'run_started_at': time.time() - 10,
             'time_budget_seconds': 60, 'model_context_tokens': 4096}
    metrics = {'tokens_used': 0, 'llm_calls': 0}
    decision, metrics, cache, ledger, error = decisions.request_decision(
        state, {'model': 'x', 'messages': [{'role': 'user', 'content': 'hi'}], 'max_tokens': 128,
                'timeout': 180}, metrics, 100)
    assert decision is None
    entry, = [row for row in ledger if row.get('provider_call')]
    assert entry['timeout'] <= 60 and entry['deadline_clamped'] is True
    assert entry['run_seconds_remaining'] <= 60


# --- R8: termination distinguishes provider timeout from run-time exhaustion -

def test_termination_reports_run_time_exhaustion_for_clamped_timeout():
    state = {'planner_metrics': {'mode': 'llm_error', 'last_error': 'Timeout'},
             'token_ledger': [{'provider_call': True, 'error_type': 'Timeout', 'deadline_clamped': True,
                               'run_seconds_remaining': 12.0}],
             'run_started_at': time.time() - 60, 'time_budget_seconds': 60}
    termination = _termination(state, 'planner_unavailable')
    assert termination['provider_timeout'] is True
    assert termination['run_time_exhausted'] is True
    assert termination['cause'] == 'run_time_exhaustion'


def test_termination_keeps_plain_provider_timeout_distinct():
    state = {'planner_metrics': {'mode': 'llm_error', 'last_error': 'Timeout'},
             'token_ledger': [{'provider_call': True, 'error_type': 'Timeout', 'deadline_clamped': False,
                               'run_seconds_remaining': 1700.0}],
             'run_started_at': time.time(), 'time_budget_seconds': 1800}
    termination = _termination(state, 'planner_unavailable')
    assert termination['provider_timeout'] is True
    assert termination['run_time_exhausted'] is False
    assert termination['cause'] == 'provider_timeout'


def test_final_report_includes_request_audit_and_partial_status():
    from src.adaptix.reporting.report import final_report
    state = {**_state(), 'stop_reason': 'time_budget_exhausted',
             'planner_metrics': {'mode': 'stopped_deadline'},
             'run_started_at': time.time() - 10, 'time_budget_seconds': 30,
             'request_audit': [{'tool': 'http_request', 'request_fingerprint': 'fp'}]}
    report = final_report(state)['report']
    assert report['status'] == 'completed_partial'
    assert report['request_audit'][0]['request_fingerprint'] == 'fp'
    assert report['termination']['cause'] == 'run_time_exhaustion'


# --- R7/R5: planner payload exposes grouped evidence and uncertainty --------

def test_planner_payload_groups_probe_evidence_and_reports_uncertainty(monkeypatch):
    captured = {}
    monkeypatch.setattr(planner, 'tool_registry', lambda: {'httpx': {'enabled': True, 'path': 'cli'}})
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: sum(len(m['content']) for m in kw['messages']) // 4)

    def completion(**kw):
        captured.update(json.loads(kw['messages'][1]['content']))
        return SimpleNamespace(usage=SimpleNamespace(total_tokens=130, prompt_tokens=100, completion_tokens=30),
                               choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(
                                   {'actions': [], 'reflection': 'stop', 'rationale': 'done',
                                    'review': {'goal_status': 'uncertain', 'evidence_refs': [], 'uncertainty': 'x',
                                               'failure': '', 'decision_change': 'stop'}})))])
    monkeypatch.setattr(planner.litellm, 'completion', completion)
    traces = [{'url': f'{BASE}/p?key={i}', 'path_key': BASE + '/p', 'method': 'GET', 'parameter': 'key',
               'payload': str(i), 'request_fingerprint': f'fp{i}', 'status_code': 200, 'body_sha256': 'b' * 64,
               'control': True, 'detected': []} for i in range(1, 7)]
    result = planner.adaptive_planning({'hosts': ['127.0.0.1'], 'probe_traces': traces})
    assert result['planner_metrics']['mode'] == 'llm'
    grouped = captured['observations']['probe_traces']
    assert len(grouped) == 1 and grouped[0]['attempts'] == 6
    assert 'uncertainty' in captured['controller_assessment']
