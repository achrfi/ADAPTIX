"""Transport starvation must not stamp a successful assessment as an error.

Measured defect: a run with five verified findings and a sealed extraction printed
`completed_with_errors` because two planning passes hit an empty provider response.
The evidence was sealed before that pass, so the status described the gateway.

`final_report` re-runs `collect_findings`, which keeps only findings whose proof is
sealed on disk - correct discipline, but it means a synthetic state cannot reach
`verified`. These tests patch that step so the status logic is exercised on its own;
`test_a_real_checkpoint_keeps_a_clean_status` checks the same behaviour end to end.
"""
import glob
import json
import sys

import pytest

sys.path.insert(0, '/root/projects/adaptix')

import src.adaptix.agents.reflector as reflector_module
from src.adaptix.reporting.report import final_report, _outcome_errors, _transport_notes, _termination

STARVED = ('Planning pass 5: provider call failed (ProviderStarvation); 14 provider '
           'attempt(s) recorded, completed observations retained')
UNION_STALE = 'union_extract: no verified injection finding names a target and parameter'
RAW_INJECTION = {
    'source_tool': 'injection_probe',
    'target': "http://127.0.0.1:3000/rest/products/search?q=a%27+OR+1%3D1--",
    'parameter': 'q', 'payload': "a' OR 1=1--",
    'verification_status': 'verified', 'verification_basis': 'differential_injection',
}


def _state(**over):
    state = {
        'target': 'http://h', 'run_id': 'status-test', 'findings': [],
        'verified_findings': [{'finding_type': 'sql_injection',
                               'verification_status': 'verified'}],
        'errors': [STARVED], 'stop_reason': 'planner_unavailable',
        'objective_status': 'achieved', 'probe_traces': [], 'planning_history': [],
        'metrics': {}, 'tool_calls': [], 'candidates': [],
    }
    state.update(over)
    return state


def _final(state, monkeypatch):
    """Run final_report without letting evidence recollection empty the buckets."""
    monkeypatch.setattr(reflector_module, 'collect_findings', lambda _state: {})
    return final_report(state)


def test_starvation_is_classified_as_transport():
    assert _transport_notes([STARVED]) == [STARVED]
    assert _outcome_errors([STARVED]) == []


def test_a_proved_run_is_not_an_error_because_the_gateway_starved(monkeypatch):
    out = _final(_state(), monkeypatch)
    assert out['report']['status'] != 'completed_with_errors', out['report']['status']
    assert out['report']['transport_notes'], 'the fault must still be visible'
    assert out['report']['errors'] == [], 'a transport fault is not an outcome error'


def test_a_run_with_nothing_proved_still_reports_the_error(monkeypatch):
    """Silence on an empty run would hide a real failure."""
    out = _final(_state(verified_findings=[], findings=[],
                        objective_status='not_assessed'), monkeypatch)
    assert out['report']['status'] == 'completed_with_errors', out['report']['status']


def test_a_security_policy_rejection_stays_fatal(monkeypatch):
    out = _final(_state(errors=['action denied: out of scope'],
                        stop_reason='policy_rejected'), monkeypatch)
    assert out['report']['status'] == 'completed_with_errors', out['report']['status']


def test_a_non_transport_error_stays_fatal(monkeypatch):
    out = _final(_state(errors=[STARVED, 'audit storage unavailable'],
                        stop_reason=None), monkeypatch)
    assert out['report']['status'] == 'completed_with_errors', out['report']['status']
    assert out['report']['errors'] == ['audit storage unavailable']
    assert len(out['report']['transport_notes']) == 1


def test_a_resolved_union_prerequisite_is_not_an_outcome_error(monkeypatch):
    state = _state(errors=[STARVED, UNION_STALE], stop_reason='provider_starved',
                   injection_findings=[RAW_INJECTION])
    assert _outcome_errors(state['errors'], state) == []
    out = _final(state, monkeypatch)
    assert out['report']['status'] == 'completed_partial', out['report']['status']
    assert out['report']['errors'] == []
    assert out['report']['stop_reason'] == 'provider_starved'


def test_a_starved_run_with_no_evidence_stays_an_error(monkeypatch):
    out = _final(_state(verified_findings=[], errors=[STARVED],
                        stop_reason='provider_starved'), monkeypatch)
    assert out['report']['status'] == 'completed_with_errors', out['report']['status']


def test_starvation_stop_is_reported_as_a_provider_error():
    term = _termination(_state(stop_reason='provider_starved'), 'provider_starved')
    assert term['cause'] == 'provider_error'
    assert 'ProviderStarvation' in term['detail']


def test_the_human_report_names_the_transport_fault(monkeypatch):
    """A short run must explain itself in the markdown, not only in the JSON."""
    out = _final(_state(), monkeypatch)
    markdown = out['markdown_report']
    assert 'Transport notes' in markdown, markdown[-400:]
    assert 'ProviderStarvation' in markdown
