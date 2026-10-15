"""Native IDOR evidence must reach summary counts without label-only promotion."""
import copy
from pathlib import Path

import pytest

from src.adaptix.agents.reflector import reflection_verification
from src.adaptix.evidence.audit import inspect_bundle
from src.adaptix.evidence.verification import write_verification_record
from src.adaptix.processing.observations import observation_processing
from src.adaptix.reporting.report import final_report
from src.adaptix.security import authorization
from src.adaptix.tools import idor
from test_adaptix_idor import _scenario, _FakeClient, _FakeResponse


@pytest.fixture(autouse=True)
def signing_key(tmp_path, monkeypatch):
    monkeypatch.setattr(authorization, 'KEY_PATH', tmp_path / 'signing-key')


def observe(monkeypatch, other_status=200, private=True):
    scenario = _scenario()
    scenario['ground_truth']['private'] = private
    responses = [_FakeResponse(200, 'private object'),
                 _FakeResponse(other_status, 'private object' if other_status == 200 else 'denied')]
    monkeypatch.setattr(idor.httpx_lib, 'Client', lambda **kw: _FakeClient(responses))
    state = {'run_id': 'test-native-idor-report', 'hosts': ['127.0.0.1'],
             'scope_ports': [8080], 'idor_scenarios': [scenario], 'events': [], 'errors': []}
    state.update(idor.idor_test(state))
    return state


@pytest.mark.parametrize('other_status,private,group', [
    (200, True, 'verified_findings'),
    (403, True, 'rejected_findings'),
    (200, False, 'inconclusive_findings')])
def test_native_result_reaches_reflection_report_and_audit(monkeypatch, other_status, private, group):
    state = observe(monkeypatch, other_status, private)
    state.update(reflection_verification(state))
    assert len(state[group]) == 1
    assert sum(len(state[k]) for k in ('verified_findings', 'rejected_findings', 'inconclusive_findings')) == 1
    counts = {'verified_findings': '1 verified', 'rejected_findings': '1 non-findings/refuted',
              'inconclusive_findings': '1 inconclusive'}
    assert counts[group] in state['events'][-1]
    result = final_report(state)
    assert len(result['report'][group]) == 1
    assert result['report'][group][0]['requests'][1]['identity'] == 'userB'
    assert result['report'][group][0]['responses'][0]['status_code'] == 200
    assert inspect_bundle(result['artifact_bundle']['evidence-index'])['status'] == 'integrity_verified'


def test_final_report_also_handles_direct_native_tool_result(monkeypatch):
    state = observe(monkeypatch)
    assert 'verified_findings' not in state
    result = final_report(state)
    assert len(result['report']['verified_findings']) == 1


def test_repeated_reflection_and_replay_candidate_count_one_finding(monkeypatch):
    state = observe(monkeypatch)
    finding = state['idor_findings'][0]
    record = {**finding, 'url': finding['target'], 'template_id': 'separate-idor-replay',
              'verification_method': 'deterministic_replay', 'verification_basis': 'private_object_access'}
    proof = write_verification_record(state, record)
    state['verification_evidence'] = [proof]
    state['candidates'] = [{'url': finding['target'], 'template_id': record['template_id']}]
    state['idor_findings'].append(copy.deepcopy(finding))
    for _ in range(3):
        state.update(reflection_verification(state))
        assert len(state['verified_findings']) == 1
        assert state['verified_findings'][0]['source_tool'] == 'idor_test'
        assert len(state['verified_findings'][0]['responses']) == 2


@pytest.mark.parametrize('variant', ['missing_proof', 'tampered_file', 'wrong_run', 'forged_label'])
def test_untrusted_idor_verdict_cannot_promote_summary(monkeypatch, variant):
    state = observe(monkeypatch)
    finding = state['idor_findings'][0]
    if variant == 'missing_proof':
        finding.pop('verification_evidence')
    elif variant == 'tampered_file':
        Path(finding['verification_evidence']['evidence_ref']).write_text('{}')
    elif variant == 'wrong_run':
        state['run_id'] = 'another-run'
    else:
        state['idor_findings'] = [{'target': finding['target'], 'verification_status': 'verified',
                                   'fixture_validated': True}]
    result = reflection_verification(state)
    assert result['verified_findings'] == [] and result['rejected_findings'] == []
    assert len(result['inconclusive_findings']) == 1


def test_distinct_identity_pairs_on_same_object_are_preserved(monkeypatch):
    state = observe(monkeypatch)
    first = state['idor_findings'][0]
    second = copy.deepcopy(first)
    second['other_identity'] = second['requests'][1]['identity'] = 'userC'
    second['template_id'] = 'another-identity-pair'
    record = {**second, 'url': second['target'], 'verification_method': 'deterministic_replay',
              'verification_basis': 'private_object_access'}
    second['verification_evidence'] = write_verification_record(state, record)
    state['idor_findings'].append(second)
    result = reflection_verification(state)
    assert len(result['verified_findings']) == 2
    assert {x['other_identity'] for x in result['verified_findings']} == {'userB', 'userC'}


def test_evidence_expansion_is_separate_from_reduction():
    state = {'raw_bytes': 10, 'idor_findings': [{'scenario': 'object', 'reason': 'evidence metadata' * 20}]}
    metrics = observation_processing(state)['metrics']
    assert metrics['reduction_percent'] == 0
    assert metrics['expansion_percent'] > 0 and metrics['size_comparison'] == 'expanded'
    assert metrics['evidence_overhead_bytes'] == metrics['structured_bytes'] - metrics['raw_bytes']
