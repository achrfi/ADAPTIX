"""Acceptance regressions for the missing I1-I6 contracts, including negative cases."""
import json
from types import SimpleNamespace
import pytest
import xml.etree.ElementTree as ET
from src.adaptix.tools.nmap import parse_inventory
from src.adaptix.processing.observations import observation_processing
from src.adaptix.agents.decisions import request_decision
from src.adaptix.agents import decisions
from src.adaptix.evidence.sanitize import sanitize
from src.adaptix.security import authorization as auth
from src.adaptix.security.action_policy import issue_action_approval, approval_for
from src.adaptix.evidence.verification import write_verification_record, valid_proof
from src.adaptix.evidence.audit import export_bundle, inspect_bundle
from src.adaptix.config import ROOT


@pytest.fixture
def signing_key(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, 'KEY_PATH', tmp_path / 'key')
    auth._key(create=True)


def test_inventory_tracks_down_closed_and_incomplete_ports():
    xml = '<nmaprun><host><status state="down"/><ports><port portid="80" protocol="tcp"><state state="closed"/></port><port portid="bad"/><port portid="443"/></ports></host></nmaprun>'
    records, warnings = parse_inventory(xml, '127.0.0.1', 123)
    assert records[0]['status'] == 'down' and records[0]['timestamp'] == 123
    assert [p['status'] for p in records[0]['ports']] == ['closed', 'unknown']
    assert warnings == ['invalid/missing port number']


@pytest.mark.parametrize('xml', ['<nmaprun><host>', '<other/>'])
def test_inventory_rejects_malformed_or_wrong_xml(xml):
    with pytest.raises((ET.ParseError, ValueError)):
        parse_inventory(xml, '127.0.0.1')


def test_empty_recon_is_unknown_not_open():
    inventory, warnings = parse_inventory('<nmaprun/>', '127.0.0.1')
    assert inventory[0]['status'] == 'unknown' and warnings


def test_retired_inventory_adapter_does_not_make_up_service(monkeypatch):
    from src.adaptix.tools import nmap, registry
    monkeypatch.setattr(registry, 'run_tool', lambda *a, **kw: pytest.fail('Retired scanner invoked'))
    result = nmap.reconnaissance({'hosts': ['127.0.0.1']})
    assert 'services' not in result and 'recon_inventory' not in result
    assert 'retired' in result['events'][-1]


def test_batch_dedup_preserves_separate_templates_and_paths():
    a = {'template_id': 'a', 'url': 'http://127.0.0.1/one'}
    b = {'template_id': 'b', 'url': 'http://127.0.0.1/one'}
    c = {'template_id': 'a', 'url': 'http://127.0.0.1/two'}
    state = {'candidates': [a, a, b, c], 'http_services': [{'url': a['url']}, {'url': a['url']}],
             'raw_bytes': 10000, 'action_outcomes': [{'failed': False, 'seconds': 1}, {'failed': True, 'seconds': 2}]}
    result = observation_processing(state)
    assert len(result['candidates']) == 3 and len(result['http_services']) == 1
    assert result['metrics']['deduplicated_records'] == 2
    assert result['metrics']['tool_error_rate'] == 0.5 and result['metrics']['tool_seconds'] == 3


def model_response(content):
    return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=20, completion_tokens=10, total_tokens=30),
                           choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


KWARGS = {'model': 'test', 'messages': [{'role': 'user', 'content': 'evidence'}], 'max_tokens': 100, 'timeout': 5}
DECISION = json.dumps({'actions': [], 'rationale': 'sufficient evidence', 'reflection': 'Stop with limitations'})


def test_model_retry_accounts_both_attempts(monkeypatch):
    results = iter([model_response('{bad json'), model_response(DECISION)])
    monkeypatch.setattr(decisions.litellm, 'completion', lambda **kw: next(results))
    d, m, _, ledger, error = request_decision({'planner_retry_limit': 1, 'token_budget': 1000}, KWARGS, {}, 20)
    assert d is not None and error is None
    assert m['llm_calls'] == 2 and m['tokens_used'] == 60 and m['retries_used'] == 1
    assert [x['result'] for x in ledger] == ['failed', 'valid_decision']
    assert all(x['source'] == 'provider' for x in ledger)


def test_failed_provider_cannot_retry_beyond_remaining_budget(monkeypatch):
    monkeypatch.setattr(decisions.litellm, 'completion', lambda **kw: (_ for _ in ()).throw(RuntimeError('offline')))
    d, m, _, ledger, error = request_decision({'planner_retry_limit': 3, 'token_budget': 550},
                                             {**KWARGS, 'max_tokens': 530}, {}, 20)
    assert d is None and error and m['llm_calls'] == 1 and m['tokens_used'] == 550
    assert ledger[0]['source'] == 'reservation'


def test_exact_cache_hit_skips_provider_but_changed_observation_misses(monkeypatch):
    calls = []
    monkeypatch.setattr(decisions.litellm, 'completion', lambda **kw: calls.append(kw) or model_response(DECISION))
    _, _, cache, _, _ = request_decision({}, KWARGS, {}, 20)
    _, metrics, _, ledger, _ = request_decision({'planner_cache': cache}, KWARGS, {}, 20)
    assert len(calls) == 1 and metrics['cache_hits'] == 1 and ledger[0]['tokens_charged'] == 0
    request_decision({'planner_cache': cache}, {**KWARGS, 'messages': [{'role': 'user', 'content': 'changed evidence'}]}, {}, 20)
    assert len(calls) == 2


def test_sensitive_values_redacted_without_erasing_token_metrics():
    value = sanitize({'Authorization': 'Bearer private', 'password': 'secret',
                      'llm_tokens_used': 100, 'token_ledger': [{'tokens_charged': 30}],
                      'authorization': {'type': 'signed_grant', 'grant_id': 'abc'},
                      'url': 'http://user:password@localhost/?token=secret'})
    assert value['Authorization'] == '[REDACTED]' and value['password'] == '[REDACTED]'
    assert value['llm_tokens_used'] == 100 and value['token_ledger'][0]['tokens_charged'] == 30
    assert value['authorization']['grant_id'] == 'abc' and 'secret' not in value['url']


def test_state_change_approval_bound_to_run_action_and_signature(signing_key, tmp_path):
    action = {'tool': 'test_mutation', 'target': 'http://127.0.0.1/object'}
    spec = {'risk': 'state_change'}
    state = {'run_id': 'approval-test', 'principal': 'human'}
    assert approval_for(state, action, spec)['result'] == 'denied'
    path = issue_action_approval('approval-test', 'human', action['tool'], action['target'], 'one disposable object', destination=tmp_path/'approval.json')
    state['action_approvals'] = [str(path)]
    assert approval_for(state, action, spec)['result'] == 'allowed'
    assert approval_for({**state, 'run_id': 'different'}, action, spec)['result'] == 'denied'
    assert approval_for({**state, 'principal': 'someone-else'}, action, spec)['result'] == 'denied'
    assert approval_for(state, {**action, 'target': 'http://127.0.0.1/other'}, spec)['result'] == 'denied'
    from unittest.mock import patch
    with patch('src.adaptix.security.action_policy.time.time', return_value=10**12):
        assert approval_for(state, action, spec)['result'] == 'denied'
    record = json.loads(path.read_text())
    record['payload']['expires_at'] = 0
    path.write_text(json.dumps(record))
    assert approval_for(state, action, spec)['result'] == 'denied'


def test_policy_blocks_mutation_before_handler_dispatch(monkeypatch):
    from src.adaptix.workflow.nodes import execute_action
    from src.adaptix.tools import registry
    monkeypatch.setattr(registry, 'tool_registry', lambda: {'httpx': {'enabled': True, 'path': 'cli', 'risk': 'state_change'}})
    monkeypatch.setattr(registry, 'tool_handlers', lambda: (_ for _ in ()).throw(AssertionError('No dispatch allowed')))
    state = {'target': ['127.0.0.1'], 'status': 'scope_ok', 'authorization': {'type': 'local_loopback'},
             'hosts': ['127.0.0.1'], 'planned_actions': [{'tool': 'httpx', 'target': 'http://127.0.0.1'}]}
    result = execute_action(state)
    assert result['stop_reason'] == 'human_approval_required' and result['approval_audit'][0]['result'] == 'denied'


def test_signed_verification_rejects_tampering_and_missing_trace(signing_key, verification_record):
    state = {'run_id': 'test-proof-integrity'}
    record = verification_record
    proof = write_verification_record(state, record)
    assert valid_proof(record, proof)
    assert not valid_proof(record, proof, 'different-run')
    from pathlib import Path
    path = Path(proof['evidence_ref']); path.write_text('{}')
    assert not valid_proof(record, proof)
    with pytest.raises(ValueError, match='complete request/response'):
        write_verification_record(state, {**record, 'responses': []})


def test_http_status_only_never_becomes_signed_vulnerability_proof(signing_key, verification_record):
    with pytest.raises(ValueError, match='vulnerability-specific'):
        write_verification_record({'run_id': 'test-status-only'}, {**verification_record, 'verification_basis': 'HTTP 200'})


def test_signed_manual_review_requires_attribution_and_full_trace(signing_key, verification_record):
    record = {**verification_record, 'verification_method': 'manual_review', 'reviewer': 'local-lab-operator',
              'reason': 'Compared trace against private-object ground truth', 'result': 'confirmed'}
    proof = write_verification_record({'run_id': 'test-manual-review'}, record)
    assert valid_proof(record, proof)


# --- The verification engine is a registry of objective evidence contracts, not IDOR-only ---

def _differential_probe(record_basis, detected, controls, status_code=200, body='syntax error'):
    return {'verification_method': 'deterministic_replay', 'verification_basis': record_basis,
            'signature_category': detected[0]['category'] if detected else None,
            'detected': detected, 'controls': controls, 'url': 'http://127.0.0.1:18080/search',
            'requests': [{'method': 'GET', 'url': 'http://127.0.0.1:18080/search?q=1', 'identity': None}],
            'responses': [{'status_code': status_code, 'headers': {}, 'body_excerpt': body, 'body_sha256': 'a' * 64}],
            'steps': ['Issue probe', 'Compare against control'], 'expected_behavior': 'independent of input',
            'actual_behavior': body}


def test_differential_injection_confirms_only_with_a_clean_control():
    from src.adaptix.evidence.verification import replay_result
    detected = [{'category': 'sql_injection', 'signature': 'mysql_syntax'}]
    clean = [{'detected': [], 'control': True}]
    dirty = [{'detected': [{'category': 'sql_injection', 'signature': 'mysql_syntax'}], 'control': True}]
    assert replay_result(_differential_probe('differential_injection', detected, clean)) == 'confirmed'
    # Without a control that is clean of this category the input did not cause it.
    assert replay_result(_differential_probe('differential_injection', detected, dirty)) is None
    assert replay_result(_differential_probe('differential_injection', detected, [])) is None


def test_reflected_markup_contract_distinguishes_encoded_from_unencoded():
    from src.adaptix.evidence.verification import replay_result
    unencoded = [{'category': 'cross_site_scripting', 'signature': 'reflected_html_markup'}]
    encoded = [{'category': 'cross_site_scripting', 'signature': 'html_encoded_reflection'}]
    assert replay_result(_differential_probe('reflected_markup', unencoded, [])) == 'confirmed'
    assert replay_result(_differential_probe('reflected_markup', encoded, [])) == 'refuted'


def test_path_traversal_contract_requires_a_clean_control():
    from src.adaptix.evidence.verification import replay_result
    detected = [{'category': 'path_traversal', 'signature': 'root:x:0:0:'}]
    assert replay_result(_differential_probe('path_traversal', detected, [{'detected': [], 'control': True}])) == 'confirmed'
    assert replay_result(_differential_probe('path_traversal', detected, [{'detected': detected, 'control': True}])) is None


def test_unknown_basis_never_confirms():
    from src.adaptix.evidence.verification import replay_result
    record = {**verification_record_placeholder(), 'verification_basis': 'severity_high'}
    assert replay_result(record) is None


def verification_record_placeholder():
    return {'requests': [{'method': 'GET', 'url': 'http://127.0.0.1:18080/x', 'identity': None}],
            'responses': [{'status_code': 200, 'headers': {}, 'body_excerpt': '', 'body_sha256': 'a' * 64}]}


def test_signed_web_verification_record_round_trips(signing_key):
    from src.adaptix.evidence.verification import record_probe_verification, valid_proof
    state = {'run_id': 'test-web-contract'}
    detected = [{'category': 'sql_injection', 'signature': 'mysql_syntax'}]
    controls = [{'detected': [], 'url': 'http://127.0.0.1:18080/search?q=apple', 'control': True}]
    proof = record_probe_verification(state, 'adaptix-probe-abc', 'http://127.0.0.1:18080/search?q=1', 'GET',
        {'method': 'GET', 'url': 'http://127.0.0.1:18080/search?q=1', 'identity': None},
        {'status_code': 500, 'headers': {}, 'body_excerpt': 'sql syntax', 'body_sha256': 'a' * 64},
        detected, controls)
    assert proof and proof['result'] == 'confirmed'
    candidate = {'template_id': proof['template_id'], 'url': proof['url']}
    assert valid_proof(candidate, proof, 'test-web-contract')
    # A probe with no applicable contract produces no record at all.
    assert record_probe_verification(state, 't', 'http://127.0.0.1:18080/x', 'GET',
        {'method': 'GET', 'url': 'http://127.0.0.1:18080/x', 'identity': None},
        {'status_code': 200, 'headers': {}, 'body_excerpt': '', 'body_sha256': 'a' * 64},
        [{'category': 'unknown_class', 'signature': 'x'}], []) is None



def test_audit_bundle_has_checkable_hashes_and_detects_changes():
    state = {'run_id': 'test-audit-integrity', 'token_ledger': [{'tokens_charged': 30}]}
    paths = export_bundle(state, {'status': 'test'}, ['event'])
    result = inspect_bundle(paths['evidence-index'])
    assert result['files_checked'] >= 9
    from pathlib import Path
    Path(paths['events']).write_text('changed')
    with pytest.raises(ValueError, match='missing/changed'):
        inspect_bundle(paths['evidence-index'])


def test_idor_public_or_same_identity_never_verified(monkeypatch):
    from test_adaptix_idor import _scenario, _FakeResponse, _FakeClient
    from src.adaptix.tools import idor
    for variant in ('public', 'same_identity', 'missing_truth'):
        sc = _scenario()
        if variant == 'public': sc['ground_truth']['private'] = False
        if variant == 'same_identity': sc['other_identity'] = sc['owner_identity']
        if variant == 'missing_truth': sc.pop('ground_truth')
        monkeypatch.setattr(idor.httpx_lib, 'Client', lambda **kw: _FakeClient([_FakeResponse(200, '{"id":42}'), _FakeResponse(200, '{"id":42}')]))
        result = idor.idor_test({'hosts': ['127.0.0.1'], 'idor_scenarios': [sc]})
        assert result['idor_findings'][0]['verification_status'] == 'inconclusive'


@pytest.mark.parametrize('owner,other,body,status', [
    (200, 401, 'denied', 'rejected'), (200, 403, 'denied', 'rejected'),
    (200, 404, 'not found', 'rejected'), (401, 200, 'object', 'inconclusive'),
    (200, 200, 'different object', 'inconclusive'), (500, 500, 'error', 'inconclusive')])
def test_idor_status_and_body_controls(monkeypatch, owner, other, body, status):
    from test_adaptix_idor import _scenario, _FakeResponse, _FakeClient
    from src.adaptix.tools import idor
    monkeypatch.setattr(idor.httpx_lib, 'Client', lambda **kw: _FakeClient([_FakeResponse(owner, 'object'), _FakeResponse(other, body)]))
    result = idor.idor_test({'hosts': ['127.0.0.1'], 'idor_scenarios': [_scenario()]})
    assert result['idor_findings'][0]['verification_status'] == status


def test_idor_never_sends_post_and_evidence_redacts_credentials(monkeypatch):
    from test_adaptix_idor import _scenario, _FakeResponse, _FakeClient
    from src.adaptix.tools import idor
    sc = {**_scenario(), 'method': 'POST'}
    monkeypatch.setattr(idor.httpx_lib, 'Client', lambda **kw: _FakeClient([]))
    result = idor.idor_test({'hosts': ['127.0.0.1'], 'idor_scenarios': [sc]})
    assert result['idor_findings'] == [] and result['errors']
    sc['method'] = 'GET'
    monkeypatch.setattr(idor.httpx_lib, 'Client', lambda **kw: _FakeClient([_FakeResponse(200, '{"password":"secret"}'), _FakeResponse(200, '{"password":"secret"}')]))
    result = idor.idor_test({'hosts': ['127.0.0.1'], 'idor_scenarios': [sc]})
    finding = result['idor_findings'][0]
    assert finding['requests'][0]['headers']['Authorization'] == '[REDACTED]'
    assert 'secret' not in finding['responses'][0]['body_excerpt']


def test_storage_failure_stops_loop_and_still_returns_report(monkeypatch):
    from src.adaptix.evidence import audit
    from src.adaptix.workflow.nodes import state_update
    from src.adaptix.reporting.report import final_report
    def unavailable(*args, **kwargs):
        raise OSError('disk unavailable')
    monkeypatch.setattr(audit, 'checkpoint', unavailable)
    state = {'run_id': 'test-storage-failure'}
    state.update(state_update(state))
    assert state['stop_reason'] == 'evidence_storage_unavailable'
    monkeypatch.setattr(audit, 'export_bundle', unavailable)
    result = final_report(state)
    assert result['status'] == 'completed_with_errors' and result['artifact_bundle'] == {}
    assert result['report']['errors']
