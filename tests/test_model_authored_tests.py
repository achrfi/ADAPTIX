"""Focused integration tests: model-authored test inputs through the whole pipeline.

Covers P5: input surface -> authored attack request (relative path, method, body,
headers, values) -> schema/normalization -> executor transmission -> persisted
evidence -> verification contract receives it -> positive reaches independent
verification, negative control cannot, inconclusive reflects into self-reflection,
and out-of-scope stays blocked.
"""
import json

import httpx
import pytest

BASEURL = 'http://127.0.0.1:18080'

from src.adaptix.agents import planner
from src.adaptix.agents.capabilities import resolve_target, missing_prerequisites
from src.adaptix.agents.schema import Action
from src.adaptix.evidence.verification import replay_result
from src.adaptix.tools import web


def _response(url, body, content_type='text/html', status=200):
    return httpx.Response(status, headers={'content-type': content_type},
                          content=body.encode(), request=httpx.Request('GET', url))


def _priority(**over):
    return {'goal_relevance': .9, 'information_gain': .8, 'evidence_value': .7,
            'confidence': .9, 'estimated_tokens': 100, 'estimated_seconds': 1.0,
            'estimated_requests': 1, **over}


def _state(**extra):
    base = {'run_id': 'authored-test', 'hosts': ['127.0.0.1'], 'scope_ports': [18080],
            'scope_manifest': {'hosts': ['127.0.0.1'], 'networks': [], 'aliases': {}},
            'execution_metrics': {}, 'raw_bytes': 0, 'errors': [], 'events': [],
            'tool_call_budget': 20, 'target': [BASEURL + '/'],
            'identity_context': {'identities': [{'name': 'alice', 'headers': {'Authorization': 'Bearer operator-issued'}}]},
            'web_routes': [{'url': BASEURL + '/rest/user/change-password?current=', 'method': 'POST',
                            'kind': 'form', 'static_asset': False, 'api_like': True, 'status_code': 200},
                           {'url': BASEURL + '/api/resource-1', 'method': 'GET', 'kind': 'xhr',
                            'static_asset': False, 'api_like': True, 'status_code': 200}]}
    base.update(extra)
    return base


def test_model_authored_relative_path_and_headers_survive_schema_and_scope():
    """A relative path, POST method, body and model headers pass schema validation
    and the scope guard resolves them against the authorized origin."""
    action = Action.model_validate({'tool': 'http_request', 'target': '/rest/user/change-password?current=',
                                    'reason': 'POST-only route observed as form in the bundle',
                                    'method': 'POST', 'body': json.dumps({'current': 'x', 'new': 'y'}),
                                    'headers': {'Content-Type': 'application/json',
                                                'X-Adaptix-Test': 'probe-1'},
                                    'priority': _priority()})
    assert action.headers == {'Content-Type': 'application/json', 'X-Adaptix-Test': 'probe-1'}
    assert resolve_target(_state(), action.target) == BASEURL + '/rest/user/change-password?current='
    assert missing_prerequisites(_state(), action.model_dump()) == []
    # out-of-origin paths do not resolve anywhere
    assert resolve_target({**_state(), 'target': ['http://other.example/']}, action.target) is None


def test_schema_reserves_transport_headers_and_line_breaks():
    with pytest.raises(Exception):
        Action.model_validate({'tool': 'http_request', 'target': BASEURL + '/x', 'reason': 'r',
                               'headers': {'Host': 'evil.example'}, 'priority': _priority()})
    with pytest.raises(Exception):
        Action.model_validate({'tool': 'http_request', 'target': BASEURL + '/x', 'reason': 'r',
                               'headers': {'X-A': 'a\r\nB: c'}, 'priority': _priority()})
    with pytest.raises(Exception):
        Action.model_validate({'tool': 'http_request', 'target': BASEURL + '/x', 'reason': 'r',
                               'headers': {f'n{i}': 'v' for i in range(5)}, 'priority': _priority()})


def test_executor_transmits_method_body_and_model_headers(monkeypatch):
    """The requested method, body, headers and parameters reach the wire unchanged."""
    sent = {}

    def fake(state, url, method='GET', body=None, identity_headers=None, extra_headers=None):
        sent.update(url=url, method=method, body=body,
                    identity_headers=identity_headers or {}, extra_headers=extra_headers or {})
        return _response(url, 'ok')

    monkeypatch.setattr(web, '_request', fake)
    state = _state(planned_actions=[{'tool': 'http_request', 'target': '/api/resource-1',
                                     'method': 'HEAD', 'headers': {'X-Adaptix-Test': 'probe'},
                                     'priority': _priority()}])
    result = web.http_request(state)
    assert sent['method'] == 'HEAD'
    assert sent['url'] == BASEURL + '/api/resource-1'
    assert sent['body'] is None
    assert sent['extra_headers'] == {'X-Adaptix-Test': 'probe'}
    trace = result['probe_traces'][-1]
    assert trace['method'] == 'HEAD' and trace['url'] == BASEURL + '/api/resource-1'
    assert sent['identity_headers'] == {}


def test_identity_headers_asked_by_name_and_supplied_by_operator(monkeypatch):
    sent = {}

    def fake(state, url, method='GET', body=None, identity_headers=None, extra_headers=None):
        sent['identity'] = identity_headers
        return _response(url, 'ok')

    monkeypatch.setattr(web, '_request', fake)
    state = _state(planned_actions=[{'tool': 'http_request', 'target': BASEURL + '/api/resource-1',
                                     'method': 'GET', 'identity': 'alice', 'priority': _priority()}])
    web.http_request(state)
    assert sent['identity'] == {'Authorization': 'Bearer operator-issued'}


def test_authored_injection_probe_is_independently_verified_from_one_action(monkeypatch):
    """The model authors one injection probe; the verification engine issues the
    clean control itself and the differential contract confirms the difference."""
    requests = []

    def fake(state, url, method='GET', body=None, identity_headers=None, extra_headers=None):
        requests.append((method, url))
        return _response(url, "You have an error in your SQL syntax" if "'" in url else 'ok')

    monkeypatch.setattr(web, '_request', fake)
    state = _state(planned_actions=[{'tool': 'http_request',
                                     'target': BASEURL + "/rest/products/search?q=search'",
                                     'method': 'GET', 'priority': _priority()}])
    result = web.http_request(state)
    # probe + the runtime-generated clean control went out; the probe value is recorded
    assert any("'" in url for _, url in requests)
    assert any('adaptix_control' in url for _, url in requests)
    control_rows = [row for row in result['probe_traces'] if row.get('control')]
    assert control_rows and control_rows[-1]['payload'] == 'adaptix_control'
    probe_row = next(row for row in result['probe_traces'] if not row.get('control'))
    assert probe_row['detected'] and any(d['category'] == 'sql_injection' for d in probe_row['detected'])
    proofs = result['verification_evidence']
    assert proofs and proofs[-1]['result'] == 'confirmed'
    record = json.load(open(proofs[-1]['evidence_ref']))
    assert insert_ok(record) and replay_result(record['record']) == 'confirmed'


def insert_ok(record):
    return record['record']['verification_basis'] == 'differential_injection' \
        and any(row.get('control') for row in record['record']['controls'])


def test_clean_control_probe_cannot_become_a_finding(monkeypatch):
    """A negative control: the same signature without a differing control stays unverified."""
    def fake(state, url, method='GET', body=None, identity_headers=None, extra_headers=None):
        return _response(url, "You have an error in your SQL syntax")

    monkeypatch.setattr(web, '_request', fake)
    state = _state(planned_actions=[{'tool': 'http_request', 'target': BASEURL + '/stable?x=1',
                                     'method': 'GET', 'priority': _priority()}])
    result = web.http_request(state)
    # a clean value is not an attacker probe: nothing detects, nothing builds a finding
    assert result['probe_traces'][-1]['control'] is True
    assert not result['verification_evidence']


def test_inconclusive_reaches_self_reflection(monkeypatch):
    """An inconclusive observation reaches reflection and shapes the next decision."""
    from src.adaptix.agents.reflector import reflection_verification
    monkeypatch.setattr(web, '_request',
                        lambda state, url, method='GET', body=None, identity_headers=None:
                        _response(url, 'public data'))
    state = _state(planned_actions=[{'tool': 'http_request',
                                     'target': BASEURL + '/api/resource-1',
                                     'method': 'GET', 'priority': _priority()}])
    state.update(web.http_request(state))
    state['attempted_actions'] = state['planned_actions']
    state['action_outcomes'] = [{'action': state['planned_actions'][0], 'goal_progress': 0.0,
                                 'new_evidence_keys': [], 'seconds': 1, 'new_facts': 0,
                                 'context_tokens_estimate': 10, 'failed': False, 'reason': 'no new evidence'}]
    reflection = reflection_verification(state)['reflection']
    assert any('no measured progress' in line or 'identical or parameter-only' in line
               for line in [reflection['guidance']])
    assert reflection['consecutive_no_gain'] >= 1


def test_out_of_scope_construction_stays_blocked():
    """Path construction against another origin never resolves; scope keeps the veto."""
    action = {'tool': 'http_request', 'target': '//127.0.0.2:9999/thing',
              'method': 'GET', 'priority': _priority()}
    assert resolve_target(_state(), action['target']) is None
    from src.adaptix.agents.planner import scope_assessment
    verdict = scope_assessment(_state(), action)
    assert not verdict['allowed']


def test_model_authored_relative_target_roundtrip_via_approval(monkeypatch):
    """Planner approval path: relative target approves and carries the absolute form."""
    decision_actions = [{'tool': 'http_request', 'target': '/api/resource-1',
                         'reason': 'verify the observed route answers for a test',
                         'priority': _priority()}]
    approved = planner._approved_actions(_state(), decision_actions, {'http_request'})
    assert approved and approved[0]['target'] == BASEURL + '/api/resource-1'
