"""Adversarial evidence-to-scenario cases; no model-invented fixtures."""
import json
from types import SimpleNamespace

import httpx
import pytest

from src.adaptix.tools import discovery
from src.adaptix.agents import planner
from src.adaptix.agents.action_identity import execution_identity

BASE = 'http://127.0.0.1:18080'


def context():
    return {'identities': [{'name': name, 'headers': {'Authorization': 'Bearer private-' + name}} for name in ('alice', 'bob')],
            'identity_url': BASE + '/me', 'identity_json_path': ['data', 'username'], 'private_fields': ['secret']}


def state():
    return {'hosts': ['127.0.0.1'], 'target': [BASE + '/'], 'scope_ports': [18080],
            'identity_context': context(), 'tool_call_budget': 20, 'run_id': 'discovery-unit',
            'api_operations': [{'url': BASE + '/records/{record_id}', 'method': 'GET', 'authenticated': True, 'source_ref': 'actual-spec'}],
            'api_observations': [{'url': BASE + '/records', 'status_code': 200, 'evidence_ref': 'actual-list',
                                 'records': [{'record_id': 'live-731', 'user': 'alice'}]}]}


def test_only_observed_object_values_can_generate_candidates():
    s = state()
    candidates = discovery.derive_candidates(s)
    assert len(candidates) == 1 and candidates[0]['object_id'] == 'live-731'
    assert candidates[0]['source_refs'] == ['actual-spec', 'actual-list']
    s['api_observations'][0]['records'][0]['user'] = 'unknown'
    assert discovery.derive_candidates(s) == []
    s['api_observations'] = []
    s['api_operations'][0]['example'] = {'record_id': 'invented', 'user': 'alice'}
    assert discovery.derive_candidates(s) == []


def test_scenario_validates_sessions_owner_and_private_policy(monkeypatch, tmp_path):
    s = state()
    candidate = discovery.derive_candidates(s)[0]
    s['planned_actions'] = [{'tool': 'scenario', 'target': candidate['name']}]
    calls = []
    def read(working, url, headers=None):
        calls.append((url, headers))
        working['execution_metrics'] = {'tool_calls_used': len(calls)}
        data = {'data': {'username': 'alice' if len(calls) == 1 else 'bob'}} if url.endswith('/me') else {'owner': 'alice', 'secret': 'PRIVATE-FIELD-NEVER-IN-PROMPT'}
        return httpx.Response(200, json=data)
    monkeypatch.setattr(discovery, 'read_get', read)
    monkeypatch.setattr(discovery, 'artifact_path', lambda *a: tmp_path / 'validation.json')
    result = discovery.build_scenario(s)
    scenario = result['idor_scenarios'][0]
    assert scenario['ground_truth']['identities_valid'] is True
    assert scenario['ground_truth']['private'] is True
    assert scenario['object_id'] == 'live-731' and len(calls) == 3
    assert 'PRIVATE-FIELD-NEVER-IN-PROMPT' not in (tmp_path / 'validation.json').read_text()


@pytest.mark.parametrize('bad', ['expired', 'same-account', 'public', 'missing-policy', 'budget'])
def test_invalid_prerequisites_never_create_scenario(monkeypatch, tmp_path, bad):
    s = state()
    if bad == 'missing-policy':
        s['identity_context']['private_fields'] = []
    if bad == 'budget':
        s['tool_call_budget'] = 2
    candidate = discovery.derive_candidates(s)[0]
    s['planned_actions'] = [{'tool': 'scenario', 'target': candidate['name']}]
    calls = []
    def read(working, url, headers=None):
        calls.append(url)
        if bad == 'expired':
            return httpx.Response(401, json={'error': 'expired'})
        if url.endswith('/me'):
            return httpx.Response(200, json={'data': {'username': 'alice' if bad == 'same-account' or len(calls) == 1 else 'bob'}})
        return httpx.Response(200, json={'owner': 'alice'})
    monkeypatch.setattr(discovery, 'read_get', read)
    monkeypatch.setattr(discovery, 'artifact_path', lambda *a: tmp_path / 'validation.json')
    result = discovery.build_scenario(s)
    assert 'idor_scenarios' not in result
    assert result['scenario_validations'][0]['validated'] is False
    if bad in ('missing-policy', 'budget'):
        assert calls == []


def test_document_examples_and_external_servers_do_not_become_objects(monkeypatch, tmp_path):
    s = state()
    s['api_observations'] = []
    s['api_operations'] = []
    s['planned_actions'] = [{'tool': 'api_discover', 'target': BASE + '/openapi.json'}]
    document = {'openapi': '3.0.0', 'paths': {'/records': {'get': {'responses': {'200': {'example': [{'record_id': 'fake', 'user': 'alice'}]}}}},
                    '/createdb': {'get': {}}, '/records/{record_id}': {'get': {'security': [{'bearer': []}]}}}}
    monkeypatch.setattr(discovery, 'read_get', lambda *a: httpx.Response(200, json=document))
    monkeypatch.setattr(discovery, 'artifact_path', lambda *a: tmp_path / 'observed.json')
    result = discovery.api_discover(s)
    assert result['scenario_candidates'] == []
    assert not any('createdb' in o['url'] for o in result['api_operations'])
    document['servers'] = [{'url': 'http://out-of-scope.invalid'}]
    assert discovery.api_discover(s)['api_operations'] == []


def test_unobserved_endpoint_and_invented_scenario_blocked():
    s = state()
    assert planner._approved_actions(s, [{'tool': 'idor', 'target': 'invented'}], {'idor'}) == []
    assert planner._approved_actions(s, [{'tool': 'scenario', 'target': 'invented'}], {'scenario'}) == []
    assert planner._approved_actions(s, [{'tool': 'api_discover', 'target': BASE + '/guessed-secret'}], {'api_discover'}) == []
    assert planner._approved_actions(s, [{'tool': 'api_discover', 'target': BASE + '/openapi.json'}], {'api_discover'})


def test_rejection_ledger_survives_success_and_normalizes_url(monkeypatch):
    s = {**state(), 'max_iterations': 10, 'token_budget': 20000}
    registry = {'api_discover': {'enabled': True, 'path': 'python-module'}}
    monkeypatch.setattr(planner, 'tool_registry', lambda: registry)
    proposed = {'tool': 'api_discover', 'target': BASE + '/invented', 'reason': 'guess',
                'priority': dict(goal_relevance=1, information_gain=1, evidence_value=1, confidence=1,
                                 estimated_tokens=10, estimated_seconds=1, estimated_requests=1)}
    def completion(**kw):
        return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=100, completion_tokens=20, total_tokens=120),
                    choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps({'actions': [proposed],
                         'rationale': 'test', 'reflection': 'Review observed evidence'})))])
    monkeypatch.setattr(planner.litellm, 'completion', completion)
    result = planner.adaptive_planning(s)
    s.update(result)
    assert len(s['rejected_actions']) == 1
    s['policy_feedback'] = []  # A later successful pass may clear immediate feedback.
    variant = {'tool': 'api_discover', 'target': 'http://127.0.0.1:18080/invented/'}
    assert 'Previously rejected' in planner.action_rejection(s, variant, {'api_discover'})
    assert execution_identity(variant, s) == s['rejected_actions'][0]['execution_identity']


def test_read_get_decodes_compressed_document_exactly_once(monkeypatch):
    import gzip
    s = state()
    document = b'{"openapi": "3.0.0", "paths": {}}'
    encoded = gzip.compress(document)
    client = httpx.Client
    monkeypatch.setattr(discovery.httpx, 'Client', lambda **kw: client(
        transport=httpx.MockTransport(lambda request: httpx.Response(
            200, headers={'content-type': 'application/json', 'content-encoding': 'gzip'}, content=encoded)), **kw))
    response = discovery.read_get(s, BASE + '/openapi.json')
    assert response.json() == {'openapi': '3.0.0', 'paths': {}}
    assert 'content-encoding' not in response.headers


def test_api_discover_records_error_document_instead_of_silent_limitation(monkeypatch, tmp_path):
    s = state()
    s['api_observations'], s['api_operations'] = [], []
    s['planned_actions'] = [{'tool': 'api_discover', 'target': BASE + '/openapi.json'}]
    page = httpx.Response(500, headers={'content-type': 'text/html; charset=utf-8'},
                          content=b'<html><title>Error: Unexpected path</title></html>',
                          request=httpx.Request('GET', BASE + '/openapi.json'))
    monkeypatch.setattr(discovery, 'read_get', lambda *a: page)
    monkeypatch.setattr(discovery, 'artifact_path', lambda *a: tmp_path / 'observed.json')
    result = discovery.api_discover(s)
    row = result['api_observations'][-1]
    assert row['status_code'] == 500 and row['document_kind'] == 'http_error'
    assert row['reason'] and 'discovery_limitations' not in result


def test_api_discover_flags_invalid_json_without_records(monkeypatch, tmp_path):
    s = state()
    s['api_observations'], s['api_operations'] = [], []
    s['planned_actions'] = [{'tool': 'api_discover', 'target': BASE + '/openapi.json'}]
    broken = httpx.Response(200, headers={'content-type': 'application/json'},
                            content=b'{not valid json', request=httpx.Request('GET', BASE + '/openapi.json'))
    monkeypatch.setattr(discovery, 'read_get', lambda *a: broken)
    monkeypatch.setattr(discovery, 'artifact_path', lambda *a: tmp_path / 'observed.json')
    row = discovery.api_discover(s)['api_observations'][-1]
    assert row['document_kind'] == 'invalid_json' and row['records'] == []


def test_discovery_transport_reserves_each_request(monkeypatch):
    s = state()
    calls = []
    def handle(request):
        calls.append(request)
        return httpx.Response(200, json={'ok': True})
    original = httpx.Client
    monkeypatch.setattr(discovery.httpx, 'Client', lambda **kw: original(transport=httpx.MockTransport(handle), **kw))
    discovery.read_get(s, BASE + '/')
    assert len(calls) == 1 and s['execution_metrics']['tool_calls_used'] == 1
    s['tool_call_budget'] = 1
    with pytest.raises(ValueError):
        discovery.read_get(s, BASE + '/')
    assert len(calls) == 1
