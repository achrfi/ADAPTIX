"""Deterministic baseline reconnaissance: bounded, LLM-free and honest.

The baseline must run before the first model decision, use shared budgets and
scope enforcement, degrade gracefully when tools are missing, never repeat on
replanning, and hand the planner a token-efficient structured inventory without
turning discovered routes into claims of exploitable surface.
"""
import json
import time

import pytest

from tests.test_adaptix_planning_recovery import _decision, _install, _state as planner_state
from src.adaptix.agents import planner
from src.adaptix.evidence.http_response import decoded_response
from src.adaptix.evidence import storage
from src.adaptix.tools import web, discovery
from src.adaptix.workflow import baseline
from src.adaptix.reporting.report import final_report

BASE = 'http://127.0.0.1:18080'


def _response(url, body, content_type='text/html', status=200):
    import httpx
    return httpx.Response(status, headers={'content-type': content_type},
                          content=body.encode(), request=httpx.Request('GET', url))


def _state(**over):
    state = {'run_id': 'baseline-test', 'hosts': ['127.0.0.1'], 'scope_ports': [18080],
             'scope_manifest': {'hosts': ['127.0.0.1'], 'networks': [], 'aliases': {},
                                'total_units': 1},
             'scope_aliases': {}, 'scope_networks': [],
             'authorization': {'type': 'local_loopback'}, 'status': 'scope_ok',
             'execution_metrics': {}, 'raw_bytes': 0, 'errors': [], 'events': [],
             'tool_call_budget': 20, 'target': [BASE + '/'],
             'run_started_at': None, 'time_budget_seconds': 1800}
    state.update(over)
    if state.get('run_started_at') is None:
        state['run_started_at'] = time.time()
    return state


def _mock_documents(monkeypatch):
    """Deterministic web surface: entry page with a link, robots.txt, openapi.json."""
    page = _response(BASE + '/', '<html><body><a href="/api/orders">orders</a></body></html>')
    robots = _response(BASE + '/robots.txt', 'Disallow: /private\n', 'text/plain')
    openapi_text = json.dumps({'openapi': '3.0.0', 'paths': {'/api/orders': {'get': {}}}})
    openapi = _response(BASE + '/openapi.json', openapi_text, 'application/json')
    responses = {BASE + '/': page, BASE + '/robots.txt': robots, BASE + '/openapi.json': openapi}
    monkeypatch.setattr(web, '_request', lambda state, url, method='GET', body=None:
                        responses.get(url) or _response(url, '', content_type='text/plain', status=404))

    def fake_read(working, url, headers=None):
        from src.adaptix.workflow.budget import record_tool_call
        working['execution_metrics'] = record_tool_call(working, 'api_discover')
        response = _response(url, openapi_text, 'application/json')
        return decoded_response(response, bytearray(openapi_text.encode()))
    monkeypatch.setattr(discovery, 'read_get', fake_read)
    return responses


@pytest.fixture
def temp_artifacts(tmp_path, monkeypatch):
    """Keep evidence artifacts inside the test's temporary directory."""
    def pathmaker(state, stage, key, ext):
        safe = ''.join(ch for ch in str(key) if ch.isalnum())[-24:] or 'x'
        return tmp_path / f'{stage}.{hash(safe) % 10**9}.{ext}'
    for module in (storage, web, discovery):
        monkeypatch.setattr(module, 'artifact_path', pathmaker)
    yield tmp_path


@pytest.fixture
def no_provider(monkeypatch):
    import litellm
    monkeypatch.setattr(litellm, 'completion',
                        lambda **kw: (_ for _ in ()).throw(AssertionError('baseline must not call the provider')))


def test_baseline_never_invokes_a_provider(temp_artifacts, no_provider, monkeypatch):
    _mock_documents(monkeypatch)
    result = baseline.baseline_reconnaissance(_state())
    assert result['baseline_recon']['completed'] is True
    assert result['web_routes'], 'an entry page must surface in-scope routes'


def test_http_url_target_skips_port_scan_and_host_expansion(temp_artifacts, no_provider, monkeypatch):
    _mock_documents(monkeypatch)
    result = baseline.baseline_reconnaissance(_state())
    assert 'network_scan_skipped_for_explicit_url_scope' in result['baseline_metrics']['skipped']
    assert result['services'] == [] and result['recon_inventory'] == []
    assert all(row['url'].split('/')[2] == '127.0.0.1:18080' for row in result['web_routes'])
    assert result['api_operations'], 'documented GET operations are extracted with provenance'


def test_host_target_discovers_services_then_explores_http_only(temp_artifacts, no_provider, monkeypatch):
    from src.adaptix.tools import nmap as nmap_tool
    monkeypatch.setattr(nmap_tool, 'reconnaissance', lambda state: {
        'services': [{'host': '127.0.0.1', 'port': 18080, 'protocol': 'tcp', 'service': 'http',
                      'product': 'vampi', 'version': '1', 'tunnel': '', 'status': 'open'}],
        'recon_inventory': [{'host': '127.0.0.1', 'status': 'up', 'ports': [], 'timestamp': 0}],
        'errors': [], 'events': ['Reconnaissance: 1 open services'], 'raw_bytes': 100})
    _mock_documents(monkeypatch)
    result = baseline.baseline_reconnaissance(_state(target=['127.0.0.1'], scope_ports=[18080]))
    steps = result['baseline_metrics']['steps']
    assert steps[0]['tool'] == 'nmap'
    assert any(step['tool'] == 'web_discover' for step in steps)
    assert result['discovered_documents']
    assert all(document.startswith('http://127.0.0.1:18080')
               for document in result['discovered_documents'])


def test_expired_run_budget_skips_the_whole_phase(no_provider, monkeypatch):
    monkeypatch.setattr(web, '_request',
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError('no request may be sent')))
    result = baseline.baseline_reconnaissance(_state(run_started_at=time.time() - 10, time_budget_seconds=5))
    assert result['baseline_recon']['mode'] == 'skipped'
    assert result['baseline_metrics']['limitations']


def test_missing_nmap_degrades_gracefully(no_provider, temp_artifacts, monkeypatch):
    monkeypatch.setattr(baseline, 'tool_registry', lambda: {
        'nmap': {'enabled': True, 'path': None, 'detail': 'not found'}})
    monkeypatch.setattr(web, '_request',
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError('no HTTP origin was observed')))
    result = baseline.baseline_reconnaissance(_state(target=['127.0.0.1']))
    assert result['baseline_recon'] == {'completed': True, 'mode': 'limited'}
    assert result['baseline_metrics']['skipped'] == ['nmap_missing']
    assert any('Nmap' in reason for reason in result['baseline_metrics']['limitations'])


def test_disabled_baseline_makes_the_planning_first_workflow_available(no_provider, monkeypatch):
    monkeypatch.setattr(web, '_request',
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError('no request may be sent')))
    result = baseline.baseline_reconnaissance(_state(baseline_disabled=True))
    assert result['baseline_recon'] == {'completed': True, 'mode': 'disabled'}


def test_baseline_is_never_repeated_on_replanning(temp_artifacts, no_provider, monkeypatch):
    _mock_documents(monkeypatch)
    state = _state()
    result = baseline.baseline_reconnaissance(state)
    assert result['baseline_recon']['completed'] is True
    again = baseline.baseline_reconnaissance({**state, **result})
    # Only the skip marker: no second discovery pass, no additional metrics.
    assert set(again) == {'events'}
    assert again['events'][-1] == 'Baseline Recon: already completed; not repeating'


def test_observations_are_deduplicated_and_provenance_kept(temp_artifacts, no_provider, monkeypatch):
    _mock_documents(monkeypatch)
    result = baseline.baseline_reconnaissance(_state())
    routes = result['web_routes']
    keys = [(row['url'], row['method'], row['kind']) for row in routes]
    assert len(keys) == len(set(keys)), 'dedupe must collapse repeated route rows'
    metrics = result['baseline_metrics']
    assert metrics['tool_calls'] > 0
    assert metrics['tool_calls'] == sum(metrics['tools_by_tool'].values())
    assert metrics['seconds'] >= 0
    assert result['structured_observations']['web_routes'], 'planner-facing inventory must exist'
    assert any(row.get('source') for row in routes), 'route provenance must cite stored evidence artifacts'


def test_phase_and_run_tool_call_limits_are_respected(temp_artifacts, no_provider, monkeypatch):
    _mock_documents(monkeypatch)
    monkeypatch.setattr(baseline, 'config', lambda name: {'baseline_reconnaissance': {
        'enabled': True, 'max_seconds': 120, 'max_tool_calls': 2, 'max_hosts': 4,
        'max_web_origins': 2, 'api_document_probes': 2, 'max_web_routes': 400,
        'fallback_when_tool_missing': 'record_limitation'}})
    result = baseline.baseline_reconnaissance(_state())
    assert result['baseline_metrics']['tool_calls'] <= 2
    assert result['baseline_metrics']['stop_reason'] == 'phase_tool_call_limit'


def test_baseline_settings_reject_invalid_configuration(monkeypatch):
    monkeypatch.setattr(baseline, 'config', lambda name: {'baseline_reconnaissance': {
        'enabled': 'yes', 'max_seconds': -1, 'unknown_flag': 1}})
    with pytest.raises(ValueError):
        baseline.baseline_settings()


def test_planner_payload_carries_the_baseline_inventory(temp_artifacts, no_provider, monkeypatch):
    _mock_documents(monkeypatch)
    baseline_result = baseline.baseline_reconnaissance(_state())
    calls = _install(monkeypatch, [_decision([])])
    state = planner_state(**baseline_result)
    planner.adaptive_planning(state)
    context = json.loads(calls[0]['messages'][1]['content'])
    inventory = context['baseline_inventory']
    assert inventory['mode'] == 'complete'
    assert inventory['route_kinds'] and inventory['entry_points'], \
        'baseline entry points must be visible and bounded'
    # Additional model-driven reconnaissance remains available: the catalog the
    # planner holds still lists discovery capabilities for further passes.
    assert 'web_discover' in context['tool_registry']
    assert context['tool_eligibility']['web_discover']['eligible'] >= 1


def test_report_splits_baseline_and_adaptive_metrics():
    state = {'baseline_recon': {'completed': True, 'mode': 'complete'},
             'baseline_metrics': {'seconds': 12.5, 'tool_calls': 6, 'tools_by_tool': {'web_discover': 6},
                                  'web_routes': 7, 'documents_probed': 3, 'steps': [],
                                  'limitations': [], 'skipped': [], 'stop_reason': 'complete'},
             'run_started_at': 0.0, 'time_budget_seconds': 100.0, 'planner_metrics': {'mode': 'llm'}}
    report = final_report(state)
    split = report['report']['metrics']['baseline_reconnaissance']
    assert split['enabled'] is True and split['mode'] == 'complete'
    assert split['seconds'] == 12.5 and split['tool_calls'] == 6
    metrics = report['report']['metrics']
    assert metrics['adaptive_seconds'] >= 0
    assert metrics['executions_by_tool'] == {}


def test_graph_runs_the_baseline_before_the_first_planning_phase(monkeypatch):
    from src.adaptix.workflow.graph import graph
    from src.adaptix.agents import planner
    from unittest.mock import MagicMock
    fake_registry = lambda: {
        'nmap': {'path': None, 'enabled': False}, 'httpx': {'path': None, 'enabled': True},
        'nuclei': {'path': None, 'enabled': True}, 'playwright': {'path': None, 'enabled': False}}
    monkeypatch.setattr(planner, 'tool_registry', fake_registry)
    _mock_documents(monkeypatch)
    empty = {'actions': [], 'reflection': 'Assess stored evidence and remaining limits',
             'rationale': 'No untested evidence', 'hypotheses': [],
             'review': {'goal_status': 'in_progress', 'evidence_refs': [], 'uncertainty': 'none stored',
                        'failure': '', 'decision_change': 'replan with the stored inventory'}}
    decisions = iter([empty, empty])
    def completion(**kw):
        mock = MagicMock()
        mock.choices[0].message.content = json.dumps(next(decisions))
        mock.usage.total_tokens = 60
        mock.usage.prompt_tokens = 40
        mock.usage.completion_tokens = 20
        return mock
    monkeypatch.setattr(planner.litellm, 'completion', completion)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 120)
    state = graph.invoke(_state(planner_retry_limit=0, max_iterations=4, token_budget=4000),
                         config={'recursion_limit': 60})
    phases = [row['phase'] for row in state['phase_runtime']]
    assert phases[:4] == ['scope_guard', 'baseline_reconnaissance', 'nuclei_scan', 'adaptive_planning'], phases
    events = state['events']
    # The baseline runs exactly once: exactly one discovery summary event, and the
    # graph has no re-entry edge to baseline_reconnaissance on replanning.
    baseline_events = [row for row in events if row.startswith('Baseline Recon: complete;')]
    assert len(baseline_events) == 1
    assert sum(1 for row in phases if row == 'baseline_reconnaissance') == 1
    assert state['baseline_recon']['completed'] is True
    assert state['baseline_metrics']['web_routes'] > 0
    assert state['report']['metrics']['baseline_reconnaissance']['enabled'] is True


def test_baseline_events_append_to_run_history_without_duplication(temp_artifacts, no_provider, monkeypatch):
    """The scope-guard event recorded before the baseline must stay first."""
    _mock_documents(monkeypatch)
    seeded = _state(events=['Run: started; budget configured', 'Scope Guard: scope approved'])
    result = baseline.baseline_reconnaissance(seeded)
    events = result['events']
    assert events[:2] == seeded['events'], 'prior run history must be preserved in order'
    assert any('Baseline Recon' in row for row in events[2:])
    assert len(events) == len(set(events)), 'no event may be duplicated'


def test_baseline_entry_point_evidence_refs_resolve_like_the_validator(temp_artifacts, no_provider, monkeypatch):
    _mock_documents(monkeypatch)
    result = baseline.baseline_reconnaissance(_state())
    from src.adaptix.agents.evidence_context import evidence_key
    state = planner_state(**result)
    inventory = baseline.baseline_inventory(state)
    stored = {row['url']: row for row in state['web_routes']}
    assert inventory['entry_points'], 'entry points must be present'
    for row in inventory['entry_points']:
        equivalent = stored.get(row['url'])
        if equivalent is not None:
            assert row['evidence_ref'] == evidence_key('web_routes', equivalent), \
                'a cited baseline ref must be computable by the same function the validator uses'


def test_available_endpoints_carry_citable_route_identifiers(temp_artifacts, no_provider, monkeypatch):
    _mock_documents(monkeypatch)
    result = baseline.baseline_reconnaissance(_state())
    state = planner_state(**result)
    rows = planner.available_endpoints(state, limit=16)
    postures = {'documented_openapi', 'http_confirmed', 'html_form_declared_post',
                'js_reference', 'html_reference', 'discovered_reference'}
    assert rows and all(row['surface'] in postures for row in rows), \
        'every offered endpoint must state its input-surface posture, not imply GET support'


def test_input_surface_posture_distinguishes_js_reference_from_confirmed_operation():
    from src.adaptix.agents.planner import available_endpoints as _ae
    state = _state_target_roots()
    state['web_routes'] = [
        {'url': BASE + '/rest/products', 'method': 'GET', 'kind': 'script_route', 'api_like': True},
        {'url': BASE + '/api/orders', 'method': 'GET', 'kind': 'link', 'api_like': True,
         'status_code': 200},
    ]
    state['probe_traces'] = [{'url': BASE + '/unrelated', 'path_key': BASE + '/unrelated',
                              'method': 'GET', 'status_code': 200, 'parameter': '', 'payload': ''}]
    rows = {row['url']: row for row in _ae(state, limit=8)}
    postures = {'documented_openapi', 'http_confirmed', 'html_form_declared_post',
                'js_reference', 'html_reference', 'discovered_reference'}
    assert rows and all(row['surface'] in postures for row in rows.values()), rows
    assert rows[BASE + '/rest/products']['surface'] == 'js_reference'
    assert rows[BASE + '/api/orders']['surface'] == 'http_confirmed'


def _state_target_roots():
    return {'run_id': 'x', 'hosts': ['127.0.0.1'], 'scope_ports': [18080],
            'scope_manifest': {'hosts': ['127.0.0.1'], 'networks': [], 'aliases': {}, 'total_units': 1},
            'execution_metrics': {}, 'errors': [], 'events': [], 'tool_call_budget': 20,
            'target': [BASE + '/'], 'web_routes': [], 'probe_traces': []}


def test_adaptive_reserve_protects_the_model_planned_budget(monkeypatch):
    settings = baseline.baseline_settings()
    assert settings['adaptive_tool_call_reserve'] == 4
    state = _state(tool_call_budget=6)
    reason = baseline._stop_reason(state, {'tool_calls_used': 3}, settings,
                                  __import__('time').monotonic() + 60)
    assert reason == 'adaptive_reserve_protected', \
        'the baseline must stop before spending the reserve the adaptive loop needs'
    low = _state(tool_call_budget=20)
    assert baseline._stop_reason(low, {'tool_calls_used': 8}, settings,
                                __import__('time').monotonic() + 60) == 'phase_tool_call_limit'


def test_baseline_discovery_is_recognized_and_not_replanned():
    from src.adaptix.agents.action_identity import already_completed, _baseline_already_discovered
    state = _state(
        baseline_metrics={'steps': [{'tool': 'web_discover', 'target': BASE + '/', 'routes': 3}],
                          'tool_calls': 5},
        discovered_documents=[BASE + '/robots.txt', BASE + '/'],
        discovery_limitations=[{'url': BASE + '/api', 'reason': 'ConnectTimeout'}],
        api_observations=[{'url': BASE + '/openapi.json', 'document_kind': 'openapi',
                           'status_code': 200, 'reason': ''}])
    assert already_completed({'tool': 'web_discover', 'target': BASE + '/'}, state)
    assert already_completed({'tool': 'api_discover', 'target': BASE + '/openapi.json'}, state)
    assert already_completed({'tool': 'api_discover', 'target': BASE + '/api'}, state), \
        'a failed baseline document probe must not be fetched again'
    # Without baseline completion on that input, the usual reasons carry the check.
    assert not already_completed({'tool': 'api_discover', 'target': 'http://127.0.0.1:9999/doc'}, state)
    failing = dict(state)
    failing['baseline_metrics'] = {'steps': []}
    failing['api_observations'] = [{'url': BASE + '/openapi.json', 'document_kind': 'http_error',
                                    'status_code': 500, 'reason': 'Documentation probe returned HTTP 500'}]
    # A failed observation stays re-openable through its own nuance, never a blanket claim.
    assert not _baseline_already_discovered('api_discover', BASE + '/openapi.json', failing)


def test_baseline_seed_origin_only_matches_the_baseline_origin():
    from src.adaptix.agents.action_identity import already_completed
    state = _state(baseline_metrics={'steps': [{'tool': 'web_discover', 'target': BASE + '/'}]})
    assert not already_completed({'tool': 'web_discover', 'target': 'http://127.0.0.1:9999/'}, state), \
        'a different origin is not covered by the baseline seed record'
