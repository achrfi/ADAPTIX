import json
from src.adaptix.security.scope import endpoint_key
from src.adaptix.tools import nuclei as nuclei_module
from src.adaptix.workflow.graph import next_action, after_update
from src.adaptix.agents.reflector import reflection_verification


def test_endpoint_normalization_preserves_api_paths():
    assert endpoint_key('http://127.0.0.1:18080/api/users/1/') == endpoint_key(
        'http://127.0.0.1:18080/api/users/1')
    assert endpoint_key('http://127.0.0.1:18080/api/users/1') != endpoint_key(
        'http://127.0.0.1:18080/api/users/2')


def test_nuclei_api_path_kept_and_unrelated_path_filtered(monkeypatch):
    original_config = nuclei_module.config
    monkeypatch.setattr(nuclei_module, 'config', lambda name: {
        **original_config(name), 'limits': {**original_config(name)['limits'], 'nuclei_templates': 'baseline'}})
    monkeypatch.setattr(nuclei_module, 'tool_registry', lambda: {
        'nuclei': {'enabled': True, 'path': '/bin/nuclei'}})
    def run_tool(*args, **kwargs):
        data = [
            {'matched-at': 'http://127.0.0.1:18080/api/users/1/',
             'template-id': 'a', 'info': {'severity': 'low'}},
            {'matched-at': 'http://127.0.0.1:18080/api/admin',
             'template-id': 'b', 'info': {'severity': 'critical'}},
        ]
        return {'returncode': 0, 'stdout': '\n'.join(json.dumps(x) for x in data), 'stderr': ''}
    monkeypatch.setattr(nuclei_module, 'run_tool', run_tool)
    state = {'run_id': 'offline', 'hosts': ['127.0.0.1'],
             'http_services': [{'url': 'http://127.0.0.1:18080/api/users/1'}]}
    result = nuclei_module.nuclei_check(state)
    assert len(result['candidates']) == 1
    assert result['candidates'][0]['template_id'] == 'a'


def test_graph_route_selects_llm_tool_and_stops_on_budget():
    state = {'planned_actions': [{'tool': 'nuclei', 'target': 'http://127.0.0.1'}],
             'action_cursor': 0, 'iterations': 0}
    assert next_action(state) == 'execute'
    state['execution_metrics'] = {'tool_calls_used': 20}
    assert next_action(state) == 'done'
    assert after_update(state) == 'report'


def test_graph_replans_once_when_llm_has_room():
    state = {'iterations': 1, 'max_iterations': 3,
             'planner_metrics': {'mode': 'llm', 'tokens_used': 200}}
    assert after_update(state) == 'replan'
    state['stop_reason'] = 'no_new_actions'
    assert after_update(state) == 'report'


def test_evidence_is_still_inconclusive_after_normalized_http_match():
    result = reflection_verification({'candidates': [
        {'template_id': 'idor', 'url': 'http://127.0.0.1:18080/api/users/1', 'severity': 'low'}],
        'http_services': [{'url': 'http://127.0.0.1:18080/api/users/1/', 'status_code': 200}]})
    assert len(result['verified_findings']) == 0
    assert result['inconclusive_findings'][0]['actual_observation']['status_code'] == 200


def test_graph_invoke_offline_loopback_pipeline(monkeypatch):
    """Mocks scanner/model boundaries, exercises one-graph tool routing."""
    from src.adaptix.workflow.graph import graph
    from src.adaptix.agents import planner
    from src.adaptix.tools import nmap as nt, httpx as ht, nuclei as nu, playwright as pw
    fake_registry = lambda: {
        'nmap': {'path': '/bin/nmap', 'enabled': True},
        'httpx': {'path': '/bin/httpx', 'enabled': True},
        'nuclei': {'path': '/bin/nuclei', 'enabled': True},
        'playwright': {'path': None, 'enabled': False}}
    for mod in (nt, ht, nu, pw, planner):
        monkeypatch.setattr(mod, 'tool_registry', fake_registry)
    from src.adaptix.tools import registry
    monkeypatch.setattr(registry, 'tool_registry', fake_registry)
    calls = []
    def fake_run(argv, timeout=45, stdin=None):
        calls.append(argv[0])
        if 'nmap' in argv[0]:
            payload = '<nmaprun><host><ports><port protocol="tcp" portid="18080"><state state="open"/><service name="http"/></port></ports></host></nmaprun>'
        elif 'httpx' in argv[0]:
            payload = json.dumps({'url': 'http://127.0.0.1:18080', 'status_code': 200}) + '\n'
        else:
            payload = json.dumps({'matched-at': 'http://127.0.0.1:18080/',
                     'template-id': 'adaptix-http-baseline', 'info': {'severity': 'info'}}) + '\n'
        return {'returncode': 0, 'stdout': payload, 'stderr': ''}
    for mod in (nt, ht, nu):
        monkeypatch.setattr(mod, 'run_tool', fake_run)
    from unittest.mock import MagicMock
    decisions = iter([
        {'actions': [{'tool': 'httpx', 'target': 'http://127.0.0.1:18080', 'reason': 'probe', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}], 'reflection': 'Assess current evidence and limits before deciding', 'rationale': 'probe'},
        {'actions': [{'tool': 'nuclei', 'target': 'http://127.0.0.1:18080', 'reason': 'inspect', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}], 'reflection': 'Assess current evidence and limits before deciding', 'rationale': 'inspect'},
        {'actions': [], 'reflection': 'Assess current evidence and limits before deciding', 'rationale': 'complete'},
    ])
    def completion(**kwargs):
        mock = MagicMock()
        mock.choices[0].message.content = json.dumps(next(decisions))
        mock.usage.total_tokens = 60
        mock.usage.prompt_tokens = 40
        mock.usage.completion_tokens = 20
        return mock
    monkeypatch.setattr(planner.litellm, 'completion', completion)
    state = graph.invoke({'target': ['127.0.0.1'], 'authorization_confirmed': True,
                          'run_id': 'test-invoke', 'errors': [], 'events': [],
                          'max_iterations': 3, 'tool_call_budget': 10, 'token_budget': 2000},
                         config={'recursion_limit': 100})
    assert len(state['verified_findings']) == 0
    assert len(state['candidates']) == 1
    assert state['report']['stop_reason'] == 'no_new_actions'
    assert state['report']['mode'] == 'llm'
    assert state['metrics']['tool_calls_used'] == 2
    assert calls == ['/bin/httpx', '/bin/nuclei']


def test_budget_limits_tool_execution_and_report_reason(monkeypatch):
    from src.adaptix.tools import nmap as nt
    from src.adaptix.reporting.report import final_report
    monkeypatch.setattr(nt, 'tool_registry', lambda: {
        'nmap': {'path': '/bin/nmap', 'enabled': True}})
    invocations = []
    def fake_run(argv, **kwargs):
        invocations.append(argv[-1])
        return {'returncode': 0,
                'stdout': '<nmaprun><host><ports/></host></nmaprun>', 'stderr': ''}
    monkeypatch.setattr(nt, 'run_tool', fake_run)
    state = {'hosts': ['127.0.0.1', '127.0.0.2'], 'tool_call_budget': 1,
             'target': ['127.0.0.1', '127.0.0.2'], 'run_id': 'budget-test'}
    state.update(nt.reconnaissance(state))
    assert invocations == ['127.0.0.1']
    assert state['execution_metrics']['tool_calls_used'] == 1
    report = final_report(state)['report']
    assert report['stop_reason'] == 'budget_exhausted'
