"""Offline full-stage regression with mocked scanners and mocked local LLM."""
import json
from src.adaptix.workflow import nodes
from src.adaptix.agents import planner
from src.adaptix.tools import nmap as nmap_tool, httpx as httpx_tool, nuclei as nuclei_tool, playwright as browser_tool


def test_deterministic_nodes_with_mock_tools(monkeypatch):
    fake_registry = lambda: {
        'nmap': {'path': '/bin/nmap', 'enabled': True},
        'httpx': {'path': '/bin/httpx', 'enabled': True},
        'nuclei': {'path': '/bin/nuclei', 'enabled': True},
        'playwright': {'path': None, 'enabled': True, 'detail': 'missing'}}
    for module in (nmap_tool, httpx_tool, nuclei_tool, browser_tool, planner):
        monkeypatch.setattr(module, 'tool_registry', fake_registry)
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: (_ for _ in ()).throw(
        RuntimeError('Ollama offline')))
    xml = '<nmaprun><host><ports><port protocol="tcp" portid="18080"><state state="open"/><service name="http" product="nginx" version="1.31.6"/></port></ports></host></nmaprun>'
    calls = []
    def fake_run_tool(argv, timeout=45, stdin=None):
        calls.append((argv, stdin))
        if 'nmap' in argv[0]:
            return {'stdout': xml, 'stderr': '', 'returncode': 0}
        if 'httpx' in argv[0]:
            assert '-no-stdin' in argv
            from pathlib import Path
            assert Path(argv[argv.index('-l') + 1]).read_text().strip() == 'http://127.0.0.1:18080'
            return {'stdout': json.dumps({'url': 'http://127.0.0.1:18080', 'status_code': 200, 'title': 'Lab'}) + '\n',
                    'stderr': '', 'returncode': 0}
        return {'stdout': json.dumps({'matched-at': 'http://127.0.0.1:18080/',
                'template-id': 'adaptix-http-baseline', 'info': {'severity': 'info'}})+'\n',
                'stderr': '', 'returncode': 0}
    for module in (nmap_tool, httpx_tool, nuclei_tool):
        monkeypatch.setattr(module, 'run_tool', fake_run_tool)
    state = {'target': ['127.0.0.1'], 'authorization_confirmed': True,
             'events': [], 'errors': [], 'tool_call_budget': 20}
    for node in (nodes.scope_guard, nodes.reconnaissance, nodes.adaptive_planning):
        state.update(node(state))
    while state['action_cursor'] < len(state['planned_actions']):
        name = state['planned_actions'][state['action_cursor']]['tool']
        state.update({'httpx': nodes.httpx_probe, 'nuclei': nodes.nuclei_check,
                      'playwright': nodes.browser_observe}[name](state))
        state.update(nodes.advance_action(state))
    for node in (nodes.observation_processing, nodes.reflection_verification,
                 nodes.state_update, nodes.final_report):
        state.update(node(state))
    assert state['report']['status'] == 'scan_completed'  # Missing tool is not chosen by planner
    assert len(state['services']) == 1
    assert len(state['http_services']) == 1
    assert len(state['candidates']) == 1
    assert state['verified_findings'] == []
    assert state['metrics']['llm_calls'] == 1
    assert state['metrics']['tool_calls_used'] == 3
    assert len(calls) == 3
