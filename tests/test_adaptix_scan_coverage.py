import json
import time

import pytest

from src.adaptix.security.ports import parse_ports, format_ports
from src.adaptix.security.scope import scope_ports
from src.adaptix.security.transport import bind_url
from src.adaptix.tools import nmap, nuclei


def test_explicit_web_ports_and_url_port_share_one_parser():
    ports = parse_ports('443,3000,8080,3000')
    assert ports == [443, 3000, 8080]
    assert format_ports(ports) == '443,3000,8080'
    selected = scope_ports(['http://127.0.0.1:18080/api'], {'limits': {'allowed_ports': '80,443,3000'}})
    assert selected == [80, 443, 3000, 18080]
    assert bind_url('http://127.0.0.1:3000/', {'hosts': ['127.0.0.1'], 'scope_ports': ports})[0].endswith(':3000/')


@pytest.mark.parametrize('spec', ['', '0', '65536', '90-80', '1-65536', '80,,443', '80;id', True, None,
                                'all', '-', '1-65535', '8000-8099', range(1, 65536),
                                list(range(1, 34)), ','.join(str(port) for port in range(1, 34))])
def test_invalid_port_selection_rejected(spec):
    with pytest.raises(ValueError):
        parse_ports(spec)


@pytest.mark.parametrize('selected', [None, [22, 80, 443]])
def test_retired_nmap_never_executes_for_any_port_selection(monkeypatch, selected):
    from src.adaptix.tools import registry
    monkeypatch.setattr(registry, 'run_tool', lambda *a, **kw: pytest.fail('Retired scanner executed'))
    result = nmap.reconnaissance({'run_id': 'scan-coverage-test', 'hosts': ['127.0.0.1'], 'scope_ports': selected,
                                 'run_started_at': time.time(), 'time_budget_seconds': 120})
    assert set(result) == {'events'}
    assert 'retired' in result['events'][-1]


def _mock_nuclei(monkeypatch, rows, mode='default'):
    monkeypatch.setattr(nuclei, 'tool_registry', lambda: {'nuclei': {'enabled': True, 'path': '/bin/nuclei'}})
    original_config = nuclei.config
    monkeypatch.setattr(nuclei, 'config', lambda name: {
        **original_config(name), 'limits': {**original_config(name)['limits'], 'nuclei_templates': mode}})
    calls = []
    def run(argv, timeout, stdin, **kwargs):
        calls.append((argv, timeout, stdin))
        return {'returncode': 0, 'stdout': '\n'.join(json.dumps(row) for row in rows), 'stderr': ''}
    monkeypatch.setattr(nuclei, 'run_tool', run)
    return calls


def test_native_templates_keep_generated_paths_but_reject_other_origins(monkeypatch):
    urls = ['http://127.0.0.1:18080/api/admin?probe=1', 'http://127.0.0.1:18080/api/users/2',
            'http://127.0.0.1:8080/admin', 'https://127.0.0.1:18080/admin', 'http://outside.invalid:18080/admin']
    calls = _mock_nuclei(monkeypatch, [{'matched-at': u, 'template-id': 'community-check',
                                     'info': {'severity': 'high'}} for u in urls])
    state = {'run_id': 'scan-coverage-test', 'hosts': ['127.0.0.1'], 'http_services': [{'url': 'http://127.0.0.1:18080/api'}],
             'run_started_at': time.time(), 'time_budget_seconds': 200}
    result = nuclei.nuclei_check(state)
    assert [x['url'] for x in result['candidates']] == urls[:2]
    assert all(x['status'] == 'candidate_unverified' for x in result['candidates'])
    argv, timeout, _ = calls[0]
    assert '-t' in argv and '-ud' not in argv and '-tags' not in argv and '-severity' not in argv
    assert '-code' not in argv and '-headless' not in argv
    assert '-dr' in argv and '-rl' in argv and '-c' in argv
    assert 0 < timeout <= 200


def test_native_template_path_restores_domain_from_pinned_ip(monkeypatch):
    calls = _mock_nuclei(monkeypatch, [{'matched-at': 'https://192.0.2.22:9443/admin?x=1',
                                     'template-id': 'community-check', 'info': {'severity': 'medium'}}])
    result = nuclei.nuclei_check({'run_id': 'scan-coverage-test', 'hosts': ['192.0.2.22'], 'scope_ports': [9443],
        'scope_aliases': {'lab.example': ['192.0.2.22']},
        'planned_actions': [{'tool': 'nuclei', 'target': 'https://lab.example:9443/api'}]})
    assert calls[0][2] == 'https://192.0.2.22:9443/api\n'
    assert result['candidates'][0]['url'] == 'https://lab.example:9443/admin?x=1'


def test_template_selection_supports_baseline_and_local_paths():
    assert nuclei.template_selection({'nuclei_templates': 'default'}) == ([], False)
    flags, exact = nuclei.template_selection({'nuclei_templates': 'baseline'})
    assert flags[0] == '-t' and flags[1].endswith('templates/http-response.yaml') and exact
    flags, exact = nuclei.template_selection({'nuclei_templates': ['templates/http-response.yaml']})
    assert flags[0] == '-t' and not exact
    with pytest.raises(ValueError, match='does not exist'):
        nuclei.template_selection({'nuclei_templates': ['templates/missing.yaml']})
    with pytest.raises(ValueError):
        nuclei.template_selection({'nuclei_templates': []})


def test_only_explicit_web_ports_appear_in_model_prompt(monkeypatch):
    from src.adaptix.agents import planner
    from unittest.mock import MagicMock
    monkeypatch.setattr(planner, 'tool_registry', lambda: {'httpx': {'enabled': True, 'path': '/bin/httpx'}})
    captured = {}
    def completion(**kwargs):
        captured.update(kwargs)
        message = MagicMock(content=json.dumps({'actions': [], 'reflection': 'Coverage request evaluated.', 'rationale': 'Stop.'}))
        return MagicMock(choices=[MagicMock(message=message)], usage=MagicMock(prompt_tokens=50, completion_tokens=20, total_tokens=70))
    monkeypatch.setattr(planner.litellm, 'completion', completion)
    result = planner.adaptive_planning({'hosts': ['127.0.0.1'], 'scope_ports': [80, 443, 3000]})
    assert result['planner_metrics']['mode'] == 'llm'
    system = captured['messages'][0]['content']
    assert 'Allowed TCP ports: 80,443,3000.' in system
    assert len(system) < 10000


def test_tool_timeout_preserves_complete_jsonl_output(monkeypatch):
    import subprocess
    from src.adaptix.tools import registry
    row = b'{"template-id":"partial-check"}\n'
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(['nuclei'], 1, output=row, stderr=b'still scanning')
    monkeypatch.setattr(registry.subprocess, 'run', timeout)
    result = registry.run_tool(['nuclei'], timeout=1)
    assert result['returncode'] == -1
    assert json.loads(result['stdout'])['template-id'] == 'partial-check'
    assert 'partial output retained' in result['stderr']


def test_nuclei_timeout_reports_error_and_keeps_unverified_matches(monkeypatch):
    _mock_nuclei(monkeypatch, [])
    row = {'matched-at': 'http://127.0.0.1:18080/admin', 'template-id': 'partial-check', 'info': {'severity': 'high'}}
    monkeypatch.setattr(nuclei, 'run_tool', lambda *a, **kw: {
        'returncode': -1, 'stdout': json.dumps(row) + '\n{"incomplete', 'stderr': 'Tool timed out; partial output retained'})
    result = nuclei.nuclei_check({'run_id': 'scan-coverage-timeout-test', 'hosts': ['127.0.0.1'],
                                 'http_services': [{'url': 'http://127.0.0.1:18080'}]})
    assert [c['template_id'] for c in result['candidates']] == ['partial-check']
    assert result['candidates'][0]['status'] == 'candidate_unverified'
    assert any('timed out' in error for error in result['errors'])
