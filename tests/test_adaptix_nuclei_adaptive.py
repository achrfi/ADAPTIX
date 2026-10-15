import json
from types import SimpleNamespace

import pytest

from src.adaptix.tools import nuclei, httpx, registry
from src.adaptix.tools.nuclei_profiles import adaptive_profile


def test_httpx_technology_and_banner_versions_select_only_trusted_tags():
    profile = adaptive_profile({'http_services': [{'url': 'https://lab.example/blog',
        'tech': ['WordPress:6.4.1', 'PHP:8.2.12', 'Node.js:20'], 'webserver': 'nginx/1.26.1'}]}, 'https://lab.example/')
    assert profile['tags'] == ['nginx', 'nodejs', 'php', 'wordpress', 'wp']
    assert profile['strategy'] == 'observed_tags'
    assert profile['flags'] == ['-tags', 'nginx,nodejs,php,wordpress,wp', '-pt', 'http']
    assert {item['source'] for item in profile['evidence']} == {'httpx'}


def test_nmap_uses_product_on_exact_pinned_host_and_port():
    state = {'scope_aliases': {'lab.example': ['192.0.2.22']}, 'services': [
        {'host': '192.0.2.22', 'port': 9443, 'product': 'Apache httpd', 'protocol': 'tcp'},
        {'host': '192.0.2.22', 'port': 8080, 'product': 'nginx'},
        {'host': '192.0.2.99', 'port': 9443, 'product': 'WordPress'},
        {'host': '192.0.2.22', 'port': 9443, 'product': 'Jenkins', 'status': 'closed'},
        {'host': '192.0.2.22', 'port': 9443, 'product': 'PHP', 'protocol': 'udp'}]}
    profile = adaptive_profile(state, 'https://lab.example:9443/api')
    assert profile['tags'] == ['apache']
    assert profile['evidence'][0]['source'] == 'nmap'


def test_other_virtual_hosts_schemes_and_ports_do_not_leak_technologies():
    state = {'http_services': [
        {'url': 'https://other.example:9443/', 'tech': ['WordPress']},
        {'url': 'http://lab.example:9443/', 'tech': ['PHP']},
        {'url': 'https://lab.example:8080/', 'tech': ['Drupal']} ]}
    profile = adaptive_profile(state, 'https://lab.example:9443/')
    assert profile['tags'] == [] and profile['flags'] == ['-as', '-pt', 'http']


@pytest.mark.parametrize('tech', [['nginx,cve'], ['rce', 'http', 'cve2024', 'wordpress --code'], ['UnknownThing:1.2'], [], None])
def test_unknown_or_untrusted_labels_never_become_arbitrary_template_filters(tech):
    profile = adaptive_profile({'http_services': [{'url': 'http://127.0.0.1:8080/', 'tech': tech}]}, 'http://127.0.0.1:8080/')
    assert profile['strategy'] == 'native_automatic'
    assert profile['flags'] == ['-as', '-pt', 'http']
    assert profile['tags'] == []


def test_adaptive_batches_are_isolated_and_respect_actual_tool_call_budget(monkeypatch):
    monkeypatch.setattr(nuclei, 'tool_registry', lambda: {'nuclei': {'enabled': True, 'path': '/bin/nuclei'}})
    calls = []
    def run(argv, timeout, stdin):
        calls.append((argv, stdin))
        return {'returncode': 0, 'stdout': '', 'stderr': ''}
    monkeypatch.setattr(nuclei, 'run_tool', run)
    state = {'run_id': 'adaptive-isolation', 'hosts': ['127.0.0.1'], 'http_services': [
        {'url': 'http://127.0.0.1:8080', 'tech': ['WordPress']},
        {'url': 'http://127.0.0.1:9443', 'tech': ['Jenkins']}]}
    result = nuclei.nuclei_check({**state, 'tool_call_budget': 2})
    assert len(calls) == 2
    assert calls[0][0][calls[0][0].index('-tags') + 1] == 'wordpress,wp'
    assert calls[1][0][calls[1][0].index('-tags') + 1] == 'jenkins'
    assert calls[0][1].strip().endswith(':8080') and calls[1][1].strip().endswith(':9443')
    assert result['execution_metrics']['tool_calls_used'] == 2
    assert len(result['nuclei_template_selections']) == 2
    calls.clear()
    result = nuclei.nuclei_check({**state, 'tool_call_budget': 1})
    assert len(calls) == 1 and result['errors']


def test_unknown_origin_requests_native_automatic_selection(monkeypatch):
    monkeypatch.setattr(nuclei, 'tool_registry', lambda: {'nuclei': {'enabled': True, 'path': '/bin/nuclei'}})
    def run(argv, **kwargs):
        assert '-as' in argv and '-t' in argv and '-ud' in argv and '-tags' not in argv
        assert argv[argv.index('-t') + 1] == argv[argv.index('-ud') + 1]
        assert argv[argv.index('-pt') + 1] == 'http'
        return {'returncode': 0, 'stdout': '', 'stderr': ''}
    monkeypatch.setattr(nuclei, 'run_tool', run)
    result = nuclei.nuclei_check({'run_id': 'adaptive-unknown', 'hosts': ['127.0.0.1'],
                                  'http_services': [{'url': 'http://127.0.0.1:8080'}]})
    assert result['nuclei_template_selections'][0]['strategy'] == 'native_automatic'


def test_graph_uses_httpx_technology_and_preserves_selection_in_report_and_planner(monkeypatch):
    from src.adaptix.workflow.graph import graph
    from src.adaptix.agents import planner
    catalog = {'httpx': {'enabled': True, 'path': '/bin/httpx'}, 'nuclei': {'enabled': True, 'path': '/bin/nuclei'}}
    for module in (planner, registry, httpx, nuclei):
        monkeypatch.setattr(module, 'tool_registry', lambda: catalog)
    target = 'http://127.0.0.1:18080/'
    decisions, calls, contexts = iter(['httpx', 'nuclei', None]), [], []
    def completion(**kwargs):
        contexts.append(json.loads(kwargs['messages'][1]['content']))
        tool = next(decisions)
        actions = [] if tool is None else [{'tool': tool, 'target': target, 'reason': 'Evidence-driven test',
            'priority': {'goal_relevance': 1, 'information_gain': 1, 'evidence_value': 1, 'confidence': 1,
                         'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}]
        return SimpleNamespace(usage=SimpleNamespace(total_tokens=70, prompt_tokens=50, completion_tokens=20),
            choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps({'actions': actions,
            'reflection': 'Assess discovered products and test the relevant technology.', 'rationale': 'Use current observations.'})))])
    monkeypatch.setattr(planner.litellm, 'completion', completion)
    def run(argv, **kwargs):
        calls.append(argv)
        if argv[0].endswith('httpx'):
            assert all(flag in argv for flag in ('-td', '-sc', '-title', '-server'))
            row = {'url': target, 'status_code': 200, 'tech': ['WordPress:6.4'], 'webserver': 'nginx/1.26'}
        else:
            assert argv[argv.index('-tags') + 1] == 'nginx,wordpress,wp'
            row = {'matched-at': target + 'wp-admin/', 'template-id': 'wordpress-check', 'info': {'severity': 'low'}}
        return {'returncode': 0, 'stdout': json.dumps(row), 'stderr': ''}
    monkeypatch.setattr(httpx, 'run_tool', run)
    monkeypatch.setattr(nuclei, 'run_tool', run)
    result = graph.invoke({'target': ['127.0.0.1'], 'max_iterations': 5, 'tool_call_budget': 4}, config={'recursion_limit': 100})
    assert len(calls) == 2
    selection = result['report']['nuclei_template_selections'][0]
    assert selection['tags'] == ['nginx', 'wordpress', 'wp'] and selection['execution_status'] == 'completed'
    assert contexts[-1]['observations']['nuclei_template_selections'][0]['tags'] == selection['tags']
    assert not result['report']['verified_findings'] and len(result['report']['inconclusive_findings']) == 1
