import httpx
import pytest

from src.adaptix.agents import reflector
from src.adaptix.agents.schema import PlannerDecision
from src.adaptix.evidence.web_signatures import build_findings, detect, is_probe_value
from src.adaptix.tools import web


def _response(url, body, content_type='text/html', status=200):
    return httpx.Response(status, headers={'content-type': content_type},
                          content=body.encode(), request=httpx.Request('GET', url))


def _state(**extra):
    base = {'run_id': 'web-test', 'hosts': ['127.0.0.1'], 'scope_ports': [18080],
            'scope_manifest': {'hosts': ['127.0.0.1'], 'networks': [], 'aliases': {}},
            'execution_metrics': {}, 'raw_bytes': 0, 'errors': [], 'events': [],
            'tool_call_budget': 20, 'target': ['http://127.0.0.1:18080/']}
    base.update(extra)
    return base


def test_detect_marks_only_crafted_values():
    assert is_probe_value("1'") and is_probe_value('../../etc/passwd') and not is_probe_value('1')
    hits = detect("You have an error in your SQL syntax near '''", 'text/html', ["1'"])
    assert {'category': 'sql_injection', 'signature': 'mysql_syntax'} in hits


def test_web_discover_extracts_in_scope_routes_and_records_documents(monkeypatch):
    page = _response('http://127.0.0.1:18080/', '<a href="/item?id=1">i</a>'
                     '<script src="/app.js"></script><form action="/search" method="post"></form>')
    robots = _response('http://127.0.0.1:18080/robots.txt', 'Disallow: /admin\n', 'text/plain')
    sitemap = _response('http://127.0.0.1:18080/sitemap.xml', '<urlset><loc>http://127.0.0.1:18080/docs</loc></urlset>',
                        'application/xml')
    bundle = _response('http://127.0.0.1:18080/app.js',
                       'const a="/rest/products/search";const b="/api/Users";const c="/assets/logo.png";',
                       'application/javascript')
    responses = {'http://127.0.0.1:18080/': page, 'http://127.0.0.1:18080/robots.txt': robots,
                 'http://127.0.0.1:18080/sitemap.xml': sitemap, 'http://127.0.0.1:18080/app.js': bundle}
    monkeypatch.setattr(web, '_request', lambda state, url, method='GET', body=None: responses[url])
    result = web.web_discover(_state(planned_actions=[{'tool': 'web_discover', 'target': 'http://127.0.0.1:18080/'}]))
    kinds = {(row['url'], row['method'], row['kind']) for row in result['web_routes']}
    assert ('http://127.0.0.1:18080/item?id=1', 'GET', 'link') in kinds
    assert ('http://127.0.0.1:18080/search', 'POST', 'form') in kinds
    assert ('http://127.0.0.1:18080/admin', 'GET', 'robots') in kinds
    assert ('http://127.0.0.1:18080/docs', 'GET', 'sitemap') in kinds
    assert ('http://127.0.0.1:18080/rest/products/search', 'GET', 'script_route') in kinds
    assert ('http://127.0.0.1:18080/api/Users', 'GET', 'script_route') in kinds
    assert not any(row['url'].endswith('logo.png') for row in result['web_routes'])
    script_row = next(row for row in result['web_routes'] if row['url'].endswith('/app.js'))
    assert script_row['static_asset'] is True
    assert all(u in result['discovered_documents'] for u in responses if u.endswith(('robots.txt', 'sitemap.xml')) or u.endswith('/'))
    assert result['raw_bytes'] > 0


def test_http_request_control_and_probe_confirm_differential_finding(monkeypatch):
    def fake(state, url, method='GET', body=None):
        probe = "'" in url
        return _response(url, "You have an error in your SQL syntax" if probe else 'ok')
    monkeypatch.setattr(web, '_request', fake)
    state = _state()
    control = web.http_request({**state, 'planned_actions': [
        {'tool': 'http_request', 'target': 'http://127.0.0.1:18080/search', 'method': 'GET'}]})
    state.update(control)
    probe = web.http_request({**state, 'planned_actions': [
        {'tool': 'http_request', 'target': "http://127.0.0.1:18080/search?q=1'", 'method': 'GET'}]})
    state.update(probe)
    assert control['probe_traces'][-1]['control'] is True
    assert probe['probe_traces'][-1]['control'] is False
    finding, = build_findings(state)
    assert finding['category'] == 'sql_injection' and finding['verification_status'] == 'confirmed'
    assert finding['reproduction']['control_url'] == 'http://127.0.0.1:18080/search'
    assert finding['tools_used'] == ['http_request']


def test_reflection_and_report_project_web_findings(monkeypatch):
    def fake(state, url, method='GET', body=None):
        return _response(url, "You have an error in your SQL syntax" if "'" in url else 'ok')
    monkeypatch.setattr(web, '_request', fake)
    state = _state()
    for url in ('http://127.0.0.1:18080/search', "http://127.0.0.1:18080/search?q=1'"):
        state.update(web.http_request({**state, 'planned_actions': [
            {'tool': 'http_request', 'target': url, 'method': 'GET'}]}))
    groups = reflector.collect_findings(state)
    assert groups['findings'][0]['category'] == 'sql_injection'
    assert any(row.get('finding_type') == 'sql_injection' for row in groups['verified_findings'])
    from src.adaptix.reporting.report import final_report
    report = final_report(state)['report']
    assert report['findings'][0]['verification_status'] == 'confirmed'
    assert report['probe_traces']


def test_state_changing_http_request_requires_human_approval(monkeypatch):
    from src.adaptix.workflow.nodes import execute_action
    from src.adaptix.tools import registry
    monkeypatch.setattr(registry, 'tool_registry', lambda: {
        'http_request': {'enabled': True, 'path': 'python-module', 'risk': 'observe', 'operation': 'observe'}})
    monkeypatch.setattr(registry, 'tool_handlers',
                        lambda: (_ for _ in ()).throw(AssertionError('No dispatch allowed')))
    state = {'target': ['127.0.0.1'], 'status': 'scope_ok', 'authorization': {'type': 'local_loopback'},
             'hosts': ['127.0.0.1'],
             'planned_actions': [{'tool': 'http_request', 'target': 'http://127.0.0.1/', 'method': 'POST'}]}
    result = execute_action(state)
    assert result['stop_reason'] == 'human_approval_required'
    assert result['approval_audit'][0]['result'] == 'denied'


def test_planner_decision_accepts_optional_hypotheses():
    decision = PlannerDecision(actions=[], rationale='r', reflection='x',
                               hypotheses=[{'category': 'sql_injection',
                                            'target': 'http://127.0.0.1:18080/search',
                                            'rationale': 'error on quote', 'evidence_refs': ['EV-1']}])
    assert decision.hypotheses[0].category == 'sql_injection'
    assert PlannerDecision(actions=[], rationale='r', reflection='x').hypotheses == []


def test_web_ports_extend_scope_without_changing_default():
    from src.adaptix.security.scope import scope_ports
    policy = {'limits': {'nmap_ports': '22,8000-8002', 'web_ports': '3000'}}
    assert 3000 in scope_ports(['http://127.0.0.1:3000/'], policy)
    assert scope_ports(['http://127.0.0.1:18080/api'], {'limits': {'nmap_ports': '22,8000-8002'}}) == \
        [22, 80, 443, 8000, 8001, 8002, 18080]


def test_out_of_scope_endpoint_is_rejected_before_request(monkeypatch):
    monkeypatch.setattr(web, '_request', lambda *a, **k: (_ for _ in ()).throw(AssertionError('must not send')))
    result = web.http_request(_state(planned_actions=[
        {'tool': 'http_request', 'target': 'http://192.0.2.9:18080/', 'method': 'GET'}]))
    assert result['events']
