"""Deterministic recovery keeps a fully infeasible decision from ending as a rejection loop.

The model stays in charge of strategy; the recovery tier only executes an
evidence-ranked alternative the policy feedback already named, through the normal
executor (scope, approval and budget all apply). These tests drive the real graph
with a mocked provider and mocked tool handlers.
"""
import json
from unittest.mock import MagicMock

from src.adaptix.agents import planner
from src.adaptix.workflow.graph import graph
from src.adaptix.tools import registry

BASE = 'http://127.0.0.1:18080'
ROUTE = BASE + '/api/search?q='
PRIORITY = {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6,
            'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1,
            'estimated_requests': 1}


def test_recovery_executes_evidence_ranked_input_surface(monkeypatch):
    catalog = {'httpx': {'enabled': True, 'path': 'cli'},
               'http_request': {'enabled': True, 'path': 'module'}}
    monkeypatch.setattr(planner, 'tool_registry', lambda: catalog)
    monkeypatch.setattr(registry, 'tool_registry', lambda: catalog)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 100)
    completions = []
    executed = []

    def completion(**kw):
        turn = len(completions) + 1
        completions.append(kw)
        actions = []
        if turn == 1:
            actions = [{'tool': 'nuclei', 'target': BASE, 'reason': 'scan', 'priority': PRIORITY}]
        elif turn == 2:
            context = json.loads(kw['messages'][1]['content'])
            directives = [row for row in context['policy_feedback']
                          if row.get('code') == 'choose_alternative' and row.get('alternatives')]
            top = directives and directives[0]['alternatives'][0]
            assert top and top['tool'] == 'http_request' and top['target'] == ROUTE, \
                'input-bearing provenance row must rank first among alternatives'
            actions = [{'tool': 'httpx', 'target': BASE, 'reason': 'observe', 'priority': PRIORITY}]
        elif turn == 3:
            actions = [{'tool': 'httpx', 'target': BASE, 'reason': 'rescan', 'priority': PRIORITY}]
        response = MagicMock()
        response.usage.total_tokens = 130
        response.choices[0].message.content = json.dumps({
            'actions': actions, 'rationale': 'objective considered',
            'reflection': 'reconsidering selection' if turn > 1 else 'trying a scanning tool'})
        return response

    monkeypatch.setattr(planner.litellm, 'completion', completion)

    def httpx_tool(state):
        target = state['planned_actions'][0]['target']
        executed.append(('httpx', target))
        return {'http_services': [{'url': target, 'status_code': 200, 'content_type': 'text/html'}],
                'execution_metrics': {'tool_calls_used': 1}}

    def http_request(state):
        target = state['planned_actions'][0]['target']
        executed.append(('http_request', target))
        return {'probe_traces': [{'url': target, 'method': 'GET', 'status_code': 200,
                                  'parameter': 'q', 'detected': []}],
                'execution_metrics': {'tool_calls_used': 1}}

    monkeypatch.setattr(registry, 'tool_handlers', lambda: {'httpx': httpx_tool,
                                                            'http_request': http_request})
    result = graph.invoke({'target': ['127.0.0.1'], 'authorization_confirmed': True,
                           'user_prompt': 'inventarisasi api beserta parameternya',
                           'max_iterations': 8, 'baseline_disabled': True, 'scanner_disabled': True,
                           'web_routes': [{'url': ROUTE, 'kind': 'api', 'method': 'GET'}]})
    for row in (result.get('planning_history') or []):
        print('DECISION', row.get('iteration'), row.get('scope_window'),
              [(s.get('tool'), s.get('target'), s.get('action_source')) for s in (row.get('selected') or [])],
              [(r.get('code'), r.get('action', {}).get('tool'), r.get('action', {}).get('target'))
               for r in (row.get('rejections') or [])])
    metrics = result.get('planner_metrics') or {}
    assert metrics.get('recovery_executions') == 2
    assert executed == [('http_request', ROUTE), ('httpx', BASE), ('httpx', ROUTE)]
    recovery_rows = [row for row in (result.get('attempted_actions') or [])
                     if row.get('action_source') == 'policy_recovery']
    assert [row['target'] for row in recovery_rows] == [ROUTE, ROUTE]
    assert any(trace.get('url') == ROUTE for trace in result.get('probe_traces') or [])
