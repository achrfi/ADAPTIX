"""A manifest scan gets a fact-based wall-clock floor, so a short run defers it honestly.

Bench evidence: the recorded manifest of 2,114 executable templates did not fit a
15-minute run, but the engine executed it anyway and the run expired before any
input testing could start. The floor makes that cost visible at ranking time.
"""
import time
from unittest.mock import MagicMock

from src.adaptix.agents import planner


BASE = 'http://127.0.0.1:3000'


def _completion(**kw):
    import json
    response = {
        'actions': [{'tool': 'nuclei', 'target': BASE, 'reason': 'scan it', 'priority':
                     {'goal_relevance': 0.9, 'information_gain': 0.8, 'evidence_value': 0.8,
                      'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 5,
                      'estimated_requests': 1}}],
        'reflection': 'Assess evidence and limits', 'rationale': 'scan'}
    msg = MagicMock(content=json.dumps(response))
    return MagicMock(choices=[MagicMock(message=msg)],
                     usage=MagicMock(prompt_tokens=50, completion_tokens=20, total_tokens=70))


def test_manifest_scan_deferred_when_the_run_cannot_fit(monkeypatch):
    catalog = {'nuclei': {'enabled': True, 'path': '/bin/nuclei'},
               'http_request': {'enabled': True, 'path': 'module'}}
    monkeypatch.setattr(planner, 'tool_registry', lambda: catalog)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 100)
    monkeypatch.setattr(planner.litellm, 'completion', _completion)
    state = {'target': [BASE], 'hosts': ['127.0.0.1'], 'max_iterations': 6,
             'tool_call_budget': 12, 'token_budget': 50000,
             'time_budget_seconds': 900,
             'nuclei_template_selections': [{'target': BASE, 'mode': 'adaptive',
                                             'executable_count': 2114, 'selected_count': 2697,
                                             'execution_status': 'error_or_partial'}]}
    state = {**state, 'run_started_at': time.time() - 500}
    result = planner.adaptive_planning(state)
    deferred = [row for row in result['policy_feedback'] if row.get('code') == 'cost_deferred']
    assert deferred, 'a manifest that cannot fit the remaining time must be deferred'
    assert 'templates' in deferred[0]['reason']
    assert result['planned_actions'] == []


def test_manifest_scan_allowed_when_time_remains(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry',
                        lambda: {'nuclei': {'enabled': True, 'path': '/bin/nuclei'}})
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 100)
    monkeypatch.setattr(planner.litellm, 'completion', _completion)
    state = {'target': [BASE], 'hosts': ['127.0.0.1'], 'run_started_at': time.time(),
             'max_iterations': 6, 'tool_call_budget': 12, 'token_budget': 50000,
             'time_budget_seconds': 2400,
             'nuclei_template_selections': [{'target': BASE, 'mode': 'adaptive',
                                             'executable_count': 2114, 'selected_count': 2697,
                                             'execution_status': 'error_or_partial'}]}
    result = planner.adaptive_planning(state)
    assert result['planned_actions'] and result['planned_actions'][0]['tool'] == 'nuclei'
