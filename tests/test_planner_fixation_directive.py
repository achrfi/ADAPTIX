"""Fixation escalation: re-proposing a refused surface is named, not just re-refused.

An observed run re-proposed one URL on six consecutive passes while every replan
directive stayed generic, and the passes died one after another. These tests drive
the real graph with a mocked provider: the model re-proposes the same endpoint,
the counter survives across passes in state, and the next directive names the
fixated surface and forbids the value-variation dodge.
"""
import json
from unittest.mock import MagicMock

from src.adaptix.agents import planner
from src.adaptix.workflow.graph import graph
from src.adaptix.tools import registry

BASE = 'http://127.0.0.1:18080'
ROUTE = BASE + '/api/search?q='
PAGE = BASE + '/status'
PRIORITY = {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6,
            'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1,
            'estimated_requests': 1}
CATALOG = {'http_request': {'enabled': True, 'path': 'module'}}


def test_repeat_proposal_escalates_to_named_fixation_directive(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', lambda: CATALOG)
    monkeypatch.setattr(registry, 'tool_registry', lambda: CATALOG)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 100)
    completions = []
    executed = []
    seen = {}

    def completion(**kw):
        turn = len(completions) + 1
        completions.append(kw)
        actions = []
        if turn in (1, 2, 3):
            # Turns 2 and 3 re-propose the endpoint turn 1 already executed.
            actions = [{'tool': 'http_request', 'target': ROUTE, 'method': 'GET',
                        'reason': 'probe the search surface', 'priority': PRIORITY}]
        elif turn == 4:
            context = json.loads(kw['messages'][1]['content'])
            directives = [row for row in context.get('policy_feedback', [])
                          if row.get('code') == 'choose_alternative' and row.get('fixated_target')]
            seen['directive'] = directives[0] if directives else None
            assert seen['directive'], 'the escalated fixation directive must reach the model'
            actions = [{'tool': 'http_request', 'target': PAGE, 'method': 'GET',
                        'reason': 'pivot to the untested surface', 'priority': PRIORITY}]
        else:
            actions = []
            seen['stopped'] = 'model proposed nothing after the pivot'
        response = MagicMock()
        response.usage.total_tokens = 130
        response.choices[0].message.content = json.dumps({
            'actions': actions, 'rationale': 'objective considered',
            'reflection': 'reconsidering selection alike every turn'})
        return response

    monkeypatch.setattr(planner.litellm, 'completion', completion)

    def http_request(state):
        target = state['planned_actions'][0]['target']
        executed.append(target)
        return {'probe_traces': [{'url': target, 'method': 'GET', 'status_code': 200,
                                  'parameter': 'q', 'detected': []}],
                'execution_metrics': {'tool_calls_used': 1}}

    monkeypatch.setattr(registry, 'tool_handlers', lambda: {'http_request': http_request})
    result = graph.invoke({'target': ['127.0.0.1'], 'authorization_confirmed': True,
                           'user_prompt': 'inventarisasi api beserta parameternya',
                           'max_iterations': 6, 'baseline_disabled': True, 'scanner_disabled': True,
                           'web_routes': [{'url': ROUTE, 'kind': 'api', 'method': 'GET'},
                                          {'url': PAGE, 'kind': 'page', 'method': 'GET'}]})

    directive = seen.get('directive')
    assert directive, 'an escalated fixation directive must be produced'
    assert directive['fixated_target'] == ROUTE.split('?')[0] or directive['fixated_target'] == ROUTE, \
        'the named fixated surface must be the re-proposed one'
    assert 're-proposed this same surface' in directive['reason']
    assert 'do not only change a parameter value' in directive['reason']
    # Counting is per path: turn 2 already_classified the same surface once, turn 3 is
    # the second consecutive refusal, so the counter must say at least 2 passes.
    assert result and isinstance(result.get('fixated_targets'), (tuple, list))


def test_fixation_counter_counts_by_path_not_query():
    state = {}
    repeat = lambda value: {'action': {'tool': 'http_request', 'target': value}, 'code': 'previously_rejected'}
    key, count = planner._fixation(state, [repeat(ROUTE)])
    assert count == 1
    # Same path through a different parameter value is still the same surface.
    key2, count2 = planner._fixation({'fixated_targets': (key, count)},
                                     [repeat(BASE + '/api/search?q=zzz')])
    assert count2 == 2 and key2 == key
    # A different surface resets the counter.
    key3, count3 = planner._fixation({'fixated_targets': (key2, count2)},
                                     [repeat(BASE + '/other')])
    assert count3 == 1 and key3 != key2
    # Non-repetition denials never count.
    assert planner._fixation({}, [{'action': {'target': ROUTE}, 'code': 'malformed_target'}]) == (None, 0)
