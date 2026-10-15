"""Replanning may correct a rejected decision, but cannot loop on stored results."""
import json
from types import SimpleNamespace

from src.adaptix.agents import planner
from src.adaptix.tools import registry
from src.adaptix.workflow.graph import graph


def install_model(monkeypatch, choose):
    catalog = {'httpx': {'enabled': True, 'path': 'cli'}}
    monkeypatch.setattr(planner, 'tool_registry', lambda: catalog)
    monkeypatch.setattr(registry, 'tool_registry', lambda: catalog)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 100)
    contexts, dispatched = [], []

    def completion(**kw):
        context = json.loads(kw['messages'][1]['content'])
        contexts.append(context)
        targets = choose(len(contexts), context)
        actions = [{'tool': 'httpx', 'target': target, 'reason': 'Read relevant evidence',
                    'priority': {'goal_relevance': 1, 'information_gain': 1,
                                 'evidence_value': 1, 'confidence': 1,
                                 'estimated_tokens': 10, 'estimated_seconds': 0.1,
                                 'estimated_requests': 1}} for target in targets]
        content = json.dumps({'actions': actions, 'rationale': 'Evidence-based next step',
                              'reflection': 'Review observed evidence and remaining limits'})
        return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=100, completion_tokens=30, total_tokens=130),
                               choices=[SimpleNamespace(message=SimpleNamespace(content=content))])

    def observe(state):
        target = state['planned_actions'][0]['target']
        dispatched.append(target)
        return {'http_services': state.get('http_services', []) + [{'url': target, 'status_code': 200}],
                'execution_metrics': {'tool_calls_used': len(dispatched)}}

    monkeypatch.setattr(planner.litellm, 'completion', completion)
    monkeypatch.setattr(registry, 'tool_handlers', lambda: {'httpx': observe})
    return contexts, dispatched


def run():
    return graph.invoke({'target': ['127.0.0.1'], 'max_iterations': 10,
                         'tool_call_budget': 10, 'token_budget': 10000},
                        config={'recursion_limit': 100})


def test_repeated_completed_action_stops_without_reexecution(monkeypatch):
    contexts, dispatched = install_model(monkeypatch, lambda call, context: ['http://127.0.0.1'])
    result = run()
    assert len(contexts) == 3 and dispatched == ['http://127.0.0.1']
    assert contexts[2]['policy_feedback']
    assert result['report']['stop_reason'] == 'policy_rejections_exhausted'
    assert result['report']['status'] == 'completed_partial'
    assert result['consecutive_policy_rejections'] == 2
    assert result['report']['http_services'][0]['status_code'] == 200


def test_rejected_decision_can_be_corrected_and_resets_streak(monkeypatch):
    def choose(call, context):
        return {1: ['http://outside.invalid'], 2: ['http://127.0.0.1/one'],
                3: ['http://outside.invalid'], 4: ['http://127.0.0.1/two']}.get(call, [])
    contexts, dispatched = install_model(monkeypatch, choose)
    result = run()
    assert len(contexts) == 5
    assert dispatched == ['http://127.0.0.1/one', 'http://127.0.0.1/two']
    assert result['report']['stop_reason'] == 'no_new_actions'
    assert result['consecutive_policy_rejections'] == 0


def test_out_of_scope_loop_stops_before_any_tool(monkeypatch):
    contexts, dispatched = install_model(monkeypatch, lambda call, context: ['http://outside.invalid'])
    result = run()
    assert len(contexts) == 2 and dispatched == []
    assert result['report']['stop_reason'] == 'policy_rejections_exhausted'


def test_candidate_alternative_executes_without_counting_a_rejection(monkeypatch):
    contexts, dispatched = install_model(monkeypatch, lambda call, context:
        ['http://outside.invalid', 'http://127.0.0.1'] if call == 1 else [])
    result = run()
    assert len(contexts) == 2 and dispatched == ['http://127.0.0.1']
    assert result['report']['stop_reason'] == 'no_new_actions'
    assert result['consecutive_policy_rejections'] == 0


def test_graph_honors_input_context_limit_before_provider_or_tool(monkeypatch):
    contexts, dispatched = install_model(monkeypatch, lambda call, context: ['http://127.0.0.1'])
    result = graph.invoke({'target': ['127.0.0.1'], 'model_context_tokens': 50})
    assert contexts == [] and dispatched == []
    assert result['report']['stop_reason'] == 'context_budget_exhausted'
    assert result['report']['status'] == 'completed_partial'
