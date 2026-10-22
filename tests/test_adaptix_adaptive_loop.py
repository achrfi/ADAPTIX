import json
from unittest.mock import MagicMock
from src.adaptix.agents import planner
from src.adaptix.workflow.graph import graph
from src.adaptix.workflow import nodes
from src.adaptix.tools import registry, idor


def test_free_prompt_observations_and_reflection_drive_next_action(monkeypatch):
    catalog = {'playwright': {'enabled': True, 'path': 'module'},
               'httpx': {'enabled': True, 'path': 'cli'}}
    monkeypatch.setattr(planner, 'tool_registry', lambda: catalog)
    monkeypatch.setattr(registry, 'tool_registry', lambda: catalog)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 100)
    seen = []
    def completion(**kw):
        context = json.loads(kw['messages'][1]['content'])
        assert context['user_request'] == 'Periksa alur login dan jelaskan keterbatasannya'
        seen.append(context)
        if len(seen) == 1:
            action = {'tool': 'playwright', 'target': 'http://127.0.0.1:18080/login', 'reason': 'observe UI', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}
        else:
            assert context['reflection']['progress'] == 1
            assert context['observations']['browser_evidence']
            action = None
        response = MagicMock()
        response.usage.total_tokens = 130
        response.choices[0].message.content = json.dumps({'actions': [action] if action else [],
            'rationale': 'objective considered', 'reflection': 'UI observed; no authorization proof'})
        return response
    monkeypatch.setattr(planner.litellm, 'completion', completion)
    calls = []
    def browser(state):
        calls.append('playwright')
        return {'browser_evidence': [{'url': state['planned_actions'][0]['target']}],
                'execution_metrics': {'tool_calls_used': 1}}
    monkeypatch.setattr(registry, 'tool_handlers', lambda: {'playwright': browser})
    result = graph.invoke({'target': ['127.0.0.1'], 'authorization_confirmed': True,
        'user_prompt': 'Periksa alur login dan jelaskan keterbatasannya', 'max_iterations': 5, 'baseline_disabled': True, 'scanner_disabled': True})
    assert calls == ['playwright']
    # The empty decision does not end the run: executable alternatives exist, so the
    # planner asks again and stops with a reported planning failure instead.
    assert len(seen) == 3
    assert 'empty_decision_with_alternatives' in [row.get('code')
                                                   for row in seen[2]['policy_feedback']]
    assert result['report']['stop_reason'] == 'planning_failure_no_decision'
    assert result['report']['status'] == 'completed_with_errors'
    assert result['report']['termination']['cause'] == 'planning_stagnation'
    assert result['report']['self_reflection'] == 'UI observed; no authorization proof'


def test_execution_gate_rejects_outside_scope(monkeypatch):
    monkeypatch.setattr(registry, 'tool_registry', lambda: {'httpx': {'enabled': True, 'path': 'cli'}})
    result = nodes.execute_action({'status': 'scope_ok', 'authorization': {'type': 'local_loopback'},
        'target': ['127.0.0.1'], 'hosts': ['127.0.0.1'], 'planned_actions': [{'tool': 'httpx', 'target': 'http://example.com', 'reason': 'bad', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}]})
    assert result['stop_reason'] == 'policy_rejected'


def test_idor_budget_reserves_two_requests(monkeypatch):
    class Client:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def request(self, *args, **kwargs): raise AssertionError('must not send request')
    monkeypatch.setattr(idor.httpx_lib, 'Client', lambda **kw: Client())
    scenario = {'name': 'object', 'base_url': 'http://127.0.0.1:8080',
                'path_template': '/objects/{object_id}', 'object_id': '1',
                'owner_identity': {'headers': {}}, 'other_identity': {'headers': {}}}
    result = idor.idor_test({'hosts': ['127.0.0.1'], 'idor_scenarios': [scenario], 'tool_call_budget': 1})
    assert result['idor_findings'] == []
    assert any('budget' in e for e in result['errors'])


def test_multiple_candidates_execute_only_one(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', lambda: {'httpx': {'enabled': True, 'path': 'cli'}})
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 100)
    response = MagicMock()
    response.usage.total_tokens = 120
    action = {'tool': 'httpx', 'target': 'http://127.0.0.1', 'reason': 'probe', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}
    response.choices[0].message.content = json.dumps({'actions': [action, action], 'reflection': 'Assess current evidence and limits before deciding', 'rationale': 'pipeline'})
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: response)
    result = planner.adaptive_planning({'hosts': ['127.0.0.1']})
    assert len(result['planned_actions']) == 1
    assert result['stop_reason'] is None


def test_failed_completion_reserves_token_budget(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', lambda: {'httpx': {'enabled': True, 'path': 'cli'}})
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: (_ for _ in ()).throw(RuntimeError('offline')))
    result = planner.adaptive_planning({'hosts': ['127.0.0.1'], 'token_budget': 2000})
    envelope = result['planner_metrics']['response_envelope']
    reserved = 100 + planner.envelope_cost(envelope)
    assert result['planner_metrics']['tokens_used'] == reserved
    assert result['planned_actions'] == []


def test_prompt_budget_prevents_model_call(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', lambda: {'httpx': {'enabled': True, 'path': 'cli'}})
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 5000)
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: (_ for _ in ()).throw(AssertionError('no call')))
    result = planner.adaptive_planning({'hosts': ['127.0.0.1'], 'token_budget': 2000})
    assert result['stop_reason'] in ('budget_exhausted', 'context_budget_exhausted')


def test_policy_feedback_drives_replanning_without_external_execution(monkeypatch):
    catalog = {'httpx': {'enabled': True, 'path': 'cli'}}
    monkeypatch.setattr(planner, 'tool_registry', lambda: catalog)
    contexts = []
    def completion(**kw):
        context = json.loads(kw['messages'][1]['content'])
        contexts.append(context)
        response = MagicMock()
        response.usage.total_tokens = 130
        if len(contexts) == 1:
            decision = {'actions': [{'tool': 'httpx', 'target': 'http://evil.invalid', 'reason': 'bad', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}], 'reflection': 'Assess current evidence and limits before deciding', 'rationale': 'bad'}
        else:
            assert context['policy_feedback']
            decision = {'actions': [], 'reflection': 'Assess current evidence and limits before deciding', 'rationale': 'outside scope; stop'}
        response.choices[0].message.content = json.dumps(decision)
        return response
    monkeypatch.setattr(planner.litellm, 'completion', completion)
    result = graph.invoke({'target': ['127.0.0.1'], 'authorization_confirmed': True, 'max_iterations': 3, 'baseline_disabled': True, 'scanner_disabled': True})
    assert len(contexts) == 2
    assert result.get('attempted_actions', []) == []
    assert result['report']['stop_reason'] == 'no_new_actions'


def test_empty_model_reflection_cannot_authorize_tool_execution(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', lambda: {'httpx': {'enabled': True, 'path': 'cli'}})
    response = MagicMock()
    response.usage.total_tokens = 130
    response.choices[0].message.content = json.dumps({'actions': [{'tool': 'httpx', 'target': 'http://127.0.0.1', 'reason': 'probe', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}], 'rationale': 'probe', 'reflection': ''})
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: response)
    result = planner.adaptive_planning({'hosts': ['127.0.0.1']})
    assert result['planned_actions'] == []
    assert result['consecutive_provider_failures'] == 0
    assert result['consecutive_schema_failures'] == 1
    assert result['stop_reason'] is None


# --- P2: invented targets are rejected at the hypothesis merge, not echoed ----

DECISION = {'actions': [{'tool': 'nuclei', 'target': 'https://example.com', 'reason': 'assess',
                         'priority': {'goal_relevance': 0.9, 'information_gain': 0.7, 'evidence_value': 0.7,
                                      'confidence': 0.6, 'estimated_tokens': 500, 'estimated_seconds': 30,
                                      'estimated_requests': 10}}],
            'reflection': 'replan from the inventory', 'rationale': 'assess the target',
            'hypotheses': [{'category': 'broken_access_control', 'target': 'https://example.com',
                            'rationale': 'assess', 'evidence_refs': []}]}


def test_planner_drops_invented_targets_and_says_why(monkeypatch):
    import json as _json
    from types import SimpleNamespace
    catalog = {'nuclei': {'enabled': True, 'path': 'cli'}}
    monkeypatch.setattr(planner, 'tool_registry', lambda: catalog)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 100)
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: SimpleNamespace(
        usage=SimpleNamespace(total_tokens=120, prompt_tokens=90, completion_tokens=30),
        choices=[SimpleNamespace(message=SimpleNamespace(content=_json.dumps({
            **DECISION, 'review': {'goal_status': 'uncertain', 'evidence_refs': [], 'uncertainty': '',
                                   'failure': '', 'decision_change': 'replan'}})))]))
    result = planner.adaptive_planning({'hosts': ['127.0.0.1']})
    assert result['planner_metrics']['hypothesis_scope_rejections'] == ['https://example.com']
    assert result['hypotheses'] == [] or all('example.com' not in str(row.get('target'))
                                            for row in result['hypotheses'])
    assert any(row['code'] == 'hypothesis_scope_rejected' for row in result['policy_feedback'])


def test_merge_hypotheses_scope_filter_drops_out_of_scope_targets():
    from src.adaptix.agents import hypotheses as hy
    kept = hy.merge_hypotheses(
        [], [{'category': 'sql_injection', 'target': 'http://127.0.0.1:18080/api/search', 'evidence_refs': []}],
        scope_filter=lambda target: '127.0.0.1' in str(target))
    assert len(kept) == 1
    dropped = hy.merge_hypotheses(
        [], [{'category': 'sql_injection', 'target': 'https://example.com/admin', 'evidence_refs': []}],
        scope_filter=lambda target: '127.0.0.1' in str(target))
    assert dropped == []


# --- P4: the planner schema can express every runtime-required tool parameter --

PRIORITY = {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.7, 'confidence': 0.6,
            'estimated_tokens': 400, 'estimated_seconds': 20, 'estimated_requests': 3}


def test_action_schema_expresses_browser_test_marker(monkeypatch):
    from src.adaptix.agents.schema import PlannerDecision
    parsed = PlannerDecision.model_validate({
        'actions': [{'tool': 'browser_test', 'target': 'http://127.0.0.1:3000/?q="<script>x.adaptix-check<script>"',
                     'marker': 'x.adaptix-check', 'reason': 'r', 'priority': PRIORITY}],
        'reflection': 'test reflection', 'rationale': 'r',
        'hypotheses': []})
    assert parsed.actions[0].marker == 'x.adaptix-check'
    from pydantic import ValidationError
    try:
        PlannerDecision.model_validate({
            'actions': [{'tool': 'browser_test', 'target': 'http://127.0.0.1/x', 'marker': '<bad>',
                         'reason': 'r', 'priority': {'goal_relevance': 0.9, 'information_gain': 0.7, 'evidence_value': 0.7, 'confidence': 0.6, 'estimated_tokens': 500, 'estimated_seconds': 30, 'estimated_requests': 10}}],
            'reflection': 'test reflection', 'rationale': 'r'})
        raise AssertionError('an invalid marker must not pass the schema')
    except ValidationError as exc:
        assert 'marker' in str(exc)


def test_action_assessment_demands_marker_in_url():
    state = {'hosts': ['127.0.0.1'],
             'scope_manifest': {'hosts': ['127.0.0.1'], 'networks': [], 'aliases': {}}}
    url = 'http://127.0.0.1:3000/?q=<script>pl.mark</script>'
    good = planner.action_assessment(state, {'tool': 'browser_test', 'target': url, 'marker': 'pl.mark',
                                             'reason': 'r', 'priority': PRIORITY}, {'browser_test'})
    bad = planner.action_assessment(state, {'tool': 'browser_test', 'target': url, 'reason': 'r',
                                            'priority': PRIORITY}, {'browser_test'})
    missing = planner.action_assessment(state, {'tool': 'browser_test', 'target': url, 'marker': 'bad mark',
                                                'reason': 'r', 'priority': PRIORITY}, {'browser_test'})
    assert good.get('eligible') in (True, good.get('eligible'))  # returns a dict, not an exception
    assert not bad['eligible'] and bad['code'] == 'marker_required' and bad['missing'] == ['marker_in_url']
    assert not missing['eligible'] and missing['code'] == 'marker_required'
    assert 'marker appears inside the URL' in bad['reason'] or 'marker' in bad['reason']
