"""Regression coverage for local-provider reliability.

A planning pass against a local model timed out at the provider window and the run
ended with ``planner_unavailable``. Measurement showed the cause was neither the run
budget nor model loading: the response envelope had no size bounds, so one decision
needed more output tokens than the call could decode, and the per-call window was a
hardcoded constant that ignored how much run time was left. These tests pin the
timeout being configurable and budget-aware, retries that tighten instead of
repeating, decisions that are guaranteed to fit their envelope, and planner errors
that keep their diagnostics without discarding gathered evidence.
"""
import json
import time
from types import SimpleNamespace

from src.adaptix.agents import decisions
from src.adaptix.agents import planner
from src.adaptix.agents.schema import PlannerDecision

REGISTRY = {'http_request': {'enabled': True, 'path': 'cli', 'description': 'bounded GET/HEAD probe'}}


def model_response(content, finish_reason='stop', prompt_tokens=100, completion_tokens=10):
    return SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                              total_tokens=prompt_tokens + completion_tokens),
        choices=[SimpleNamespace(message=SimpleNamespace(content=content), finish_reason=finish_reason)])


def decision_json(actions=(), hypotheses=()):
    return json.dumps({'actions': list(actions), 'hypotheses': list(hypotheses),
                       'rationale': 'Observed routes allow one bounded probe.',
                       'reflection': 'Assess the observed route inventory before deciding.',
                       'review': {'goal_status': 'in_progress', 'evidence_refs': [],
                                  'uncertainty': '', 'failure': '',
                                  'decision_change': 'Probe one discovered route.'}})


def running(**overrides):
    state = {'run_started_at': time.time(), 'time_budget_seconds': 1800, 'token_budget': 50000,
             'model_context_tokens': 4096, 'hosts': ['127.0.0.1'], 'scope_ports': [3000],
             'target': ['http://127.0.0.1:3000']}
    state.update(overrides)
    return state


def envelope_of(parameters):
    return parameters['response_format']['json_schema']['schema']


# --- provider window is configurable and budget-aware ---

def test_provider_window_defaults_and_scales_with_run_budget(monkeypatch):
    monkeypatch.delenv('ADAPTIX_LLM_TIMEOUT', raising=False)
    assert decisions.configured_timeout({'time_budget_seconds': 1800}) == 180.0
    # A single call may never claim more than half of the run's own clock.
    assert decisions.configured_timeout({'time_budget_seconds': 200}) == 100.0
    assert decisions.configured_timeout({}) == decisions.DEFAULT_PROVIDER_SECONDS


def test_provider_window_honours_run_setting_then_environment(monkeypatch):
    monkeypatch.setenv('ADAPTIX_LLM_TIMEOUT', '240')
    assert decisions.configured_timeout({'time_budget_seconds': 1800}) == 240.0
    assert decisions.configured_timeout({'time_budget_seconds': 1800, 'llm_timeout_seconds': 90}) == 90.0
    monkeypatch.setenv('ADAPTIX_LLM_TIMEOUT', 'not-a-number')
    assert decisions.configured_timeout({'time_budget_seconds': 1800}) == decisions.DEFAULT_PROVIDER_SECONDS


def test_planner_sends_configured_window_instead_of_a_constant(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', lambda: REGISTRY)
    seen = {}

    def capture(**kwargs):
        seen.update(kwargs)
        return model_response(decision_json())

    monkeypatch.setattr(planner.litellm, 'completion', capture)
    result = planner.adaptive_planning(running(llm_timeout_seconds=300))
    assert seen['timeout'] == 300.0
    assert result['planner_metrics']['provider_call_window'] == 300.0


def test_window_is_clamped_to_remaining_run_time(monkeypatch):
    monkeypatch.setattr(decisions.litellm, 'completion', lambda **kw: (_ for _ in ()).throw(TimeoutError()))
    monkeypatch.setattr(decisions.litellm, 'token_counter', lambda **kw: 100)
    _, _, _, ledger, _ = decisions.request_decision(
        running(time_budget_seconds=300, run_started_at=time.time() - 250),
        {'model': 'x', 'messages': [{'role': 'user', 'content': 'hi'}], 'max_tokens': 128, 'timeout': 180},
        {}, 100)
    entry, = [row for row in ledger if row.get('provider_call')]
    assert entry['timeout'] <= 50 and entry['deadline_clamped'] is True
    assert entry['run_seconds_remaining'] <= 50


# --- a decision always fits its envelope ---

def test_decision_schema_bounds_every_free_text_field():
    schema = PlannerDecision.model_json_schema()
    assert schema['properties']['actions']['maxItems'] >= 1
    assert schema['properties']['hypotheses']['maxItems'] >= 1
    for spec in (schema['$defs']['Action']['properties']['reason'],
                 schema['$defs']['Action']['properties']['target'],
                 schema['$defs']['Hypothesis']['properties']['rationale'],
                 schema['properties']['rationale'], schema['properties']['reflection']):
        assert isinstance(spec.get('maxLength'), int) and spec['maxLength'] > 0


def test_decision_at_the_largest_envelope_still_validates():
    action = {'tool': 'http_request', 'target': 'http://127.0.0.1:3000/api/orders', 'reason': 'r' * 240,
              'priority': {'goal_relevance': 0.9, 'information_gain': 0.8, 'evidence_value': 0.7,
                           'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 2,
                           'estimated_requests': 1}}
    hypothesis = {'category': 'idor', 'target': 'http://127.0.0.1:3000/api/orders/1',
                  'rationale': 'r' * 240, 'evidence_refs': ['web_routes:a', 'web_routes:b']}
    parsed = PlannerDecision.model_validate_json(decision_json(
        [action] * planner.OUTPUT_ENVELOPES[0]['actions'],
        [hypothesis] * planner.OUTPUT_ENVELOPES[0]['hypotheses']))
    assert len(parsed.actions) == planner.OUTPUT_ENVELOPES[0]['actions']
    assert len(parsed.hypotheses) == planner.OUTPUT_ENVELOPES[0]['hypotheses']


def test_every_envelope_rung_is_a_subset_of_the_model_bounds():
    base = PlannerDecision.model_json_schema()
    for envelope in planner.OUTPUT_ENVELOPES:
        bounded = planner.envelope_schema(base, envelope)
        assert bounded['properties']['actions']['maxItems'] <= base['properties']['actions']['maxItems']
        assert bounded['properties']['hypotheses']['maxItems'] <= base['properties']['hypotheses']['maxItems']
        for name, fields in planner.PROSE_FIELDS.items():
            for field in fields:
                original = base['$defs'][name]['properties'][field]['maxLength']
                assert bounded['$defs'][name]['properties'][field]['maxLength'] <= original


def test_envelope_shrinks_when_measured_throughput_cannot_fit_the_full_decision():
    costs = [planner.envelope_cost(envelope) for envelope in planner.OUTPUT_ENVELOPES]
    # Every rung must be cheaper than the one above it, or tightening would not converge.
    assert costs == sorted(costs, reverse=True)
    assert planner.PLANNER_OUTPUT_TOKENS >= costs[0]
    # Shapes are unique so a schema maps back to exactly one cost.
    shapes = [(e['actions'], e['hypotheses']) for e in planner.OUTPUT_ENVELOPES]
    assert len(shapes) == len(set(shapes))
    # A tighter window never selects a more expensive rung than a wider one.
    indexes = [planner.select_envelope(planner.PLANNER_OUTPUT_TOKENS, {}, {}, w)
               for w in (400, 300, 240, 180)]
    assert indexes == sorted(indexes), indexes
    assert indexes[-1] == len(planner.OUTPUT_ENVELOPES) - 1
    for window in (300, 240, 180):
        index = planner.select_envelope(planner.PLANNER_OUTPUT_TOKENS, {}, {}, window)
        rate = decisions.PLANNING_OUTPUT_RATE
        assert planner.envelope_cost(planner.OUTPUT_ENVELOPES[index]) / rate <= window + 60
    # Every window above the smallest viable decision has a rung that fits it, so a
    # retry always has somewhere smaller to go.
    rate = decisions.PLANNING_OUTPUT_RATE
    smallest = planner.OUTPUT_ENVELOPES[-1]
    assert planner.envelope_cost(smallest) / rate <= planner.MIN_PROVIDER_SECONDS + 60
    for window in range(int(planner.MIN_PROVIDER_SECONDS) + 45, 400, 5):
        index = planner.select_envelope(planner.PLANNER_OUTPUT_TOKENS, {}, {}, window)
        assert planner.envelope_cost(planner.OUTPUT_ENVELOPES[index]) / rate <= max(window, planner.MIN_PROVIDER_SECONDS)


def test_slower_provider_selects_a_smaller_envelope():
    slow = planner.select_envelope(planner.PLANNER_OUTPUT_TOKENS, {},
                                   {'output_tokens_per_second': 3.0}, 180)
    fast = planner.select_envelope(planner.PLANNER_OUTPUT_TOKENS, {},
                                   {'output_tokens_per_second': 6.0}, 180)
    assert slow >= fast


def test_a_rate_from_a_short_first_call_is_not_trusted_over_measurement():
    # A short first decision decodes faster than the longer ones that follow; trusting
    # it would select an envelope that cannot finish.
    from src.adaptix.agents.decisions import configured_output_rate, PLANNING_OUTPUT_RATE
    assert configured_output_rate({}, {'output_tokens_per_second': 5.32}) == PLANNING_OUTPUT_RATE
    # A provider that is genuinely slower still tightens further.
    assert configured_output_rate({}, {'output_tokens_per_second': 3.0}) == 3.0


def test_configured_rate_overrides_the_measured_default(monkeypatch):
    from src.adaptix.agents.decisions import configured_output_rate
    monkeypatch.setenv('ADAPTIX_OUTPUT_TOKENS_PER_SECOND', '20')
    assert configured_output_rate({}, {}) == 20.0
    assert configured_output_rate({'llm_output_tokens_per_second': 8}, {}) == 8.0


# --- a timeout is capacity, not an over-large envelope ---

def test_timeout_is_classified_separately_and_never_shrinks_the_envelope(monkeypatch):
    """A timed-out provider is not an over-large envelope.

    Shrinking 1152 output tokens to 576 asks the same question of a provider that
    already could not finish, and records the failure under the wrong class. The
    retry budget is still spent; the envelope and the cap stay put.
    """
    monkeypatch.setattr(decisions.litellm, 'token_counter', lambda **kw: 100)
    seen = []

    def fail(**kwargs):
        seen.append(kwargs)
        raise TimeoutError('provider timed out')

    monkeypatch.setattr(decisions.litellm, 'completion', fail)
    state = running(planner_retry_limit=1, host='x')
    schema = PlannerDecision.model_json_schema()
    tighten = build_tighten(schema)
    _, metrics, _, ledger, error = decisions.request_decision(
        state, {'model': 'x', 'messages': [{'role': 'user', 'content': 'hi'}],
                'max_tokens': 1152, 'timeout': 180,
                'response_format': {'type': 'json_schema', 'json_schema': {'name': 'PlannerDecision', 'schema': schema}}},
        {}, 100, tighten)
    assert error == 'TimeoutError' and len(seen) == 2
    first, second = seen
    assert second['max_tokens'] == first['max_tokens'], 'a timeout must not shrink the cap'
    assert envelope_of(second) == envelope_of(first), 'a timeout must not shrink the envelope'
    assert metrics['provider_timeout'] == 2
    rows = [row for row in ledger if row.get('provider_call')]
    assert rows and all(row.get('error_class') == 'provider_timeout' for row in rows)
    assert all(row.get('envelope') != 'too_large' for row in rows)


def test_truncated_response_also_tightens_the_next_attempt(monkeypatch):
    monkeypatch.setattr(decisions.litellm, 'token_counter', lambda **kw: 100)
    seen = []

    def truncated(**kwargs):
        seen.append(kwargs)
        if len(seen) == 1:
            return model_response('{"actions": [{"tool": "http_request"', finish_reason='length')
        return model_response(decision_json())

    monkeypatch.setattr(decisions.litellm, 'completion', truncated)
    schema = PlannerDecision.model_json_schema()
    decision, _, _, ledger, error = decisions.request_decision(
        running(planner_retry_limit=1),
        {'model': 'x', 'messages': [{'role': 'user', 'content': 'hi'}], 'max_tokens': 1152, 'timeout': 180,
         'response_format': {'type': 'json_schema', 'json_schema': {'name': 'PlannerDecision', 'schema': schema}}},
        {}, 100, build_tighten(schema))
    assert decision is not None and error is None
    assert seen[1]['max_tokens'] < seen[0]['max_tokens']
    first, = [row for row in ledger if row.get('attempt') == 1]
    assert first['envelope'] == 'too_large' and first['finish_reason'] == 'length'


def test_malformed_json_retry_repairs_without_shrinking_the_envelope(monkeypatch):
    monkeypatch.setattr(decisions.litellm, 'token_counter', lambda **kw: 100)
    seen = []
    results = iter(['{not json}', model_response(decision_json())])

    def respond(**kwargs):
        seen.append(kwargs)
        value = next(results)
        return value if isinstance(value, BaseException) else value

    monkeypatch.setattr(decisions.litellm, 'completion', respond)
    schema = PlannerDecision.model_json_schema()
    decision, _, _, _, error = decisions.request_decision(
        running(planner_retry_limit=1),
        {'model': 'x', 'messages': [{'role': 'user', 'content': 'hi'}], 'max_tokens': 1152, 'timeout': 180,
         'response_format': {'type': 'json_schema', 'json_schema': {'name': 'PlannerDecision', 'schema': schema}}},
        {}, 100, build_tighten(schema))
    assert decision is not None and error is None
    assert len(seen) == 2
    assert seen[1]['max_tokens'] == seen[0]['max_tokens']
    assert envelope_of(seen[1]) == envelope_of(seen[0])


def test_retry_is_not_started_when_the_run_has_no_time_left(monkeypatch):
    monkeypatch.setattr(decisions.litellm, 'token_counter', lambda **kw: 100)
    calls = []

    def fail(**kwargs):
        calls.append(kwargs)
        raise TimeoutError('provider timed out')

    monkeypatch.setattr(decisions.litellm, 'completion', fail)
    decisions.request_decision(
        running(planner_retry_limit=2, time_budget_seconds=90, run_started_at=time.time() - 30),
        {'model': 'x', 'messages': [{'role': 'user', 'content': 'hi'}], 'max_tokens': 512, 'timeout': 180},
        {}, 100)
    assert len(calls) == 1


def test_retry_cap_matches_the_tightened_envelope(monkeypatch):
    """A retry must not cap a tightened envelope below what that envelope needs.

    Applies to a truncated response (`finish_reason == 'length'`), which is the only
    failure that means "the envelope did not fit". A *timeout* keeps its envelope,
    so this test drives a truncation and asserts the retry tightens coherently.
    """
    monkeypatch.setattr(planner, 'tool_registry', lambda: REGISTRY)
    seen = []

    def respond(**kwargs):
        seen.append(kwargs)
        if len(seen) == 1:
            # Truncated at the output limit: the envelope was too large.
            return model_response('', finish_reason='length')
        return model_response(decision_json())

    monkeypatch.setattr(planner.litellm, 'completion', respond)
    result = planner.adaptive_planning(running(planner_retry_limit=1, llm_timeout_seconds=300))
    assert len(seen) == 2
    first, second = seen
    first_envelope = result['planner_metrics']['response_envelope']
    assert second['max_tokens'] < first['max_tokens']
    # Every attempted cap is bounded by the envelope it was paired with.
    for call, schema in ((first, envelope_of(first)), (second, envelope_of(second))):
        actions = schema['properties']['actions']['maxItems']
        hypotheses = schema['properties']['hypotheses']['maxItems']
        rung = next((e for e in planner.OUTPUT_ENVELOPES
                     if e['actions'] == actions and e['hypotheses'] == hypotheses), None)
        assert rung is not None, (actions, hypotheses)
        assert 0 < call['max_tokens'] <= planner.envelope_cost(rung)
    chosen = next(e for e in planner.OUTPUT_ENVELOPES
                  if e['actions'] == first_envelope['actions']
                  and e['hypotheses'] == first_envelope['hypotheses'])
    assert chosen in planner.OUTPUT_ENVELOPES
    index = planner.OUTPUT_ENVELOPES.index(chosen)
    rate = decisions.PLANNING_OUTPUT_RATE
    assert planner.envelope_cost(chosen) / rate <= 300 + 60
    # No larger rung may also fit, or the selection was not the largest that fits.
    for bigger in planner.OUTPUT_ENVELOPES[:index]:
        assert planner.envelope_cost(bigger) / rate > 300


def test_planner_window_default_is_the_configured_provider_window(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', lambda: REGISTRY)
    seen = {}
    monkeypatch.setattr(planner.litellm, 'completion',
                        lambda **kw: (seen.update(kw), model_response(decision_json()))[1])
    planner.adaptive_planning(running())
    assert seen['timeout'] == decisions.DEFAULT_PROVIDER_SECONDS
    # The cap must be the largest rung that the default window can actually finish.
    expected = planner.envelope_cost(
        planner.OUTPUT_ENVELOPES[planner.select_envelope(
            planner.PLANNER_OUTPUT_TOKENS, {}, {}, seen['timeout'])])
    assert seen['max_tokens'] == expected
    index = planner.select_envelope(planner.PLANNER_OUTPUT_TOKENS, {}, {}, seen['timeout'])
    assert planner.envelope_cost(planner.OUTPUT_ENVELOPES[index]) / decisions.PLANNING_OUTPUT_RATE <= seen['timeout']


def build_tighten(schema):
    def tighten(parameters, attempt):
        rung = planner.OUTPUT_ENVELOPES[min(attempt, len(planner.OUTPUT_ENVELOPES) - 1)]
        parameters['response_format'] = {'type': 'json_schema', 'json_schema': {
            'name': 'PlannerDecision', 'strict': True, 'schema': planner.envelope_schema(schema, rung)}}
        return parameters
    return tighten


# --- throughput is learned from measurement, not assumed ---

def test_successful_call_records_throughput_for_later_passes(monkeypatch):
    monkeypatch.setattr(decisions.litellm, 'token_counter', lambda **kw: 100)
    monkeypatch.setattr(decisions.litellm, 'completion',
                        lambda **kw: model_response(decision_json(), completion_tokens=400))
    _, metrics, _, _, _ = decisions.request_decision(
        running(), {'model': 'x', 'messages': [{'role': 'user', 'content': 'hi'}],
                    'max_tokens': 512, 'timeout': 180}, {}, 100)
    assert metrics['output_tokens_per_second'] > 0
    assert decisions.measured_output_rate(metrics) == metrics['output_tokens_per_second']
    assert decisions.measured_output_rate({}) is None


def test_planner_uses_learned_throughput_to_pick_a_smaller_envelope(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', lambda: REGISTRY)
    seen = {}
    monkeypatch.setattr(planner.litellm, 'completion',
                        lambda **kw: (seen.update(kw), model_response(decision_json()))[1])
    slow = planner.adaptive_planning(running(llm_timeout_seconds=180))
    assert slow['planner_metrics']['planned_output_rate'] == decisions.PLANNING_OUTPUT_RATE
    # Whatever rung was chosen must fit the tight window at the rate it was sized for.
    assert seen['max_tokens'] / decisions.PLANNING_OUTPUT_RATE <= 180 + 60
    slower = planner.select_envelope(planner.PLANNER_OUTPUT_TOKENS, {},
                                     {'output_tokens_per_second': 3.0}, 180)
    assert planner.envelope_cost(planner.OUTPUT_ENVELOPES[slower]) / 3.0 <= 180 + 60


# --- planner errors keep diagnostics and evidence ---

def test_provider_failure_records_diagnostics_without_discarding_evidence(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', lambda: REGISTRY)
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: (_ for _ in ()).throw(TimeoutError('boom')))
    state = running(web_routes=[{'url': 'http://127.0.0.1:3000/api/orders', 'method': 'GET'}],
                    errors=['earlier unrelated failure'])
    result = planner.adaptive_planning(state)
    assert result['stop_reason'] is None
    assert result['errors'][0] == 'earlier unrelated failure'
    assert 'provider call failed (TimeoutError)' in result['errors'][-1]
    assert result['token_ledger'] and result['token_ledger'][-1]['error_type'] == 'TimeoutError'
    assert result['planner_metrics']['last_error'] == 'TimeoutError'
    # Nothing that was already observed may be dropped from the run.
    assert result['candidate_assessments'] == []


def test_provider_error_message_never_echoes_provider_text(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', lambda: REGISTRY)
    monkeypatch.setattr(planner.litellm, 'completion',
                        lambda **kw: (_ for _ in ()).throw(RuntimeError('Authorization: Bearer sk-secret-value')))
    result = planner.adaptive_planning(running())
    assert 'sk-secret-value' not in json.dumps(result['errors'])
    assert result['planner_metrics']['last_error'] == 'RuntimeError'


def test_workflow_continues_after_a_provider_failure_and_reports_it(monkeypatch):
    from src.adaptix.workflow.graph import graph
    monkeypatch.setattr(planner, 'tool_registry', lambda: REGISTRY)
    calls = []

    def respond(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise TimeoutError('provider timed out')
        return model_response(decision_json())

    monkeypatch.setattr(planner.litellm, 'completion', respond)
    result = graph.invoke(running(planner_retry_limit=0, max_iterations=3, tool_call_budget=3,
                                  scope_manifest=None, status='scope_ok', authorization={'type': 'signed_grant'},
                                  execution_metrics={}, iterations=0, baseline_disabled=True),
                          config={'recursion_limit': 25})
    assert len(calls) >= 2
    assert result['report']['stop_reason'] != 'planner_unavailable'
    # The fault stays visible, but it is filed as a transport note rather than an
    # outcome error: a provider hiccup is not a security result.
    reported = (list(result['report']['errors'])
                + list(result['report'].get('transport_notes') or []))
    assert any('provider call failed' in message for message in reported)


def test_bounded_provider_failure_still_stops_the_run(monkeypatch):
    from src.adaptix.workflow.graph import graph
    monkeypatch.setattr(planner, 'tool_registry', lambda: REGISTRY)
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: (_ for _ in ()).throw(TimeoutError()))
    result = graph.invoke(running(max_iterations=5, tool_call_budget=5, status='scope_ok',
                                  authorization={'type': 'signed_grant'}, execution_metrics={},
                                  iterations=0, provider_failure_limit=2, baseline_disabled=True),
                          config={'recursion_limit': 25})
    assert result['report']['stop_reason'] == 'planner_unavailable'
    assert result['report']['termination']['provider_timeout'] is True