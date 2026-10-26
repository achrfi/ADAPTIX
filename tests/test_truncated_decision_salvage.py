"""A truncated decision must be salvaged, not discarded.

Measured on a real gateway: `max_tokens=850` was ignored, output was hard-capped
at 2048, and both planning passes ended inside a string literal. Every action the
model had finished writing was correct and pointed at real routes, but the run
ended with `planner_decision_invalid` and zero actions.

Truncation is a transport fact. These tests pin the recovery, and pin its limits:
a document with no complete action must still fail rather than invent one.
"""
import json

import pytest

from src.adaptix.agents.schema import PlannerDecision, salvage_truncated_json

# The exact prefix shape a hard-capped gateway produced, cut mid-string.
TRUNCATED = (
    '{"actions":[{"tool":"httpx","target":"http://127.0.0.1:3000/rest/memories",'
    '"reason":"Establish if memories data answers unauthenticated","method":"GET",'
    '"body":"","headers":"","identity":"","marker":"","hypothesis":"information_disclosure",'
    '"profile":"","priority":{"goal_relevance":0.9,"information_gain":0.8,"evidence_value":0.8,'
    '"confidence":0.5,"estimated_tokens":400,"estimated_seconds":5,"estimated_requests":1}},'
    '{"tool":"httpx","target":"http://127.0.0.1:3000/metrics","reason":"Confirm metrics endpoint '
    'exposure implied by scanner row","method":"GET","body":"","headers":"","identity":"",'
    '"marker":"","hypothesis":"security_misconfiguration","profile":"","priority":'
    '{"goal_relevance":0.7,"information_gain":0.6,"evidence_value":0.6,"confidence":0.5,'
    '"estimated_tokens":400,"estimated_seconds":5,"estimated_requests":1}}],'
    '"rationale":"Endpoint inventory unfetched; validate two high-signal routes.",'
    '"reflection":"Only scanner candidates exist; confirm real endpoint behavior.",'
    '"hypotheses":[{"category":"information_disclosure","target":"http://127.0.0.1:3000/rest/memories",'
    '"rationale":"Memory route referenced in app'
)


def test_the_real_truncated_payload_is_salvaged():
    salvaged = salvage_truncated_json(TRUNCATED)
    assert salvaged is not None
    decision = PlannerDecision.model_validate_json(salvaged)
    assert len(decision.actions) == 2
    assert decision.actions[0].target.endswith('/rest/memories')
    assert decision.actions[1].target.endswith('/metrics')


def test_salvage_keeps_only_complete_actions():
    """A half-written third action must be dropped, not guessed at."""
    cut = TRUNCATED + ' incomplete tail of a third action'
    salvaged = salvage_truncated_json(cut)
    assert salvaged is not None
    decision = PlannerDecision.model_validate_json(salvaged)
    assert len(decision.actions) == 2


def test_no_complete_action_means_no_salvage():
    """Inventing an action would be worse than failing."""
    cut = '{"actions":[{"tool":"httpx","target":"http://127.0.0.1:3000/'
    assert salvage_truncated_json(cut) is None


def test_non_json_input_is_refused():
    for value in ('', '   ', 'not json at all', None):
        assert salvage_truncated_json(value) is None


def test_complete_but_invalid_json_is_not_salvaged():
    """Salvage is for truncation only, never for a schema the model got wrong.

    A complete document that fails validation must take the normal reject/retry
    path, where field feedback teaches the next attempt. Salvaging it would accept
    a decision the schema refused - an empty reflection, for example, which is a
    safety rule rather than a formatting one.
    """
    complete = json.dumps({
        'actions': [{
            'tool': 'httpx', 'target': 'http://127.0.0.1', 'reason': 'probe',
            'priority': {'goal_relevance': 0.8, 'information_gain': 0.7,
                         'evidence_value': 0.6, 'confidence': 0.9,
                         'estimated_tokens': 100, 'estimated_seconds': 1,
                         'estimated_requests': 1},
        }],
        'rationale': 'probe',
        'reflection': '',
    })
    assert salvage_truncated_json(complete) is None


def test_salvaged_decision_is_marked_trainable():
    """Recovery must never look like a clean parse to the caller."""
    salvaged = salvage_truncated_json(TRUNCATED)
    assert json.loads(salvaged)['actions']
