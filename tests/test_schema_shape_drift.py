"""Schema validation must survive providers that cannot enforce the schema.

Measured against a real gateway: ``glm-5.3`` returned ``review.uncertainty`` as a
list on one pass and a plain string on the next. Because the transport was
``json_object`` - the gateway accepts ``json_schema`` and then ignores it - there
was nothing to stop either shape. Both passes were rejected by pydantic and the
run ended with ``planner_decision_invalid`` and zero actions, even though the
decisions themselves were correct and pointed at real routes.

The rule these tests hold: shape drift in a model-written *description* field must
be normalised, never turned into a lost planning pass. Fields that carry meaning
for correctness (tool name, target, priority bounds) must still be rejected.
"""
import json

import pytest
from pydantic import ValidationError

from src.adaptix.agents.schema import (
    Hypothesis,
    PlannerDecision,
    ReflectionReview,
    _as_text,
    _as_text_list,
)

REVIEW_AS_LIST = {
    'goal_status': 'in_progress',
    'evidence_refs': ['web_routes:abc'],
    'uncertainty': ['one unverified candidate', '/metrics undecided'],
    'failure': ['schema validation on both planning passes'],
    'decision_change': 'probe /api/BasketItems then replan',
}


def _decision(review):
    return {
        'actions': [{
            'tool': 'http_request',
            'target': 'http://127.0.0.1:3000/api/BasketItems',
            'reason': 'decide if basket data is exposed',
            'method': 'GET',
            'hypothesis': 'broken_access_control',
            'priority': {
                'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.8,
                'confidence': 0.4, 'estimated_tokens': 300, 'estimated_seconds': 5,
                'estimated_requests': 1,
            },
        }],
        'rationale': 'no responses observed yet',
        'reflection': 'keep output minimal and valid',
        'review': review,
        'advance_scope': False,
    }


def test_list_where_string_expected_is_joined_not_rejected():
    review = ReflectionReview.model_validate(REVIEW_AS_LIST)
    assert isinstance(review.uncertainty, str)
    assert 'one unverified candidate' in review.uncertainty
    assert '/metrics undecided' in review.uncertainty


def test_the_real_failing_payload_now_validates():
    """The exact response that ended a run is accepted."""
    decision = PlannerDecision.model_validate(_decision(REVIEW_AS_LIST))
    assert decision.actions[0].tool == 'http_request'
    assert isinstance(decision.review.uncertainty, str)


def test_string_where_list_expected_becomes_a_single_item_list():
    review = ReflectionReview.model_validate({
        'goal_status': 'in_progress',
        'evidence_refs': 'web_routes:abc',
        'uncertainty': 'nothing verified yet',
        'failure': '',
        'decision_change': 'validate a route',
    })
    assert review.evidence_refs == ['web_routes:abc']


def test_mixed_shape_is_strung_out_without_losing_references():
    review = ReflectionReview.model_validate({
        'goal_status': 'in_progress',
        'evidence_refs': ['web_routes:abc', {'candidates': '9b1d8cb3'}],
        'uncertainty': {'prometheus': 'unverified', 'metrics': 'undecided'},
        'failure': None,
        'decision_change': 'probe then replan',
    })
    assert review.failure == ''
    assert len(review.evidence_refs) == 2
    assert 'prometheus' in review.uncertainty


def test_hypothesis_refs_are_coerced_too():
    hyp = Hypothesis.model_validate({
        'category': 'broken_access_control',
        'target': 'http://127.0.0.1:3000/api/BasketItems',
        'rationale': 'exposed collection',
        'evidence_refs': 'web_routes:abc',
    })
    assert hyp.evidence_refs == ['web_routes:abc']


def _action(**overrides):
    base = {
        'tool': 'http_request',
        'target': 'http://127.0.0.1:3000/',
        'reason': 'x',
        'method': 'GET',
        'hypothesis': 'x',
        'priority': {'goal_relevance': 0.5, 'information_gain': 0.5, 'evidence_value': 0.5,
                     'confidence': 0.5, 'estimated_tokens': 1, 'estimated_seconds': 1,
                     'estimated_requests': 1},
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize('mutate,why', [
    (lambda p: p['actions'][0]['priority'].update(goal_relevance=9.0), 'priority out of bounds'),
    (lambda p: p['actions'][0]['priority'].update(confidence=-0.1), 'confidence below zero'),
    (lambda p: p['actions'][0].update(unexpected_key='boom'), 'extra key forbidden'),
    (lambda p: p.update(reflection=''), 'empty reflection'),
    (lambda p: p.update(advance_scope='not-a-bool'), 'advance_scope must be boolean'),
])
def test_correctness_fields_are_still_rejected(mutate, why):
    """Tolerance must not become permissiveness: meaning is still enforced."""
    payload = _decision(None)
    mutate(payload)
    with pytest.raises(ValidationError):
        PlannerDecision.model_validate(payload)


def test_unknown_tool_is_not_the_schema_s_job():
    """A tool name is free text here; the registry decides eligibility.

    Documented so nobody "fixes" the schema into a hardcoded tool list and then
    silently rejects a newly registered tool.
    """
    payload = _decision(None)
    payload['actions'] = [_action(tool='not_a_tool')]
    decision = PlannerDecision.model_validate(payload)
    assert decision.actions[0].tool == 'not_a_tool'



def test_helper_never_raises_on_arbitrary_json():
    for value in (None, 0, 1.5, True, [], {}, [[1, 2]], {'a': {'b': 'c'}}):
        assert isinstance(_as_text(value), str)
        assert isinstance(_as_text_list(value), list)
