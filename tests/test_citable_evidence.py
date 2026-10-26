"""A review that cites the run's own sealed evidence must be accepted.

Measured: after `verified_findings` began carrying sealed artifact paths, the model
correctly named them — and `grounded_review` rejected the review as "evidence not
present", stopping the run on its own best proof. The strongest evidence a run holds
has to be citable. A prose field returned as a list or object must also coerce instead
of discarding an otherwise valid decision.
"""
from src.adaptix.agents.review import grounded_review
from src.adaptix.agents.schema import PlannerDecision, ReflectionReview

SEALED = '/runs/v/verification-sqli.json'


def _decision(refs, status='achieved'):
    return PlannerDecision(
        actions=[], rationale='reviewed the stored verification artifacts',
        reflection='three classes are each backed by a sealed artifact',
        review=ReflectionReview(goal_status=status, evidence_refs=list(refs),
                                uncertainty='', failure='', decision_change='stop'))


def _state():
    return {
        'user_prompt': 'Prove three vulnerabilities.',
        'verification_evidence': [{'url': 'http://h/rest/products/search?q=a',
                                   'result': 'confirmed', 'evidence_ref': SEALED}],
        'injection_findings': [{'target': 'http://h/rest/products/search?q=a',
                                'parameter': 'q', 'verification_status': 'verified',
                                'verification_basis': 'differential_injection'}],
    }


def test_a_sealed_artifact_is_citable():
    _, errors = grounded_review(_state(), _decision([SEALED]))
    assert not any('not present' in message for message in errors), errors


def test_a_sealed_path_generated_by_the_run_is_not_rejected():
    _, errors = grounded_review(_state(), _decision(['/runs/v/never-issued.json']))
    assert errors
    assert any('not present' in message for message in errors)


def test_reflection_returned_as_a_list_is_coerced():
    decision = PlannerDecision.model_validate({
        'actions': [], 'rationale': 'r',
        'reflection': ['first observation', 'second observation'],
        'review': {'goal_status': 'uncertain', 'evidence_refs': [],
                   'uncertainty': '', 'failure': '', 'decision_change': 'continue'}})
    assert decision.reflection == 'first observation; second observation'


def test_reflection_returned_as_an_object_is_coerced():
    decision = PlannerDecision.model_validate({
        'actions': [], 'rationale': 'r', 'reflection': {'progress': 'one probe verified'},
        'review': {'goal_status': 'uncertain', 'evidence_refs': [],
                   'uncertainty': '', 'failure': '', 'decision_change': 'continue'}})
    assert 'one probe verified' in decision.reflection


def test_an_empty_reflection_is_still_refused():
    import pytest
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        PlannerDecision.model_validate({
            'actions': [], 'rationale': 'r', 'reflection': ['   '],
            'review': {'goal_status': 'uncertain', 'evidence_refs': [],
                       'uncertainty': '', 'failure': '', 'decision_change': 'c'}})
