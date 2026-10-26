"""Planner decisions must survive a large target.

Three measured defects made every planning pass on a 74-route SPA fail:
  1. the largest output envelope (1216 tokens) was below what a real decision needs, so
     every response ended at `finish_reason=length` with the JSON cut mid-object;
  2. a complete response could still be rejected for prose length alone
     (`string_too_long`), discarding a usable decision over a cosmetic cap;
  3. the prompt demanded 130/90 characters while the validator enforced 400/240, so a
     model obeying neither was refused for a limit it was never told.
"""
import json

import pytest

from src.adaptix.agents import planner as P
from src.adaptix.agents.prose_fit import fit_prose, _max_length


def test_largest_envelope_can_carry_a_real_decision():
    """Measured: a complete decision on a large target used 1.8-2.4k output tokens."""
    assert P.OUTPUT_ENVELOPES[0]['tokens'] >= 2048
    for smaller, larger in zip(P.OUTPUT_ENVELOPES[1:], P.OUTPUT_ENVELOPES):
        assert smaller['tokens'] < larger['tokens']
        assert smaller['actions'] <= larger['actions']


def test_output_cap_tracks_the_largest_envelope():
    """A fixed literal here silently re-capped the first pass at the old ceiling."""
    assert P.PLANNER_OUTPUT_TOKENS == P.OUTPUT_ENVELOPES[0]['tokens']


def test_prompt_caps_come_from_the_validator():
    """The instruction and the enforced contract can never drift apart again."""
    assert P.PROSE_CAPS['rationale'] == _max_length(('rationale',))
    assert P.PROSE_CAPS['review'] == _max_length(('review', 'uncertainty'))
    assert P.PROSE_CAPS['reason'] == _max_length(('Action', 'reason'))


def test_optional_nested_review_is_unwrapped():
    """`review` is declared `ReflectionReview | None`; the cap lives behind the union."""
    assert _max_length(('review', 'failure')) == 240
    assert _max_length(('review', 'decision_change')) == 240


def test_overlong_prose_is_fitted_not_rejected():
    body = {'actions': [], 'rationale': 'r' * 900, 'reflection': 'f' * 900,
            'review': {'goal_status': 'uncertain', 'evidence_refs': [],
                       'uncertainty': 'u' * 900, 'failure': 'x' * 900,
                       'decision_change': 'd' * 900}}
    fitted, trimmed = fit_prose(json.dumps(body))
    assert fitted is not None
    assert set(trimmed) == {'rationale', 'reflection', 'review.uncertainty',
                            'review.failure', 'review.decision_change'}
    out = json.loads(fitted)
    assert len(out['rationale']) <= 400
    assert len(out['review']['uncertainty']) <= 240
    # Structured values are never touched by a prose fit.
    assert out['review']['goal_status'] == 'uncertain'
    assert out['actions'] == []


def test_structured_fields_are_never_trimmed():
    """Only prose paths are eligible; an action or evidence ref is never shortened."""
    from src.adaptix.agents.prose_fit import PROSE_PATHS
    flat = {'.'.join(path) for path in PROSE_PATHS}
    for forbidden in ('actions', 'target', 'tool', 'review.goal_status',
                      'review.evidence_refs', 'hypotheses'):
        assert forbidden not in flat


def test_fit_is_a_no_op_when_prose_already_fits():
    body = {'actions': [], 'rationale': 'short', 'reflection': 'short',
            'review': {'goal_status': 'achieved', 'evidence_refs': ['x'],
                       'uncertainty': '', 'failure': '', 'decision_change': 'stop'}}
    fitted, trimmed = fit_prose(json.dumps(body))
    assert fitted is None and trimmed == []


def test_prompt_states_flat_action_shape():
    """Without this rule the model wrapped parameters in `args` (extra_forbidden)."""
    import inspect
    source = inspect.getsource(P)
    assert 'never under "args"' in source
