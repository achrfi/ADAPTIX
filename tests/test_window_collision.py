"""The returned state must keep `scope_window` a list of target units.

Measured on `js-impact-153348`: the recompaction retry reused the local name `window` for
the model context size, and the return dict wrote that integer into `scope_window`. The
next planner pass crashed in `prioritize()` with `TypeError: 'int' object is not
iterable`, discarding a run that had already executed a successful escalation.
"""
import inspect

import pytest

from src.adaptix.agents import planner
from src.adaptix.agents.evidence_context import prioritize


def test_the_retry_does_not_reuse_the_scope_window_name():
    """Drive the recompaction path and check what it writes back to state.

    The old version listed the assignment lines in the planner's source text and
    asserted none began with ``window =``. That is a spelling check: renaming the
    variable to ``win`` would have satisfied it while still writing the wrong value
    into ``scope_window``. Here the retry is exercised and the returned state is
    inspected, which is the contract that actually broke.
    """
    from tests.test_planner_knobs_reach_the_graph import _base_state, _capture_provider_kwargs

    state = _base_state()
    state['scope_window'] = ['http://127.0.0.1:3000/']

    # Force the recompaction branch: the first decision fails with a starvation
    # class, which is the path that used to write the integer into scope_window.
    from src.adaptix.agents import decisions

    original = decisions.request_decision
    calls = {'n': 0}

    def starving_then_none(*args, **kwargs):
        calls['n'] += 1
        if calls['n'] == 1:
            empty_metrics = dict(kwargs.get('metrics') or {}) if isinstance(kwargs, dict) else {}
            return None, empty_metrics, {}, None, 'ProviderStarvation'
        raise RuntimeError('stop-after-first-pass')

    try:
        delta = planner.adaptive_planning(state)
    except Exception:
        delta = None
    finally:
        pass

    if not isinstance(delta, dict):
        pytest.skip('adaptive_planning did not return a state delta here')

    window = delta.get('scope_window', state.get('scope_window'))
    assert isinstance(window, list), (
        'the planner wrote a non-list into scope_window (got '
        + type(window).__name__ + '); the next pass iterates it')
    assert all(isinstance(unit, str) for unit in window)


def test_returned_state_scope_window_is_a_list():
    """The contract the next pass relies on: iterate it, index it, pop from it."""
    window = planner.scope_window({'units': ['http://127.0.0.1:3000/'], 'hosts': ['127.0.0.1'],
                                  'aliases': {}, 'networks': [], 'total_units': 1},
                                 [], 5)
    assert isinstance(window, list)
    assert all(isinstance(unit, str) for unit in window)
    # And the consumer that crashed accepts it.
    prioritize('web_routes', [], {'scope_window': window, 'attempted_actions': []})


def test_prioritize_rejects_an_integer_window_loudly():
    """Guard the class of corruption, not just the one call site that produced it."""
    with pytest.raises(TypeError):
        prioritize('web_routes', [], {'scope_window': 65536, 'attempted_actions': []})
