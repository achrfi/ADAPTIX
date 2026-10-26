"""The returned state must keep `scope_window` a list of target units.

Measured on `js-impact-153348`: the recompaction retry reused the local name `window` for
the model context size, and the return dict wrote that integer into `scope_window`. The
next planner pass crashed in `prioritize()` with `TypeError: 'int' object is not
iterable`, discarding a run that had already executed a successful escalation.
"""
import inspect

from src.adaptix.agents import planner


def test_the_retry_does_not_reuse_the_scope_window_name():
    source = inspect.getsource(planner.adaptive_planning)
    # The integer context size must be bound to its own name. Check assignments only:
    # the fix's own comment quotes the old buggy line.
    assignments = [line.strip() for line in source.splitlines()
                   if '=' in line and 'model_context_tokens' in line
                   and not line.strip().startswith('#')]
    assert assignments
    for line in assignments:
        assert not line.startswith('window ='), line
    assert any(line.startswith('context_window =') for line in assignments), assignments


def test_returned_state_scope_window_is_a_list():
    """The contract the next pass relies on: iterate it, index it, pop from it."""
    window = planner.scope_window({'units': ['http://127.0.0.1:3000/'], 'hosts': ['127.0.0.1'],
                                  'aliases': {}, 'networks': [], 'total_units': 1},
                                 [], 5)
    assert isinstance(window, list)
    assert all(isinstance(unit, str) for unit in window)
    # And the consumer that crashed accepts it.
    from src.adaptix.agents.evidence_context import prioritize
    prioritize('web_routes', [], {'scope_window': window, 'attempted_actions': []})


def test_prioritize_rejects_an_integer_window_loudly():
    """Guard the class of corruption, not just the one call site that produced it."""
    import pytest
    from src.adaptix.agents.evidence_context import prioritize
    with pytest.raises(TypeError):
        prioritize('web_routes', [], {'scope_window': 65536, 'attempted_actions': []})
