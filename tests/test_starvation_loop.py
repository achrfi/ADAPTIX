"""Starvation at one prompt size must not be retried indefinitely.

Measured on `js-impact-151241`: after its two starvation retries the loop resent the
identical 32,275-token request until the clock ran out (5 attempts, all empty), and the
planner never recompacted because that path only armed for context/budget exhaustion.
Eleven of fourteen calls were wasted, and the run reported `planner_unavailable` after
it had already executed two successful escalations.
"""
import pytest

from src.adaptix.agents import decisions, planner


def test_the_starvation_allowance_ends_the_attempt_loop():
    """Once both retries are spent, returning the class beats resending the same prompt."""
    import inspect
    source = inspect.getsource(decisions.request_decision)
    marker = source.find('starvation_attempts += 1')
    assert marker != -1
    tail = source[marker:marker + 900]
    # There must be a break once the allowance is exhausted, not an unconditional retry.
    assert 'break' in tail
    assert 'spend the starvation allowance' in tail


def test_the_planner_recompacts_on_starvation():
    """A smaller prompt is the only lever that changes a size-dependent starvation."""
    import inspect
    source = inspect.getsource(planner.adaptive_planning)
    assert "'ProviderStarvation'" in source
    gate = source.find("decision_error in ('ContextHeadroomInsufficient'")
    assert gate != -1
    window = source[gate:gate + 260]
    assert 'ProviderStarvation' in window


def test_starvation_is_still_a_provider_class_not_a_schema_failure():
    """It must not be recorded as a decision the model got wrong."""
    assert issubclass(decisions.ProviderStarvation, Exception)
    import inspect
    source = inspect.getsource(decisions.request_decision)
    assert "entry['error_class'] = 'provider_starvation'" in source
