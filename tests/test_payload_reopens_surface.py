"""A fresh payload reopens a surface; the refused value never does.

An earlier fix stopped the planner from re-offering surfaces the run had already
refused (see ``test_refused_surfaces.py``). That filter was too broad: a refusal is
recorded against a full request identity that includes the query string, so
condemning the whole surface hid a legitimate pivot - the same endpoint with a
different payload. Blind-injection work depends on exactly that move.

Rule locked here:
  * the same (path, value) pair is refused again;
  * the same path with a different value is allowed;
  * a surface already executed to completion stays closed whatever the value;
  * a refusal with no query parameter closes the path outright.
"""

import pytest

from src.adaptix.agents.planner import (
    _is_refused,
    _refused_surfaces,
    _value_bound_surfaces,
)

SEARCH = 'http://127.0.0.1:3000/rest/products/search?q=1'
SEARCH_OTHER = "http://127.0.0.1:3000/rest/products/search?q=%27%20OR%201%3D1--"
METRICS = 'http://127.0.0.1:3000/metrics'


def _state(rejected=(), attempted=()):
    return {
        'rejected_actions': [{'tool': 'http_request', 'target': t} for t in rejected],
        'attempted_actions': [{'tool': 'http_request', 'target': t} for t in attempted],
    }


def test_repeating_the_refused_value_is_refused():
    state = _state(rejected=[SEARCH])
    assert _is_refused(state, SEARCH, allow_value_bound=True) is True


def test_a_different_payload_reopens_the_surface():
    """The pivot this fix exists to protect."""
    state = _state(rejected=[SEARCH])
    assert _is_refused(state, SEARCH_OTHER, allow_value_bound=True) is False


def test_executed_surface_stays_closed_for_every_value():
    state = _state(rejected=[SEARCH], attempted=[SEARCH])
    assert _is_refused(state, SEARCH, allow_value_bound=True) is True
    assert _is_refused(state, SEARCH_OTHER, allow_value_bound=True) is True


def test_queryless_refusal_closes_the_path():
    state = _state(rejected=[METRICS])
    assert _is_refused(state, METRICS, allow_value_bound=True) is True
    assert METRICS.endswith('/metrics')
    assert _value_bound_surfaces(state) == set()


def test_value_bound_set_holds_the_surface_without_its_value():
    state = _state(rejected=[SEARCH])
    assert _refused_surfaces(state) == {('http', '127.0.0.1', 3000, '/rest/products/search')}
    assert _value_bound_surfaces(state) == {('http', '127.0.0.1', 3000, '/rest/products/search')}


def test_default_strict_mode_is_unchanged():
    """Without allow_value_bound the surface stays closed - old callers keep their
    semantics."""
    state = _state(rejected=[SEARCH])
    assert _is_refused(state, SEARCH) is True
    assert _is_refused(state, SEARCH_OTHER) is True


def test_unknown_surface_is_never_refused():
    state = _state(rejected=[SEARCH])
    assert _is_refused(state, 'http://127.0.0.1:3000/address/create', allow_value_bound=True) is False
