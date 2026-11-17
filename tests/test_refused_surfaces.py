"""Refused surfaces stay refused: a closed set is not re-offered as alternatives.

An observed run (ui-225618) cycled between three surfaces the run had already
refused - /rest/products/search, /rest/user/security-question and /metrics - for six
consecutive passes. Two separate mechanisms let it happen:

1. ``_fixation`` reset its counter whenever the proposed surface differed from the
   previous pass, so alternating S -> M -> S read as three fresh attempts and the
   escalation directive never fired.
2. Every rejection re-advertised the refused surfaces in its ``alternatives`` list,
   because the planner only looked at the pass it was in, never at what the run had
   already turned down.

Both are locked here. The counter must survive cycling, and a surface that was
refused anywhere in the run's history must not be offered as a suggestion again.
"""
from src.adaptix.agents import planner

P = 'http://127.0.0.1:3000/rest/products/search?q='
S = 'http://127.0.0.1:3000/rest/user/security-question?email='
M = 'http://127.0.0.1:3000/metrics'
FRESH = 'http://127.0.0.1:3000/address/create'


def _denial(target, code='previously_rejected'):
    return {'action': {'tool': 'http_request', 'target': target}, 'code': code}


def _refused(*targets):
    from src.adaptix.security.scope import endpoint_key
    return [list(endpoint_key(t)[:4]) for t in targets]


def test_counter_survives_alternating_surfaces():
    """S -> M -> S is one continuing loop, not three fresh attempts."""
    state = {'refused_surfaces': _refused(P, S, M)}
    counts = []
    for target in (P, S, M, S, P):
        key, count = planner._fixation(state, [_denial(target)])
        state['fixated_targets'] = (key, count)
        counts.append(count)
    assert counts == [1, 2, 3, 4, 5], f'the loop must accumulate, got {counts}'
    assert counts[-1] >= planner._FIXATION_LIMIT


def test_counter_resets_only_for_a_genuinely_new_surface():
    state = {'refused_surfaces': _refused(P)}
    _, count = planner._fixation(state, [_denial(P)])
    assert count == 1
    state['fixated_targets'] = ({('http', '127.0.0.1', 3000, '/rest/products/search')}, 1)
    # A surface never refused before is a restart.
    _, count = planner._fixation(state, [_denial(FRESH)])
    assert count == 1


def test_multi_surface_refusal_does_not_clear_the_counter():
    """Two refused surfaces in one pass is cycling, not a clean slate."""
    state = {'refused_surfaces': _refused(P, S)}
    key, count = planner._fixation(state, [_denial(P), _denial(S)])
    assert count == 1, 'first sighting starts the count'
    assert isinstance(key, set) and len(key) == 2, 'both surfaces must be tracked'
    state['fixated_targets'] = (key, count)
    key, count = planner._fixation(state, [_denial(P), _denial(S)])
    assert count == 2, 'a repeated multi-surface refusal must accumulate, not reset'
    state['fixated_targets'] = (key, count)
    key, count = planner._fixation(state, [_denial(P), _denial(S)])
    assert count == 3


def test_refused_surfaces_reads_the_whole_history():
    state = {'rejected_actions': [{'tool': 'http_request', 'target': P},
                                  {'tool': 'http_request', 'target': S}]}
    refused = planner._refused_surfaces(state)
    assert len(refused) == 2
    assert planner._is_refused(state, P)
    assert planner._is_refused(state, S)
    assert not planner._is_refused(state, FRESH)


def test_is_refused_ignores_parameter_variation():
    """Refusal is per surface: changing the query value is still the same surface."""
    state = {'rejected_actions': [{'tool': 'http_request', 'target': P}]}
    assert planner._is_refused(state, 'http://127.0.0.1:3000/rest/products/search?q=1')
    assert planner._is_refused(state, 'http://127.0.0.1:3000/rest/products/search?q=%27')


def test_refused_surface_is_not_offered_as_an_alternative():
    refused = planner._refused_surfaces(
        {'rejected_actions': [{'tool': 'http_request', 'target': P}]})
    candidates = [P, FRESH, S]
    offered = [t for t in candidates if not planner._is_refused({'rejected_actions': []}, t, refused)]
    assert P not in offered, 'a refused surface must never come back as a suggestion'
    assert FRESH in offered, 'an untried surface must remain offerable'


def test_as_surface_set_accepts_every_persisted_shape():
    """A resumed checkpoint can carry an old scalar key or a new collection."""
    flat = ('http', '127.0.0.1', 3000, '/a')
    assert planner._as_surface_set(flat) == {flat}
    assert planner._as_surface_set([flat]) == {flat}
    assert planner._as_surface_set([flat, ('http', 'h', 80, '/b')]) == {
        flat, ('http', 'h', 80, '/b')}
    assert planner._as_surface_set({flat}) == {flat}
    assert planner._as_surface_set(None) == set()
    assert planner._as_surface_set('') == set()


def test_refused_surfaces_are_persisted_in_the_state_delta():
    """The history has to survive the pass, or the next one repeats the offer."""
    source = open(planner.__file__, encoding='utf-8').read()
    assert "'refused_surfaces': sorted(refused_surfaces)" in source, \
        'the refusal history must be written back to graph state'
    assert "'fixated_targets': fixated,\n            'refused_surfaces': sorted(refused_surfaces)," in source, \
        'it must sit in the same state delta as the fixation counter'


def test_refused_surfaces_is_declared_in_the_graph_state():
    """An undeclared key is dropped by the checkpointer on resume."""
    from src.adaptix.workflow import graph as graph_module
    source = open(graph_module.__file__, encoding='utf-8').read()
    assert 'refused_surfaces: list' in source
