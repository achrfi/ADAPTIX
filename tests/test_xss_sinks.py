"""The XSS probe must derive its sinks from the map, and still confirm on a real sink.

Measured defect this locks: the probe built `/#/search?q=` as a literal, so the browser
stage could only ever find XSS on an application whose sink sits on that exact route.
"""
import sys

sys.path.insert(0, '/root/projects/adaptix')

from src.adaptix.evidence.xss_sinks import candidate_sinks, ROUTER_PARAMETERS


def _state():
    return {'web_routes': [
        {'url': 'http://h/', 'kind': 'document', 'method': 'GET'},
        {'url': 'http://h/chunk-abc.js', 'kind': 'script', 'method': 'GET'},
        {'url': 'http://h/assets/logo.png', 'kind': 'link', 'method': 'GET'},
        {'url': 'http://h/rest/products/search?q=', 'kind': 'script_route', 'method': 'GET'},
        {'url': 'http://h/api/Challenges/?key=', 'kind': 'script_route', 'method': 'GET'},
        {'url': 'http://h/review?productId=', 'kind': 'script_route', 'method': 'GET'},
    ]}


def test_a_hash_route_is_a_candidate_even_though_no_server_route_names_it():
    sinks = candidate_sinks(_state())
    fragments = [row for row in sinks if row[0] == 'fragment']
    assert fragments, sinks
    # The entry document plus a router parameter; q must be among them.
    assert fragments[0][1].startswith('http://h'), fragments[0]
    assert 'q' in {row[2] for row in fragments}, fragments


def test_parameters_come_from_the_mapped_routes_not_a_literal():
    sinks = candidate_sinks(_state())
    query_sinks = {(row[1], row[2]) for row in sinks if row[0] == 'query'}
    assert ('http://h/rest/products/search', 'q') in query_sinks, query_sinks
    assert ('http://h/review', 'productId') in query_sinks, query_sinks


def test_an_api_path_is_not_offered_as_a_browser_sink():
    """A JSON response cannot reflect a tag into an HTML document."""
    sinks = candidate_sinks(_state())
    targets = ' '.join(row[1] for row in sinks)
    assert '/api/' not in targets, sinks


def test_static_assets_and_the_copy_javascript_are_not_sinks():
    sinks = candidate_sinks(_state())
    targets = ' '.join(row[1] for row in sinks)
    assert 'chunk-abc.js' not in targets, targets
    assert 'logo.png' not in targets, targets


def test_a_target_with_no_mapped_surface_yields_no_candidates():
    assert candidate_sinks({}) == []
    assert candidate_sinks({'web_routes': []}) == []


def test_candidates_are_bounded_and_deterministic():
    first = candidate_sinks(_state(), limit=5)
    second = candidate_sinks(_state(), limit=5)
    assert first == second
    assert len(first) <= 5


def test_the_probe_module_no_longer_carries_a_literal_fragment():
    source = open('/root/projects/adaptix/src/adaptix/tools/vuln_probes.py').read()
    assert '/#/search?q=' not in source, 'the literal sink is still in the probe'
