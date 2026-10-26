"""Deterministic class probes must sign only on their own contract.

These tests pin the three defects found while running the probes against a target
with no OpenAPI document: a single-object response was invisible to record
extraction, a detail route was probed with a placeholder id, and the control body
was truncated so the differential contract could never trust it clean.
"""
import json

import pytest

from src.adaptix.tools import vuln_probes


ROUTES = [
    {'url': 'http://127.0.0.1:3000/rest/products/search?q=', 'method': 'GET'},
    {'url': 'http://127.0.0.1:3000/rest/basket/placeholder', 'method': 'GET'},
    {'url': 'http://127.0.0.1:3000/', 'method': 'GET'},
]


def _state(**extra):
    state = {'run_id': 'test-probes', 'identity_context': {
        'identity_url': 'http://127.0.0.1:3000/rest/user/whoami',
        'identities': [{'name': 'owner', 'headers': {'Cookie': 'token=owner'}},
                       {'name': 'other', 'headers': {'Cookie': 'token=other'}}]},
        'web_routes': list(ROUTES), 'api_operations': [], 'api_observations': [],
        'verification_evidence': [], 'errors': [], 'events': [],
        'execution_metrics': {}, 'raw_bytes': 0}
    state.update(extra)
    return state


def test_single_object_response_is_a_record():
    """A detail endpoint answers with one object, not a row list."""
    assert vuln_probes._records_of({'data': {'id': 8, 'UserId': 1}}) == [{'id': 8, 'UserId': 1}]
    assert vuln_probes._records_of({'user': {'email': 'a@b'}}) == [{'email': 'a@b'}]
    # A list body still yields its rows.
    assert vuln_probes._records_of({'data': [{'id': 1}, {'id': 2}]}) == [{'id': 1}, {'id': 2}]


def test_detail_templates_use_the_observed_placeholder():
    state = _state()
    templates = vuln_probes._detail_templates(state)
    assert templates['http://127.0.0.1:3000/rest/basket'] == 'http://127.0.0.1:3000/rest/basket/placeholder'


def test_search_targets_require_an_observed_parameter():
    targets = vuln_probes._search_targets(_state(), {})
    assert list(targets) == ['http://127.0.0.1:3000/rest/products/search?q=']
    assert targets['http://127.0.0.1:3000/rest/products/search?q='] == ('q', '')
    # Plain documents carry no parameter and must never be injected into.
    assert 'http://127.0.0.1:3000/' not in targets


def test_falsy_twin_changes_the_operator():
    """`OR 1=1` -> `OR 1=2` is still true; the operator has to become AND."""
    import re
    truthy = "a')) OR 1=1--"
    falsy = re.sub(r'\bor\b', 'and', truthy, count=1, flags=re.I).replace('1=1', '1=2', 1)
    assert falsy == "a')) and 1=2--"
    assert 'or' not in falsy.lower()


def test_control_body_is_kept_whole_up_to_the_cap():
    """A truncated control can never be trusted clean by the differential contract."""
    assert vuln_probes.CONTROL_EXCERPT >= 200_000


def test_probes_are_registered_under_the_coverage_classes():
    from src.adaptix.reporting.coverage import TOOL_CLASSES
    assert 'sql_injection' in TOOL_CLASSES['injection_probe']
    assert 'broken_object_level_authorization' in TOOL_CLASSES['authorization_probe']
    assert 'cross_site_scripting' in TOOL_CLASSES['script_probe']


def test_object_findings_use_the_key_reflection_consumes():
    """`authorization_findings` was read by nobody; idor_findings already is."""
    import inspect
    assert "'idor_findings': findings" in inspect.getsource(vuln_probes.authorization_probe)
    # The unused key must not reappear anywhere in the module.
    assert "'authorization_findings'" not in inspect.getsource(vuln_probes)
