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
    import ast
    import inspect

    # The probe must return its object findings under the key the reflection stage
    # reads. Proved by reading the function's own return statement through the AST,
    # not by grepping one spelling of a dict literal: a reworded return value used
    # to fail this, while a stale mention of the old key in a comment was forbidden.
    tree = ast.parse(inspect.getsource(vuln_probes.authorization_probe))
    returned_keys = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Return):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Dict):
                    for key in inner.keys:
                        if isinstance(key, ast.Constant) and isinstance(key.value, str):
                            returned_keys.add(key.value)
    assert 'idor_findings' in returned_keys, (
        'authorization_probe does not return idor_findings; the reflection stage '
        f'consumes no object finding. Keys returned: {sorted(returned_keys)}')

    # And the unused key must not be returned anywhere in the module -- a comment
    # mentioning it is documentation, not a defect.
    module_tree = ast.parse(inspect.getsource(vuln_probes))
    bad = []
    for node in ast.walk(module_tree):
        if isinstance(node, ast.Return):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Dict):
                    for key in inner.keys:
                        if isinstance(key, ast.Constant) and key.value == 'authorization_findings':
                            bad.append(node.lineno)
    assert not bad, (
        f'authorization_findings is still returned at lines {bad}; no consumer '
        'reads that key')


# --------------------------------------------------------------- path traversal

class _FakeResponse:
    def __init__(self, url, text, status=200):
        self.url = url
        self.text = text
        self.status_code = status
        self.headers = {'content-type': 'text/plain'}
        self.content = text.encode()


def _fake_session(handler):
    """Replace the probe's HTTP layer with a table: url -> body.

    The traversal probe is tested on what it decides, not on whether the environment
    happens to have a live target: the handler decides which URLs leak a file, and the
    probe's answer must follow from that alone.
    """
    class _Session:
        def __init__(self, state):
            self.state = state
            self.errors = []
            self.metrics = {}
            self.raw = 0

        def get(self, url, headers=None):
            body = handler(url)
            return None if body is None else _FakeResponse(url, body)

        def record(self, response, state, limit=2048):
            return {'status_code': response.status_code, 'headers': response.headers,
                    'body_sha256': 'sha', 'body_excerpt': response.text[:limit],
                    'body_truncated': len(response.text) > limit, 'url': response.url}

        def close(self):
            pass

    return _Session


def _traversal_state(**extra):
    state = _state()
    state['web_routes'] = [{'url': 'http://t/ftp/legal.md', 'method': 'GET'},
                           {'url': 'http://t/', 'method': 'GET'}]
    state.update(extra)
    return state


def test_file_directories_only_use_proven_or_conventional_bases():
    """A traversal base must hold files; a login route is not one."""
    state = _traversal_state()
    state['web_routes'] += [{'url': 'http://t/rest/user/login'},
                            {'url': 'http://t/api/Users'}]
    dirs = vuln_probes._file_directories(state)
    assert set(dirs) == {'http://t/ftp'}
    # The noise that used to push the real base past the cap is gone.
    assert 'http://t/rest/user/login' not in dirs


def test_probe_signs_a_traversal_only_when_the_body_discloses_a_file(monkeypatch):
    generated = []

    def fake_record(state, template_id, url, method, request, row, detected, controls):
        generated.append({'url': url, 'detected': detected, 'controls': controls})
        return {'template_id': template_id, 'url': url, 'result': 'confirmed',
                'verification_basis': 'path_traversal', 'evidence_ref': 'ref-1'}

    monkeypatch.setattr(vuln_probes, '_Session',
                        _fake_session(lambda url: '{"name": "juice-shop", "scripts": {}}'
                                      if '%2500' in url else 'listing directory /ftp'))
    monkeypatch.setattr(vuln_probes, 'record_probe_verification', fake_record)

    out = vuln_probes.traversal_probe(_traversal_state())
    assert len(out['traversal_findings']) == 1
    finding = out['traversal_findings'][0]
    assert finding['verification_basis'] == 'path_traversal'
    # A finding must carry its template_id and proof, or reflection rebuilds it as
    # inconclusive however good the evidence was.
    assert finding['template_id'].startswith('adaptix-traversal-')
    assert finding['encoding'] == 'nul_bak'
    assert finding['verification_evidence']['result'] == 'confirmed'


def test_probe_refuses_a_hit_the_control_already_showed(monkeypatch):
    """A marker already in the control was not caused by the payload."""
    called = []
    monkeypatch.setattr(vuln_probes, '_Session',
                        _fake_session(lambda url: 'root:x:0:0:root:/root:/bin/bash'))
    monkeypatch.setattr(vuln_probes, 'record_probe_verification',
                        lambda *a, **k: called.append(a) or None)

    out = vuln_probes.traversal_probe(_traversal_state())
    assert out['traversal_findings'] == []
    assert called == []


def test_probe_reports_skipped_when_nothing_is_confirmed(monkeypatch):
    monkeypatch.setattr(vuln_probes, '_Session', _fake_session(lambda url: '<html>ok</html>'))
    out = vuln_probes.traversal_probe(_traversal_state())
    assert out['traversal_findings'] == []
    assert 'no payload disclosed a sensitive file' in str(out['events'])


def test_probe_does_nothing_without_a_file_backed_directory():
    state = _state()
    state['web_routes'] = [{'url': 'http://t/rest/user/login', 'method': 'GET'}]
    out = vuln_probes.traversal_probe(state)
    # An early exit returns events only, the same shape the other probes use.
    assert 'traversal_findings' not in out
    assert 'no file-backed directory observed' in str(out['events'])


def test_three_encoding_variants_are_present():
    """The roadmap required the dot-dot, percent-encoded and doubled forms."""
    labels = {label for label, _ in vuln_probes.TRAVERSAL_FRAMES}
    assert {'dotdot', 'encoded', 'doubled'} <= labels


def test_two_leaking_bases_are_both_reported(monkeypatch):
    """One confirmed base must not end the probe.

    Stopping at the first hit reported one finding and left every other directory
    silently untested: the operator had no way to tell "the rest is clean" from
    "the rest was never tried".
    """
    signed = []

    def fake_record(state, template_id, url, method, request, row, detected, controls):
        signed.append(url)
        return {'template_id': template_id, 'url': url, 'result': 'confirmed',
                'verification_basis': 'path_traversal', 'evidence_ref': 'ref-%d' % len(signed)}

    monkeypatch.setattr(vuln_probes, '_Session',
                        _fake_session(lambda url: '{"name": "leaked", "scripts": {}}'
                                      if url.endswith('%2500.md') else 'listing'))
    monkeypatch.setattr(vuln_probes, 'record_probe_verification', fake_record)

    state = _traversal_state()
    state['web_routes'] = [{'url': 'http://t/ftp/legal.md', 'method': 'GET'},
                           {'url': 'http://t/uploads/notes.txt', 'method': 'GET'}]
    out = vuln_probes.traversal_probe(state)

    targets = {f['target'] for f in out['traversal_findings']}
    assert targets == {'http://t/ftp/package.json.bak%2500.md',
                       'http://t/uploads/package.json.bak%2500.md'}
    assert len(out['traversal_findings']) == 2
    # The frame that leaks is the only one sent for its base: '%2500.md' appears twice,
    # once per base, and the earlier frames were tried before it.
    assert len(signed) == 2


def test_remaining_frames_are_skipped_once_one_leaks(monkeypatch):
    """Inside a base, a hit ends the frame list but not the directory list."""
    seen = []

    def handler(url):
        seen.append(url)
        return '{"a": "b", "scripts": {}}' if (url.endswith('%2500.md')
                                                or url.endswith('/package.json')) else 'listing'

    monkeypatch.setattr(vuln_probes, '_Session', _fake_session(handler))
    monkeypatch.setattr(vuln_probes, 'record_probe_verification',
                        lambda state, tid, url, m, req, row, det, ctl:
                        {'template_id': tid, 'url': url, 'result': 'confirmed',
                         'verification_basis': 'path_traversal', 'evidence_ref': 'r'})
    out = vuln_probes.traversal_probe(_traversal_state())
    # The first frame leaks, so 'deep' is never sent for that base.
    assert not any('/etc/passwd' in u for u in seen)
    assert len(out['traversal_findings']) == 1
