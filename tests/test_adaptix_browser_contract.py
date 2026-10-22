"""Focused contract tests for the browser_execution and boolean_injection replay
contracts, plus the signed probe paths that feed them.

The browser contract needs the shell of the browser session only (no Playwright);
the recorded trace is exactly what ``browser_test`` stores. The boolean contract
needs three deterministic companion observations around a truthy GET probe, which
``http_request`` issues in production; here a loopback lab supplies the behavior.
"""
import hashlib
import http.server
import threading

import pytest

from src.adaptix.evidence.verification import replay_result, write_verification_record, load_valid_proof
from src.adaptix.security import authorization as auth
from src.adaptix.tools import web

STATE = {
    'run_id': 'contract-3ed5f921', 'target': ['http://127.0.0.1'], 'hosts': ['127.0.0.1'],
    'scope_ports': [80], 'scope_manifest': {'hosts': ['127.0.0.1'], 'networks': [], 'aliases': {}},
    'execution_metrics': {}, 'raw_bytes': 0, 'errors': [], 'events': [], 'verification_evidence': []}


class _BoolLab(http.server.BaseHTTPRequestHandler):
    """Falsy/clean share one body; the truthy predicate changes the returned data."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        from urllib.parse import parse_qs, urlsplit
        params = {k: v[0] for k, v in parse_qs(urlsplit(self.path).query, keep_blank_values=True).items()}
        value = params.get('q', '')
        if 'and 1=2' in value.lower():
            body = '<p>clean catalog</p>'
        elif 'adaptix_control' in value:
            body = '<p>clean catalog</p>'
        elif 'or 1=1' in value.lower():
            body = '<p>ALLUSERS admin backupFlagged</p>'  # data the predicate changed
        else:
            body = '<p>clean catalog</p>'
        data = body.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture(scope='module')
def bool_lab():
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _BoolLab)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f'http://127.0.0.1:{server.server_address[1]}'


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch, bool_lab):
    state = dict(STATE)
    state['target'] = [bool_lab]
    state['scope_ports'] = [server_address := int(bool_lab.rsplit(':', 1)[1])]
    monkeypatch.setattr(auth, 'KEY_PATH', tmp_path / 'key')
    auth._key(create=True)
    monkeypatch.setattr(web, 'throttle', lambda: None)
    return state


def _browser_record(url, marker, payload_dialogs, control_dialogs, result_state):
    return {
        'template_id': 'browser-' + marker, 'url': url, 'method': 'GET',
        'verification_method': 'deterministic_replay', 'verification_basis': 'browser_execution',
        'requests': [{'method': 'GET', 'url': url}, {'method': 'GET', 'url': url.replace(marker, '')}],
        'responses': [{'status_code': 200, 'headers': {}, 'body_sha256': hashlib.sha256(b'p').hexdigest(),
                       'body_excerpt': '<p>x</p>'},
                      {'status_code': 200, 'headers': {}, 'body_sha256': hashlib.sha256(b'c').hexdigest(),
                       'body_excerpt': '<p>y</p>'}],
        'browser': {'marker': marker, 'dialog_messages': payload_dialogs,
                    'control_dialog_messages': control_dialogs, 'url': url.replace(marker, '')},
        'steps': ['Payload navigation', 'Control navigation'],
        'expected_behavior': 'no dialog on the marker-free control',
        'actual_behavior': 'marker dialog only on the payload navigation'}


def test_browser_contract_confirms_only_a_payload_dialog():
    url = 'http://127.0.0.1/vuln/xss?q=%3Cscript%3Ealert(%27mrkA31js9%27)%3C%2Fscript%3E'
    record = _browser_record(url, 'mrkA31js9', ['alert(mrkA31js9) executed'], [], None)
    assert replay_result(record) == 'confirmed'
    proof = write_verification_record(STATE, record)
    assert proof['result'] == 'confirmed'
    assert load_valid_proof({'template_id': 'browser-mrkA31js9', 'url': proof['url']}, proof, STATE['run_id'])['result'] == 'confirmed'


def test_browser_contract_refutes_when_the_control_dialog_carries_the_marker():
    url = 'http://127.0.0.1/vuln/xss?q=%3Cscript%3Ealert(%27mrkB42kds8%27)%3C%2Fscript%3E'
    record = _browser_record(url, 'mrkB42kds8', ['alert(mrkB42kds8) executed'], ['merge site script mrkB42kds8'], None)
    assert replay_result(record) == 'refuted'
    proof = write_verification_record(STATE, record)
    assert proof['result'] == 'refuted'


def test_browser_contract_stays_inconclusive_without_any_dialog():
    url = 'http://127.0.0.1/vuln/xss?q=%3Cscript%3Ealert(%27mrkC73ksd2%27)%3C%2Fscript%3E'
    record = _browser_record(url, 'mrkC73ksd2', [], [], None)
    assert replay_result(record) is None
    with pytest.raises(ValueError, match='replay proof'):
        write_verification_record(STATE, record)


def test_browser_contract_rejects_invalid_markers():
    url = 'http://127.0.0.1/vuln/xss?q=%3Cscript%3Ealert(%27x%3C%3F%27)%3C%2Fscript%3E'
    assert replay_result(_browser_record(url, 'x<?', ['alert()'], [], None)) is None
    assert replay_result({'verification_basis': 'browser_execution', 'requests': [], 'responses': [],
                          'browser': {}}) is None


def test_boolean_oracle_signed_from_lab_companions(_state: dict):
    from src.adaptix.evidence.web_signatures import detect
    url = f"{_state['target'][0]}/catalog?q='or 1=1"
    probes = web._payload_candidates(url)
    assert any('or 1=1' in (web._truthy_token(p) or '') for p in probes) or any(
        web._truthy_token(p) for p in probes)
    trace = {'url': url, 'method': 'GET', 'status_code': 200, 'body_sha256': '', 'request_fingerprint':
             hashlib.sha256(url.encode()).hexdigest(), 'identity': None}
    working = {**_state, 'tool_call_budget': 40}
    # Issue the truthy probe and its deterministic companions through the real helpers.
    truthy = web._request(working, url, 'GET')
    row = web.response_record(truthy, web.scenario_secrets(working))
    trace['body_sha256'] = hashlib.sha256(truthy.content).hexdigest()
    trace['status_code'] = truthy.status_code
    trace['body_excerpt'] = truthy.text[:2048]
    from src.adaptix.evidence.sanitize import scenario_secrets
    companions, errors = web._boolean_companions(working, trace)
    assert not errors
    kinds = [kind for kind, *_ in companions]
    assert kinds == ['falsy', 'clean', 'repeat']
    record = web._boolean_probe_verification(_state, trace, companions, row)
    assert record is not None and record['result'] == 'confirmed'
    loaded = load_valid_proof({'template_id': record['template_id'], 'url': record['url']}, record, _state['run_id'])
    oracle = loaded['boolean_oracle']
    assert len(set(oracle['truthy_sha256'])) == 1
    assert oracle['falsy_sha256'] == oracle['clean_sha256'] != oracle['truthy_sha256'][0]
    assert replay_result(loaded) == loaded['result']
