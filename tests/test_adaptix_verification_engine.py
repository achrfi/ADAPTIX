"""Positive and negative controls for the verification engine, over real HTTP.

A throwaway loopback lab (authorized by construction: 127.0.0.1, ephemeral port) serves
genuinely vulnerable routes and deliberately secure ones. The engine must verify every
vulnerable route from signed replayable evidence, and must never verify the secure or
the evidence-insufficient ones - no HTTP status, severity label or LLM claim can.
"""
import hashlib
import json
import html
import http.server
import threading

import pytest

from src.adaptix.agents import reflector
from src.adaptix.evidence.verification import load_valid_proof
from src.adaptix.security import authorization as auth
from src.adaptix.tools import web

PASSWD = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/false\n'


class _Lab(http.server.BaseHTTPRequestHandler):
    """Positive controls: sqli, xss, traversal, multi. Negative: secure-sqli/xss, noisy."""

    def log_message(self, *args):
        pass

    def _send(self, code, body, content_type='text/html; charset=utf-8'):
        data = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        from urllib.parse import parse_qs, urlsplit
        query = urlsplit(self.path).query
        params = {key: values[0] for key, values in parse_qs(query, keep_blank_values=True).items()}
        value = params.get('q', params.get('file', ''))
        path = urlsplit(self.path).path
        if path == '/vuln/sqli':
            if any(char in value for char in '\'"`'):
                self._send(500, f'Fatal: <b>You have an error in your SQL syntax</b> near {value!r}')
            else:
                self._send(200, '<p>catalog page</p>')
        elif path == '/secure/sqli':  # parameterized handler: input never reaches the DB
            self._send(200, '<p>catalog page</p>')
        elif path == '/noisy/sqli':  # errors on every response, input or not
            self._send(500, 'You have an error in your SQL syntax near internal')
        elif path == '/vuln/xss':
            self._send(200, f'<p>echo: {value}</p>')
        elif path == '/secure/xss':
            self._send(200, f'<p>echo: {html.escape(value, quote=True)}</p>')
        elif path == '/vuln/traversal':
            if '../' in value or '%' in query:
                self._send(200, f'<pre>{PASSWD}</pre>', 'text/plain')
            else:
                self._send(200, 'index of files: readme.txt', 'text/plain')
        elif path == '/vuln/multi':
            if any(char in value for char in '\'"`') and '<script' in value.lower():
                self._send(500, f'You have an error in your SQL syntax near <b>{value}</b>')
            else:
                self._send(200, '<p>catalog page</p>')
        elif path == '/vuln/keys':  # unambiguous credential material: never an echo game
            self._send(200, 'aws_access_key_id = AKIAAAEKSAMPLEKEYZQ1; region eu-west-1', 'text/plain')
        elif path == '/docs/example-keys':  # placeholder the rule family still detects
            self._send(200, 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE; from the official documentation',
                       'text/plain')
        elif path == '/vuln/sqli-late':  # error text sits beyond the stored excerpt cut
            if any(char in value for char in '\'"`'):
                self._send(500, 'You have an error in your SQL syntax near the quoted input')
            else:
                padding = 'x' * 3000  # marker lands after the 2048-char excerpt window
                self._send(200, padding + 'internal: You have an error in your SQL syntax near config')
        else:
            self._send(404, '{"error": "unknown lab path"}', 'application/json')


@pytest.fixture(scope='module')
def lab_url():
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Lab)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{server.server_address[1]}'
    server.shutdown()
    server.server_close()


@pytest.fixture
def base_state(request, tmp_path, monkeypatch, lab_url):
    monkeypatch.setattr(auth, 'KEY_PATH', tmp_path / 'key')
    auth._key(create=True)
    monkeypatch.setattr(web, 'throttle', lambda: None)  # pacing unchanged in production
    port = int(lab_url.rsplit(':', 1)[1])
    return {'run_id': 'verify-' + hashlib.sha256(request.node.name.encode()).hexdigest()[:10],
            'target': [lab_url], 'hosts': ['127.0.0.1'], 'scope_ports': [port],
            'scope_manifest': {'hosts': ['127.0.0.1'], 'networks': [], 'aliases': {}},
            'execution_metrics': {}, 'raw_bytes': 0, 'errors': [], 'events': [],
            'tool_call_budget': 40, 'token_budget': 50000, 'planner_metrics': {}}


def _run(base, *urls):
    """Issue probes in sequence, threading each result into the next call's state."""
    merged = {}
    for url in urls:
        state = {**base, **merged}
        merged.update(web.http_request({**state, 'planned_actions': [
            {'tool': 'http_request', 'target': url, 'method': 'GET'}]}))
    return merged


def _out_of(findings, category, group='verified_findings'):
    return [row for row in findings.get(group, []) if row.get('category') == category
            or row.get('finding_type') == category]


def test_positive_control_verifies_signed_replayable_evidence(base_state, lab_url):
    """The vulnerable route is verified only by an authenticated signed record."""
    merged = _run(base_state, f'{lab_url}/vuln/sqli', f"{lab_url}/vuln/sqli?q=1'")
    assert merged['probe_traces'][-1]['control'] is False
    assert any(d['category'] == 'sql_injection' for row in merged['probe_traces']
               for d in row.get('detected', []))
    records = [proof for proof in merged['verification_evidence'] if proof['result'] == 'confirmed']
    assert len(records) == 1
    findings = reflector.collect_findings(merged)
    verified = _out_of(findings, 'sql_injection')
    assert verified and verified[0]['verification_status'] == 'verified'
    evidence = verified[0]['verification_evidence']
    candidate = {'template_id': evidence['template_id'], 'url': evidence['url']}
    # The reference is reproducible: reload, re-hash, re-sign-check, re-evaluate contract.
    record = load_valid_proof(candidate, evidence, base_state['run_id'])
    assert record is not None and record['verification_basis'] == 'differential_injection'
    assert record['controls'] and record['detected']


def test_negative_control_claim_is_never_verified(base_state, lab_url):
    """The secure route yields no signature, so nothing is claimed; and an encoded
    reflection is REFUTED, not reported as a finding."""
    merged = _run(base_state, f'{lab_url}/secure/sqli', f"{lab_url}/secure/sqli?q=1'")
    assert merged['probe_traces'][-1]['control'] is False
    assert not any(row.get('detected') for row in merged['probe_traces'])
    assert merged.get('verification_evidence', []) == []
    findings = reflector.collect_findings(merged)
    assert findings['verified_findings'] == [] and findings['inconclusive_findings'] == []

    encoded = _run(base_state, f"{lab_url}/secure/xss?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    records = [proof for proof in encoded['verification_evidence']]
    assert len(records) == 1 and records[0]['result'] == 'refuted'
    findings = reflector.collect_findings(encoded)
    assert not _out_of(findings, 'cross_site_scripting', 'verified_findings')
    rejected = _out_of(findings, 'cross_site_scripting', 'rejected_findings')
    assert rejected and rejected[0]['verification_evidence']['result'] == 'refuted'


def test_probe_without_control_gets_a_deterministic_clean_control(base_state, lab_url):
    """A detection-bearing probe without a stored control is completed by the
    verification engine's own clean control; the contract then decides from the
    recorded response difference, not from a scanner label. An endpoint-inherent
    error (the control re-eval) still refuses confirmation elsewhere."""
    merged = _run(base_state, f"{lab_url}/vuln/sqli?q=1'")  # probe only: the engine fetches the control
    assert any(d['category'] == 'sql_injection' for row in merged['probe_traces']
               for d in row.get('detected', []))
    controls = [row for row in merged['probe_traces'] if row.get('control')]
    assert controls and controls[-1]['payload'] == 'adaptix_control'
    proofs = [proof for proof in merged.get('verification_evidence', []) if proof['result'] == 'confirmed']
    assert proofs
    record = json.load(open(proofs[-1]['evidence_ref']))
    assert record['record']['verification_basis'] == 'differential_injection'
    assert any(row.get('control') for row in record['record']['controls'])
    findings = reflector.collect_findings(merged)
    assert findings['verified_findings']


def test_contradictory_control_refuses_confirmation(base_state, lab_url):
    """An endpoint that errors regardless of input never confirms input-caused injection."""
    merged = _run(base_state, f'{lab_url}/noisy/sqli', f"{lab_url}/noisy/sqli?q=1'")
    assert merged['probe_traces'][0]['control'] is True
    assert any(d['category'] == 'sql_injection' for row in merged['probe_traces']
               for d in row.get('detected', []))
    assert not [proof for proof in merged.get('verification_evidence', [])
                if proof['result'] == 'confirmed']
    findings = reflector.collect_findings(merged)
    assert findings['verified_findings'] == []
    assert _out_of(findings, 'sql_injection', 'inconclusive_findings')


def test_xss_is_never_verified_by_reflection_alone(base_state, lab_url):
    """Milestone contract: unencoded attacker markup is a hint only; a verified XSS
    claim needs the browser_execution contract over a real session record."""
    merged = _run(base_state, f"{lab_url}/vuln/xss?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    assert not [proof for proof in merged['verification_evidence'] if proof['result'] == 'confirmed']
    findings = reflector.collect_findings(merged)
    assert findings['verified_findings'] == []
    inconclusive = _out_of(findings, 'cross_site_scripting', 'inconclusive_findings')
    assert inconclusive
    # The browser contract still verifies a genuine execution record end to end.
    marker = 'mrk_exec_1'
    from src.adaptix.evidence.verification import write_verification_record
    browser_record = {
        'template_id': 'browser-' + marker, 'url': f'{lab_url}/vuln/xss?q=%3Cscript%3Ealert(%27{marker}%27)%3C%2Fscript%3E',
        'method': 'GET', 'verification_method': 'deterministic_replay', 'verification_basis': 'browser_execution',
        'requests': [{'method': 'GET', 'url': f'{lab_url}/vuln/xss?q=<script>alert(\'{marker}\')</script>'},
                     {'method': 'GET', 'url': f'{lab_url}/vuln/xss?q=<script>alert()</script>'}],
        'responses': [
            {'status_code': 200, 'headers': {}, 'body_sha256': 'a' * 64, 'body_excerpt': '<h1>ok</h1>'},
            {'status_code': 200, 'headers': {}, 'body_sha256': 'b' * 64, 'body_excerpt': '<h1>ok</h1>'}],
        'browser': {'marker': marker, 'dialog_messages': [f'alert({marker}) executed'],
                    'control_dialog_messages': [], 'control_url': f'{lab_url}/vuln/xss?q=<script>alert()</script>'},
        'steps': ['Payload navigation', 'Control navigation'],
        'expected_behavior': 'no execution', 'actual_behavior': 'marker dialog on payload only',
    }
    proof = write_verification_record(base_state, browser_record)
    assert proof['result'] == 'confirmed'
    merged['candidates'] = merged.get('candidates', []) + [{
        'template_id': 'browser-' + marker, 'url': proof['url'],
        'finding_type': 'cross_site_scripting'}]
    merged['verification_evidence'] = list(merged.get('verification_evidence', [])) + [proof]
    findings = reflector.collect_findings(merged)
    verified = _out_of(findings, 'cross_site_scripting', 'verified_findings')
    assert verified and verified[0]['verification_status'] == 'verified'
    record = load_valid_proof({'template_id': proof['template_id'], 'url': proof['url']},
                              proof, base_state['run_id'])
    assert record['verification_basis'] == 'browser_execution'


def test_traversal_needs_clean_control_but_then_verifies(base_state, lab_url):
    merged = _run(base_state, f'{lab_url}/vuln/traversal',
                  f'{lab_url}/vuln/traversal?file=../../etc/passwd')
    records = [proof for proof in merged['verification_evidence'] if proof['result'] == 'confirmed']
    assert len(records) == 1
    findings = reflector.collect_findings(merged)
    verified = _out_of(findings, 'path_traversal')
    assert verified and verified[0]['verification_status'] == 'verified'


def test_sensitive_material_is_confirmed_directly_from_the_response(base_state, lab_url):
    """Unambiguous credential material needs no control: the evidence is in the body."""
    merged = _run(base_state, f'{lab_url}/vuln/keys')
    records = [proof for proof in merged['verification_evidence'] if proof['result'] == 'confirmed']
    assert len(records) == 1
    findings = reflector.collect_findings(merged)
    verified = _out_of(findings, 'sensitive_information_exposure')
    assert verified and verified[0]['verification_status'] == 'verified'
    record = load_valid_proof({'template_id': verified[0]['verification_evidence']['template_id'],
                               'url': verified[0]['verification_evidence']['url']},
                              verified[0]['verification_evidence'], base_state['run_id'])
    assert record['verification_basis'] == 'sensitive_material_exposure'


def test_documentation_placeholder_keys_stay_hints_not_verified_findings(base_state, lab_url):
    """A credential-shaped example value published by documentation is sample text."""
    from src.adaptix.evidence.web_signatures import PLACEHOLDER_MATERIAL  # noqa: F401
    merged = _run(base_state, f'{lab_url}/docs/example-keys')
    assert any(d['signature'] == 'aws_access_key' for row in merged['probe_traces']
               for d in row.get('detected', []))
    assert merged.get('verification_evidence', []) == []
    findings = reflector.collect_findings(merged)
    assert findings['verified_findings'] == []
    hint = _out_of(findings, 'sensitive_information_exposure', 'inconclusive_findings')
    assert hint and hint[0]['web_finding']['verification_status'] == 'potential'


def test_truncated_control_never_counts_as_clean(base_state, lab_url):
    """A control whose stored excerpt was cut must not be assumed marker-free."""
    merged = _run(base_state, f'{lab_url}/vuln/sqli-late', f"{lab_url}/vuln/sqli-late?q=1'")
    control = merged['probe_traces'][0]
    assert control['control'] is True
    assert len(control['body_excerpt']) < control['body_length'] and control['excerpt_truncated']
    # The full stored evidence proves the marker, but the excerpt cannot; refuse to trust.
    probe = merged['probe_traces'][1]
    assert any(d['category'] == 'sql_injection' for d in probe['detected'])
    assert not [proof for proof in merged.get('verification_evidence', [])
                if proof['result'] == 'confirmed']
    findings = reflector.collect_findings(merged)
    assert findings['verified_findings'] == []
    assert _out_of(findings, 'sql_injection', 'inconclusive_findings')


def test_multi_signature_probe_proves_each_contracted_category(base_state, lab_url):
    """A probe tripping two independent contracts signs each per-category record;
    the XSS side stays inconclusive until real browser execution is recorded."""
    merged = _run(base_state, f'{lab_url}/vuln/multi',
                  f"{lab_url}/vuln/multi?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'")
    confirmed = {proof['template_id'].rsplit('-', 1)[-1] for proof in merged['verification_evidence']
                 if proof['result'] == 'confirmed'}
    assert confirmed == {'sql_injection'}
    findings = reflector.collect_findings(merged)
    assert _out_of(findings, 'sql_injection', 'verified_findings')
    assert findings['verified_findings'] == [] or not _out_of(findings, 'cross_site_scripting', 'verified_findings')
    assert _out_of(findings, 'cross_site_scripting', 'inconclusive_findings')


def test_tampered_record_is_never_a_verified_finding(base_state, lab_url):
    """Proof that fails authentication drops the finding back to inconclusive."""
    from pathlib import Path
    merged = _run(base_state, f'{lab_url}/vuln/sqli', f"{lab_url}/vuln/sqli?q=1'")
    findings = reflector.collect_findings(merged)
    assert _out_of(findings, 'sql_injection', 'verified_findings')
    evidence = _out_of(findings, 'sql_injection')[0]['verification_evidence']
    Path(evidence['evidence_ref']).write_text('{"record": {"tampered": true}}')
    again = reflector.collect_findings(merged)
    assert _out_of(again, 'sql_injection', 'verified_findings') == []
    hint = _out_of(again, 'sql_injection', 'inconclusive_findings')
    reproduction = hint and hint[0]['verification_evidence']
    assert reproduction and reproduction.get('url') and not reproduction.get('evidence_ref')
