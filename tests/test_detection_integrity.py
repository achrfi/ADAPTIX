"""Offline regression tests for detection integrity (audit D01-D10).

Every scenario runs on synthetic in-memory fixtures: no target is contacted, no
model/provider is called, and no scanner is executed. Playwright is faked at the
sync_playwright boundary; Nuclei is exercised only through the pure registration
helper. This suite checks bookkeeping honesty - candidate and proof ledgers
survive inconclusive browser results, scanner matches are not independent
verification, recon/import runs declare not_tested, and a stop reason never
becomes a safety conclusion. It says nothing about real-world XSS recall and
produces no detection-coverage numbers.
"""
import hashlib
import json
import time

import pytest

from src.adaptix.tools import nuclei
from src.adaptix.tools import playwright as pw
from src.adaptix.agents.reflector import collect_findings
from src.adaptix.processing.normalize import deduplicate
from src.adaptix.reporting.report import final_report, markdown_report
from src.adaptix.reporting.coverage import assessment_coverage

PORT = 18080
URL = f'http://127.0.0.1:{PORT}/vuln/echo'
MARKER = 'rkx7Qz31'


def _state(**extra):
    state = {
        'run_id': 'integrity-d10-fixture', 'target': ['http://127.0.0.1'],
        'hosts': ['127.0.0.1'], 'scope_ports': [PORT],
        'scope_aliases': {}, 'scope_networks': [],
        'time_budget_seconds': 600, 'tool_call_budget': 5,
        'run_started_at': time.time(),
        'execution_metrics': {}, 'raw_bytes': 0, 'errors': [], 'events': [],
        'candidates': [], 'verification_evidence': [], 'browser_evidence': [],
        'planned_actions': [{'tool': 'browser_test',
                             'target': f'{URL}?q=%3Cscript%3Ealert(%27{MARKER}%27)%3C%2Fscript%3E',
                             'marker': MARKER}],
    }
    state.update(extra)
    return state


AUTH = ()


@pytest.fixture(autouse=True)
def _auth_key(tmp_path, monkeypatch):
    from src.adaptix.security import authorization
    monkeypatch.setattr(authorization, 'KEY_PATH', tmp_path / 'key')
    authorization._key(create=True)


def _fake_playwright(monkeypatch, *, dialog_message=None, goto_error=None, enter_error=None):
    """Install a fake sync_playwright. dialog_message drives a captured alert."""

    class _FakeDialog:
        def __init__(self, message):
            self.message, self.type = message, 'alert'

        def dismiss(self):
            pass

    class _FakePage:
        def __init__(self):
            self._dialog_handlers = []

        def on(self, event, handler):
            if event == 'dialog':
                self._dialog_handlers.append(handler)

        def remove_listener(self, event, handler):
            if handler in self._dialog_handlers:
                self._dialog_handlers.remove(handler)

        def route(self, *_a, **_k):
            pass

        def goto(self, target, **_k):
            if goto_error is not None:
                raise goto_error
            if dialog_message is not None and MARKER in target:
                # Marker-carrying navigation fires the captured dialog; the
                # marker-free control navigation never does.
                for handler in list(self._dialog_handlers):
                    handler(_FakeDialog(dialog_message))
            return type('R', (), {'status': 200})()

        @property
        def url(self):
            return URL

        def wait_for_load_state(self, *a, **k):
            pass

        def wait_for_timeout(self, _ms):
            pass

        def content(self):
            return '<html><body>fixture</body></html>'

    class _FakeContext:
        def new_page(self):
            return _FakePage()

        def close(self):
            pass

    class _FakeBrowser:
        def new_context(self, **k):
            return _FakeContext()

        def close(self):
            pass

    class _FakeP:
        chromium = type('chromium', (), {'launch': staticmethod(lambda **k: _FakeBrowser())})()

    class _FakeCM:
        def __enter__(self):
            if enter_error is not None:
                raise enter_error
            return _FakeP()

        def __exit__(self, *a):
            return False

    playwright_module = pytest.importorskip('playwright.sync_api')
    monkeypatch.setattr(playwright_module, 'sync_playwright', lambda: _FakeCM())
    monkeypatch.setattr(pw, 'tool_registry',
                        lambda: {'playwright': {'enabled': True, 'path': 'python-module'}})


# --- D03: candidate and proof ledgers survive inconclusive browser outcomes --

def test_inconclusive_browser_result_preserves_candidates_and_evidence(monkeypatch):
    _fake_playwright(monkeypatch, dialog_message=None)  # no dialog ever fires
    prior_candidate = {'template_id': 'prior-x1', 'url': f'http://127.0.0.1:{PORT}/s?q=1',
                       'finding_type': 'cross_site_scripting', 'evidence': [{'marker': 'old'}]}
    prior_proof = {'template_id': 'prior-x1', 'url': prior_candidate['url'],
                   'result': 'confirmed', 'evidence_ref': '/tmp/prior.json'}
    state = _state(candidates=[prior_candidate], verification_evidence=[prior_proof])
    result = pw.browser_test(state)
    merged = {**state, **result}
    assert result['browser_test_outcome'] == 'inconclusive_no_marker_dialog'
    assert merged['candidates'] == [prior_candidate], 'empty browser output must not delete candidates'
    assert merged['verification_evidence'] == [prior_proof], 'empty browser output must not delete proof'
    assert not any(str(row.get('template_id', '')).startswith('browser-')
                   for row in merged['candidates']), 'no status promotion without new evidence'
    assert 'inconclusive' in result['events'][-1]


def test_browser_timeout_and_error_preserve_candidates(monkeypatch):
    prior_candidate = {'template_id': 'prior-x1', 'url': f'http://127.0.0.1:{PORT}/s?q=1'}
    prior_proof = {'result': 'confirmed'}
    for error in (TimeoutError('lab: navigation window closed'),
                  RuntimeError('lab: browser unavailable')):
        _fake_playwright(monkeypatch, goto_error=error)
        state = _state(candidates=[prior_candidate], verification_evidence=[prior_proof])
        result = pw.browser_test(state)
        merged = {**state, **result}
        assert merged['candidates'] == [prior_candidate]
        assert merged['verification_evidence'] == [prior_proof]
        assert merged['browser_test_outcome'] == 'error_before_capture'
        assert any('Browser Test:' in row for row in merged['errors'])


def test_confirmed_browser_result_appends_candidate_exactly_once(monkeypatch):
    _fake_playwright(monkeypatch, dialog_message=f'alert({MARKER}) executed')
    prior_candidate = {'template_id': 'prior-x1', 'url': f'http://127.0.0.1:{PORT}/s?q=1'}
    state = _state(candidates=[prior_candidate])
    target = state['planned_actions'][0]['target']
    first = pw.browser_test(state)
    merged = {**state, **first}
    ids = [(row.get('template_id'), row.get('url')) for row in merged['candidates']]
    assert ids.count((f'browser-{MARKER}', target)) == 1
    assert len(merged['verification_evidence']) == 1
    second = pw.browser_test(merged)
    merged2 = {**merged, **second}
    keys = [(row.get('template_id'), row.get('url')) for row in merged2['candidates']]
    assert len(keys) == len(set(keys)), 'candidate merge must never duplicate an identity'
    assert prior_candidate in merged2['candidates'], 'merge must not drop distinct prior candidates'


def test_execution_boundary_merges_candidates_without_duplication_or_loss():
    away = f'http://127.0.0.1:{PORT}/a'
    prior = [{'template_id': 'keep-01', 'url': away}]
    repeated = [{'template_id': 'browser-abc123', 'url': f'http://127.0.0.1:{PORT}/b'},
                {'template_id': 'browser-abc123', 'url': f'http://127.0.0.1:{PORT}/b'},
                {'template_id': 'keep-01', 'url': away},
                {'template_id': 'keep-01', 'url': away}]
    merged = deduplicate('candidates', prior + repeated)
    keys = [(row['template_id'], row['url']) for row in merged]
    assert sorted(k for k in keys if k[0] == 'keep-01') == [('keep-01', away)]
    assert sorted(set(keys)) == sorted(keys), 'merge dedupes without dropping distinct pairs'


# --- D04: scanner match is not independently verified -----------------------

def _register_scanner_match(severity='high'):
    template_tags = {'mock-xss-probe': ['cve']}
    findings, observations = [], []
    nuclei._register_nuclei_match(
        {'matched-at': URL, 'template-id': 'mock-xss-probe',
         'info': {'name': 'Mock xss template match', 'severity': severity,
                  'tags': ['cve', 'xss']},
         'matcher-name': 'regex-echo', 'matcher-status': True, 'type': 'http',
         'host': f'127.0.0.1:{PORT}', 'timestamp': '2026-10-24T00:00:00.00', 'ip': '127.0.0.1'},
        'mock-xss-probe', URL, severity, 1, '/tmp/fixture.jsonl',
        hashlib.sha256(b'fixture').hexdigest(), 'integrity-d10-fixture',
        template_tags, set(), {'detect'}, set(), set(), findings, observations)
    return findings[0]


def test_scanner_match_is_labeled_scanner_matched_not_independent():
    row = _register_scanner_match()
    assert row['verification_status'] == 'scanner_matched'
    assert row['verification_level'] == 'scanner_matched'
    assert row['verification_method'] == 'nuclei_template_match'
    assert row['independently_verified'] is False
    assert row['verification_basis'] != 'browser_execution'
    # Provenance and verification method survive as recorded.
    assert row['verification_evidence']['verification_method'] == 'nuclei_template_match'
    assert row['verification_evidence']['evidence_ref'] == '/tmp/fixture.jsonl'


def test_scanner_match_stays_out_of_the_independently_verified_bucket():
    row = _register_scanner_match()
    rebuilt = collect_findings(_state(verified_findings=[row]))
    assert rebuilt['scanner_matched_findings'] == [row], 'scanner row keeps its own bucket'
    assert rebuilt['verified_findings'] == [], 'a scanner match must not become "verified"'


def test_report_renders_scanner_matches_apart_from_independent_evidence():
    row = _register_scanner_match()
    state = _state(verified_findings=[row], scanner_matched_findings=[row],
                   inconclusive_findings=[], rejected_findings=[], hypotheses=[],
                   findings=[], nuclei_observations=[], attempted_actions=[],
                   planner_metrics={}, token_ledger=[], run_started_at=time.time() - 1,
                   user_prompt='fixture')
    result = final_report(state)
    payload = result['report']
    assert [r['finding_id'] for r in payload['scanner_matched_findings']] == [row['finding_id']]
    assert payload['independently_verified_findings'] == []
    assert payload['findings'] == [], 'a scanner match must not be promoted into final findings'
    assert payload['metrics']['finding_classes']['scanner_matched'] == 1
    assert payload['metrics']['finding_classes']['total_verified_findings'] == 0
    markdown = result['markdown_report']
    assert '## Nuclei scanner matches (1)' in markdown
    assert '## Independently verified findings (0)' in markdown
    scanner_section = markdown.split('## Nuclei scanner matches')[1].split('##')[0]
    assert 'not independently verified' in scanner_section
    assert 'not an independently verified finding' in markdown
    assert 'browser-execution' in scanner_section


# --- D01/D02/D08: recon and imports declare not_tested ----------------------

def test_recon_assessment_block_declares_not_tested():
    from src.adaptix.local_inventory.workflow import assessment_block
    block = assessment_block()
    assert block['assessment_status'] == 'not_tested'
    assert block['classes'] == []
    assert block['inventory_proves_input_processing'] is False
    assert 'not tested' in block['assessment_status_reason'] or 'not' in block['meaning']
    assert any('not "not vulnerable"' in line or 'not tested' in line for line in block['meaning'].split(','))


def test_recon_report_json_and_markdown_carry_the_not_tested_fields(monkeypatch, tmp_path):
    """End-to-end through the recon graph's save stage with every tool faked."""
    from src.adaptix.local_inventory import workflow as inventory
    scope = type('S', (), {
        'as_dict': staticmethod(lambda: {'target': 'http://127.0.0.1'}), 'origin': 'http://127.0.0.1:18080'})()
    ffuf = {'records': [], 'candidates': 0, 'status': 'success', 'progress': {}, 'auto_calibration': {}}
    monkeypatch.setattr(inventory, 'ffuf_discover', lambda *a, **k: ffuf)
    monkeypatch.setattr(inventory, 'browser_discover',
                        lambda *a, **k: {'records': [], 'pages': [], 'forms': [], 'blocked': [],
                                         'client_routes': [], 'status': 'success', 'requests_sent': 0,
                                         'errors': [], 'remaining_pages': 0})
    graph = inventory.build_graph(scope, tmp_path, ai=False)
    events = list(graph.stream({}))
    report = events[-1]['write_report']['report']
    assert report['assessment_status'] == 'not_tested'
    assert report['inventory_proves_input_processing'] is False
    markdown = (tmp_path / 'report.md').read_text(encoding='utf-8')
    assert 'Assessment status: not_tested' in markdown
    assert '"not tested"' in markdown or 'not tested' in markdown


def test_ffuf_import_review_only_state_declares_not_tested():
    state = _state(operator_recon_review_only=True, scanner_disabled=True, baseline_disabled=True,
                   ffuf_imports=[{'source_sha256': 'a' * 64, 'bytes': 10, 'input_rows': 2,
                                  'accepted_rows': 2, 'rejected_rows': 0, 'duplicate_rows': 0}],
                   ffuf_observations=[{'url': URL, 'status_code': 200, 'method': 'GET',
                                       'source': 'operator_ffuf_json', 'source_sha256': 'a' * 64,
                                       'route_existence_verified': False,
                                       'verification_status': 'operator_supplied_unverified'}],
                   inconclusive_findings=[], rejected_findings=[], hypotheses=[],
                   findings=[], nuclei_observations=[], attempted_actions=[],
                   planner_metrics={}, token_ledger=[], run_started_at=time.time() - 1,
                   user_prompt='import review')
    result = final_report(state)
    coverage = result['report']['assessment_coverage']
    assert coverage['review_only'] is True and coverage['assessment_performed'] is False
    assert all(row['status'] == 'not_tested' for row in coverage['classes'].values())
    assert all('review-only' in row['reason'] for row in coverage['classes'].values())
    markdown = result['markdown_report']
    assert 'not_tested' in markdown
    assert 'Review-only mode disabled all testing tools' in markdown


# --- D08: stop reason and zero findings are not safety conclusions ----------

def test_stop_reason_and_zero_findings_never_become_not_vulnerable():
    state = _state(user_prompt='xss', run_started_at=time.time() - 1,
                   inconclusive_findings=[], rejected_findings=[], hypotheses=[],
                   findings=[], nuclei_observations=[], attempted_actions=[],
                   scanner_matched_findings=[], planner_metrics={}, token_ledger=[],
                   stop_reason='no_new_actions')
    result = final_report(state)
    payload = result['report']
    coverage = payload['assessment_coverage']
    assert coverage['classes']['cross_site_scripting']['status'] == 'not_tested'
    assert coverage['classes']['cross_site_scripting']['reason']
    # Nothing in the JSON labels any class 'not_vulnerable'.
    assert 'not_vulnerable' not in json.dumps(payload.get('assessment_coverage'), ensure_ascii=False)
    markdown = result['markdown_report']
    assert 'not_tested' in markdown
    assert 'does not mean the target is not vulnerable' in markdown
    # The stop reason stays an execution state, never an application verdict.
    assert coverage['stop_reason'] == 'no_new_actions'
    assert payload['termination']['stop_reason'] == 'no_new_actions'


# --- D05-D09: recorded activity vs data-unavailable -------------------------

def test_coverage_distinguishes_missing_data_from_zero():
    coverage = assessment_coverage(_state(), stop_reason='budget_exhausted')
    assert coverage['candidates_collected'] == 0, 'the recorded list is empty: a real zero'
    coverage_without_key = assessment_coverage({'hosts': ['127.0.0.1'], 'scope_ports': [PORT]},
                                               stop_reason='budget_exhausted')
    assert coverage_without_key['candidates_collected'] is None, 'no recorded list is not a zero'
    assert coverage_without_key['actions_executed_by_tool'] == {}
    for row in coverage['classes'].values():
        assert row['status'] == 'not_tested' and row['reason']


# --- D10: older report states still render, with explicit limits ------------

def test_legacy_report_state_still_renders_with_scanner_split():
    legacy_scanner = {'finding_id': 'NUC-legacy0001', 'tool_source': 'nuclei',
                      'vulnerability_name': 'Legacy template match', 'template_id': 'legacy-tpl',
                      'severity': 'high', 'target': URL, 'matched_location': URL,
                      'matcher_name': 'regex-legacy',
                      'verification_method': 'nuclei_template_match',
                      'verification_level': 'verified', 'verification_status': 'verified',
                      'verification_evidence': {'result': 'confirmed', 'evidence_ref': '/tmp/x.jsonl'}}
    state = _state(verified_findings=[legacy_scanner],
                   scanner_matched_findings=[], inconclusive_findings=[],
                   rejected_findings=[], hypotheses=[], findings=[],
                   nuclei_observations=[], attempted_actions=[],
                   planner_metrics={}, token_ledger=[], run_started_at=time.time() - 1,
                   user_prompt='legacy')
    result = final_report(state)
    payload = result['report']
    assert len(payload['scanner_matched_findings']) == 1
    assert len(payload['independently_verified_findings']) == 0
    markdown = result['markdown_report']
    assert 'Legacy template match' in markdown
    assert 'not independently verified' in markdown


def test_legacy_report_dict_renders_both_tiers_from_method_provenance():
    """Older report dictionaries missing the new keys split by verification_method."""
    legacy_scanner = {'finding_id': 'NUC-legacy0001', 'vulnerability_name': 'Legacy template match',
                      'template_id': 'legacy-tpl', 'severity': 'high', 'matched_location': URL,
                      'matcher_name': 'regex-legacy', 'verification_method': 'nuclei_template_match',
                      'verification_status': 'verified', 'verification_evidence': {'evidence_ref': '/x.jsonl'}}
    legacy_independent = {'evidence_id': 'EV-001', 'template_id': 'idor-a1', 'target': URL,
                          'finding_type': 'broken_object_level_authorization',
                          'verification_method': 'manual_review', 'verification_status': 'verified'}
    markdown = markdown_report({'status': 'scan_completed', 'target': 'http://127.0.0.1',
                                'stop_reason': 'no_new_actions',
                                'verified_findings': [legacy_scanner, legacy_independent]})
    assert '## Independently verified findings (1)' in markdown
    assert '## Nuclei scanner matches (1)' in markdown
    assert 'Legacy template match' in markdown
    assert 'not independently verified' in markdown


def test_minimal_legacy_report_dict_renders_with_explicit_limits():
    markdown = markdown_report({'status': 'scan_completed', 'target': 'http://127.0.0.1',
                                'stop_reason': 'no_new_actions', 'errors': [], 'metrics': {}})
    assert 'Assessment status' in markdown
    assert 'assessment-coverage record' in markdown, 'old reports state the coverage gap explicitly'
    assert markdown.count('_None') >= 1
