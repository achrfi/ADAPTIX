"""Direct Nuclei registration: a positive template match is the scanner's verdict.

The engine's matchers evaluate its templates; ADAPTIX registers each positive
match immediately with its own finding id, provenance and the
nuclei_template_match basis, labelled ``scanner_matched`` and
``independently_verified: false`` (audit D04 - a scanner match is not an
independently verified finding and never a browser-execution XSS proof), while
informational matches and engine-false rows stay observations.
These tests drive the real adapter and the real workflow phases with the
subprocess, template catalog and provider mocked at their boundaries; results
land in real artifact files under artifacts/scans/<run-id>/.
"""
import json
import time

import pytest

from src.adaptix.tools import nuclei
from src.adaptix.tools import registry as tool_registry_module
from src.adaptix.agents import planner
from src.adaptix.agents.reflector import collect_findings
from src.adaptix.evidence import audit
from src.adaptix.workflow import scanner

URL = 'http://127.0.0.1:18080/private/storage'
MANIFEST = {
    'selected_count': 2, 'executable_count': 2, 'approval_required_count': 0,
    'approval': {'result': 'allowed'}, 'manifest_ref': 'test-manifest', 'manifest_sha256': 'a' * 64,
    'request_ceiling_per_target': 300, 'exact_path': False, 'coverage': 'test-scope',
    'targets': [URL], 'strategy': 'configured', 'tags': [],
    '_chosen': [
        {'id': 'mock-vuln-cve', 'sha256': 'b' * 64, 'tags': ['cve', 'misconfig'], 'methods': [],
         'requests': 1, 'path': '/templates/http/mock-vuln-cve.yaml'},
        {'id': 'mock-panel-detect', 'sha256': 'c' * 64, 'tags': ['detect', 'panel', 'discovery'],
         'methods': [], 'requests': 1, 'path': '/templates/http/mock-panel-detect.yaml'}]}
VULN_ROW = {'matched-at': URL, 'template-id': 'mock-vuln-cve',
            'info': {'name': 'Mock exposed storage', 'severity': 'high', 'tags': ['cve']},
            'matcher-name': 'regex-exposed', 'matcher-status': True, 'type': 'http',
            'host': '127.0.0.1:18080', 'timestamp': '2026-10-22T03:03:20.32', 'ip': '127.0.0.1'}
PANEL_ROW = {'matched-at': 'http://127.0.0.1:18080/admin', 'template-id': 'mock-panel-detect',
             'info': {'name': 'Mock admin panel', 'severity': 'info'},
             'matcher-name': 'word-panel', 'matcher-status': True, 'host': '127.0.0.1:18080'}


def _scan_state(run_id='nuclei-direct-reg', verification=None):
    return {'run_id': run_id, 'hosts': ['127.0.0.1'], 'scope_ports': [18080],
            'http_services': [{'url': URL}], 'run_started_at': time.time(),
            'time_budget_seconds': 600, 'tool_call_budget': 8,
            'verification_evidence': verification or []}


def _install(monkeypatch, rows, returncode=0):
    monkeypatch.setattr(nuclei, 'tool_registry', lambda: {'nuclei': {'enabled': True, 'path': '/bin/nuclei'}})
    monkeypatch.setattr(nuclei, 'prepare_scan', lambda state, target, cfg: MANIFEST)
    monkeypatch.setattr(nuclei, 'materialize', lambda state, manifest: ['-t', '/nonexistent'])
    stdout = '\n'.join(json.dumps(row) for row in rows)
    monkeypatch.setattr(nuclei, 'run_tool', lambda argv, timeout, stdin, **kw:
                        {'returncode': returncode, 'stdout': stdout, 'stderr': 'Requests: 2/2'})


def test_positive_match_registers_immediately_as_scanner_match(monkeypatch):
    _install(monkeypatch, [VULN_ROW, PANEL_ROW])
    result = nuclei.nuclei_check(_scan_state())
    findings = result['verified_findings']
    assert len(findings) == 1, 'a positive vulnerability match registers; informational matches stay out'
    entry = findings[0]
    assert entry['finding_id'].startswith('NUC-')
    assert entry['tool_source'] == 'nuclei' and entry['source_tool'] == 'nuclei'
    assert entry['vulnerability_name'] == 'Mock exposed storage'
    assert entry['template_id'] == 'mock-vuln-cve' and entry['severity'] == 'high'
    assert entry['matched_location'] == URL and entry['matched_at'] == URL
    assert entry['matcher_name'] == 'regex-exposed' and entry['matcher_status'] is True
    assert entry['category'] == 'nuclei_template_match'
    assert entry['verification_method'] == 'nuclei_template_match'
    assert entry['verification_level'] == 'scanner_matched'
    assert entry['independently_verified'] is False and entry['verification_status'] == 'scanner_matched'
    evidence = entry['verification_evidence']
    assert evidence['verification_level'] == 'scanner_matched' and evidence['result'] == 'confirmed'
    assert evidence['evidence_line'] == 1 and evidence['evidence_sha256'] and evidence['evidence_ref']
    assert entry['nuclei_metadata']['type'] == 'http' and entry['nuclei_metadata']['ip'] == '127.0.0.1'
    observations = result['nuclei_observations']
    assert len(observations) == 1 and observations[0]['kind'] == 'informational_nuclei_match'
    assert observations[0]['observation_id'] != entry['finding_id']
    # The same JSONL row is still a live artifact the finding points at.
    with open(evidence['evidence_ref'], encoding='utf-8') as handled:
        stored = json.loads(handled.read().splitlines()[evidence['evidence_line'] - 1])
    assert stored['template-id'] == 'mock-vuln-cve'


def test_registration_needs_no_second_action_or_proof(monkeypatch):
    _install(monkeypatch, [VULN_ROW])
    state = _scan_state()
    result = nuclei.nuclei_check(state)
    assert result['verified_findings'] and result['verified_findings'][0]['verification_status'] == 'scanner_matched'
    assert not state.get('verification_evidence'), 'no replay proof, review label or re-test is required'
    assert not state.get('attempted_actions'), 'registration happens in the scan phase, never as an extra action'


def test_duplicates_dedupe_without_discarding_distinct_matches(monkeypatch):
    _install(monkeypatch, [VULN_ROW, VULN_ROW, {**VULN_ROW, 'matcher-name': 'second-matcher'}])
    state = _scan_state()
    first = nuclei.nuclei_check(state)
    ids = [row['finding_id'] for row in first['verified_findings']]
    assert len(ids) == 2 and len(set(ids)) == 2, 'identical matches collapse; a distinct matcher survives'
    carried = {**state, 'verified_findings': first['verified_findings'],
               'nuclei_observations': first['nuclei_observations']}
    second = nuclei.nuclei_check(carried)
    assert [row['finding_id'] for row in second['verified_findings']] == ids


def test_finding_ids_stable_across_scans_with_different_evidence_files(monkeypatch):
    # The same match discovered by a scan with a different run identity and a
    # different JSONL artifact (extra unrelated row, line noise, other file) must
    # resolve to the identical finding id; the artifacts themselves stay the
    # provenance record of each scan.
    _install(monkeypatch, [VULN_ROW, PANEL_ROW])
    first = nuclei.nuclei_check(_scan_state(run_id='nuclei-scan-alpha'))
    ids = [row['finding_id'] for row in first['verified_findings']]
    assert len(ids) == 1
    original_evidence = first['verified_findings'][0]['verification_evidence']

    noisy = [PANEL_ROW, {**VULN_ROW, 'timestamp': '2026-01-02T00:00:00.000000+00:00'}, PANEL_ROW]
    _install(monkeypatch, noisy)
    carried = {**_scan_state(run_id='nuclei-scan-beta'), 'verified_findings': first['verified_findings'],
               'nuclei_observations': first['nuclei_observations']}
    second = nuclei.nuclei_check(carried)
    assert [row['finding_id'] for row in second['verified_findings']] == ids, \
        're-scans of the same surface resolve to the same finding id'
    # The first scan keeps owning the entry: a different artifact does not
    # duplicate the record, and neither does the amend lose its provenance.
    assert second['verified_findings'][0]['verification_evidence'] == original_evidence
    assert second['verified_findings'][0]['verification_evidence']['run_id'] == 'nuclei-scan-alpha'
    # The two scans really did write distinct evidence artifacts.
    from src.adaptix.evidence.storage import artifact_path
    beta_state = _scan_state(run_id='nuclei-scan-beta')
    beta_file = artifact_path(beta_state, 'nuclei', URL, 'jsonl')
    assert beta_file.exists()
    import hashlib
    beta_sha = hashlib.sha256(beta_file.read_bytes()).hexdigest()
    assert beta_sha != original_evidence['evidence_sha256']
    assert original_evidence['evidence_ref'] != str(beta_file)


def test_findings_survive_engine_timeout_with_partial_output(monkeypatch):
    _install(monkeypatch, [VULN_ROW], returncode=-1)
    result = nuclei.nuclei_check(_scan_state())
    assert [row['finding_id'] for row in result['verified_findings']], \
        'nuclei emits complete JSONL findings as it runs; a wall-clock stop must not lose them'


def test_unanchored_match_never_becomes_a_finding(monkeypatch):
    _install(monkeypatch, [{**VULN_ROW, 'template-id': 'template-the-run-never-approved'}])
    result = nuclei.nuclei_check(_scan_state())
    assert result['verified_findings'] == []
    assert result['candidates'][0]['template_id'] == 'template-the-run-never-approved'
    assert result['nuclei_observations'][0]['kind'] == 'informational_nuclei_match'


def test_scanner_rows_persist_through_collect_findings_and_checkpoints(monkeypatch):
    _install(monkeypatch, [VULN_ROW, PANEL_ROW])
    run_id = f'nuclei-persist-{int(time.time())}'
    registered = nuclei.nuclei_check(_scan_state(run_id=run_id))
    state = {**_scan_state(run_id=run_id), 'verified_findings': registered['verified_findings'],
             'nuclei_observations': registered['nuclei_observations'],
             'candidates': registered['candidates'], 'iterations': 1}
    rebuilt = collect_findings(state)
    assert len(rebuilt['scanner_matched_findings']) == 1
    row = rebuilt['scanner_matched_findings'][0]
    assert row['verification_level'] == 'scanner_matched' and row['independently_verified'] is False
    assert row['finding_id'] == registered['verified_findings'][0]['finding_id']
    assert row.get('verification_evidence') == registered['verified_findings'][0]['verification_evidence']
    # Findings must survive as records, not be re-derived: repeated rebuilds and
    # the state_update checkpoints keep the identical entry.
    assert collect_findings({**state, **rebuilt})['scanner_matched_findings'] == \
        rebuilt['scanner_matched_findings']
    checkpoint_ref = audit.checkpoint(state)
    stored = json.loads(open(checkpoint_ref, encoding='utf-8').read())
    assert stored['verified_findings'][0]['finding_id'] == row['finding_id']
    assert stored['nuclei_observations'][0]['kind'] == 'informational_nuclei_match'


def test_independent_verification_stays_available_alongside_scanner_rows(monkeypatch, tmp_path, verification_record):
    _install(monkeypatch, [VULN_ROW])
    registered = nuclei.nuclei_check(_scan_state(run_id='nuclei-direct-indep'))
    scanner_row = registered['verified_findings'][0]
    from src.adaptix.security import authorization
    from src.adaptix.evidence.verification import write_verification_record
    monkeypatch.setattr(authorization, 'KEY_PATH', tmp_path / 'key')
    authorization._key(create=True)
    state = _scan_state(run_id='nuclei-direct-indep')
    proof = write_verification_record(state, verification_record)
    state['candidates'] = [{'template_id': 'idor', 'url': 'http://127.0.0.1:18080', 'severity': 'high'}]
    state['verification_evidence'] = [proof]
    state['verified_findings'] = [scanner_row]
    rebuilt = collect_findings(state)
    scanner_row_out = rebuilt['scanner_matched_findings'][0]
    independent = [row for row in rebuilt['verified_findings']
                   if row.get('verification_method') != 'nuclei_template_match']
    assert scanner_row_out['verification_status'] == 'scanner_matched', \
        'the scanner row persists untouched next to the replay-confirmed record'
    assert len(independent) == 1 and independent[0]['template_id'] == 'idor'
    assert independent[0]['verification_evidence']['result'] == 'confirmed'
    assert scanner_row['finding_id'] != independent[0].get('evidence_id')


def test_final_report_splits_provenance_and_counts_metrics_separately(monkeypatch, tmp_path, verification_record):
    _install(monkeypatch, [VULN_ROW])
    registered = nuclei.nuclei_check(_scan_state(run_id='nuclei-direct-report'))
    scanner_row = registered['verified_findings'][0]
    state = _scan_state(run_id='nuclei-direct-report')
    from src.adaptix.security import authorization
    from src.adaptix.evidence.verification import write_verification_record
    monkeypatch.setattr(authorization, 'KEY_PATH', tmp_path / 'key')
    authorization._key(create=True)
    proof = write_verification_record(state, verification_record)
    state.update(planner_metrics={'tokens_used': 2000, 'llm_calls': 1},
                 candidates=[{'template_id': 'idor', 'url': 'http://127.0.0.1:18080', 'severity': 'high'}],
                 verification_evidence=[proof],
                 verified_findings=[scanner_row], baseline_recon={}, events=[],
                 hosts=['127.0.0.1'], user_prompt='assessment')
    from src.adaptix.reporting.report import final_report, markdown_report
    result = final_report({**state, 'iterations': 0})
    report = result['report']
    assert [row['finding_id'] for row in report['scanner_matched_findings']] == [scanner_row['finding_id']]
    assert [row['finding_id'] for row in report['nuclei_verified_findings']] == [scanner_row['finding_id']]
    assert [row['template_id'] for row in report['independently_verified_findings']] == ['idor']
    assert report['unverified_candidate_findings'] == []
    assert len(report['verified_findings']) == 1, 'only the independently verified row is in the verified bucket'
    assert all(row.get('verification_method') == 'nuclei_template_match'
               for row in report['scanner_matched_findings'])
    comparison = report['metrics']['research_comparison']
    assert comparison['verified_findings'] == 1, 'only independently verified rows count here'
    assert comparison['scanner_matched_findings'] == 1 and comparison['independently_verified_findings'] == 1
    assert report['metrics']['finding_classes'] == {'total_verified_findings': 1, 'scanner_matched': 1,
                                                    'nuclei_verified': 1, 'other_verified': 1,
                                                    'unverified_candidates': 0}
    markdown = result['markdown_report']
    assert '## Independently verified findings (1)' in markdown
    assert f"**{scanner_row['finding_id']}**" in markdown and 'regex-exposed' in markdown
    assert 'scanner_matched' in markdown
    assert '## Unverified candidate findings (0)' in markdown
    assert report.get('verified_findings', []) is not None
    # The markdown artifact exists on disk next to the JSON report.
    with open(str(json_report_markdown_path(result)), encoding='utf-8') as fh:
        assert '## Independently verified findings (1)' in fh.read()


def json_report_markdown_path(result):
    from src.adaptix.evidence.storage import artifact_path
    path = artifact_path({'run_id': 'nuclei-direct-report'}, 'report', 'summary', 'md')
    assert path.is_file() and path.name.endswith('.md')
    return path


INVENTORIED = {'target': ['http://127.0.0.1:18080/'], 'status': 'scope_ok', 'run_id': 'phase-projection'}


def test_scanner_phase_projection_carries_findings_up_to_the_graph(monkeypatch):
    """The nuclei_scan phase projects adapter findings into state verbatim."""
    SETTINGS = {'enabled': True, 'template_mode': 'adaptive', 'max_seconds': 60, 'max_origins': 2,
                'adaptive_tool_call_reserve': 4, 'max_candidates_per_origin': 40, 'template_cap': 160,
                'vulnerability_assessment': False}
    phase = {
        'nuclei_template_selections': [{'policy': {'coverage': MANIFEST['coverage']}}],
        'verified_findings': [{'finding_id': 'NUC-phase0001', 'tool_source': 'nuclei',
                               'template_id': 'mock-vuln-cve', 'severity': 'high', 'target': URL,
                               'matched_location': URL, 'verification_method': 'nuclei_template_match',
                               'verification_level': 'scanner_verified', 'independently_verified': False,
                               'verification_status': 'verified'}],
        'nuclei_observations': [{'observation_id': 'NUC-obs0001', 'tool_source': 'nuclei',
                                 'template_id': 'mock-panel-detect', 'kind': 'informational_nuclei_match'}],
        'candidates': [], 'execution_metrics': {'tool_calls_used': 1}, 'errors': [], 'events': [],
        'raw_bytes': 4, 'http_services': [], 'discovered_documents': [], 'web_routes': []}
    monkeypatch.setattr(scanner, 'scanner_settings', lambda: dict(SETTINGS))
    monkeypatch.setattr(scanner, 'tool_registry', lambda: {'nuclei': {'enabled': True, 'path': '/bin/nuclei'}})
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: phase)
    state = {**INVENTORIED, 'run_started_at': time.time() - 5, 'time_budget_seconds': 600,
             'tool_call_budget': 8, 'scanner_disabled': False}
    result = scanner.nuclei_scan(state)
    assert result['nuclei_scan'] == {'completed': True}
    assert [row['finding_id'] for row in result['verified_findings']] == ['NUC-phase0001']
    assert result['nuclei_observations'][0]['kind'] == 'informational_nuclei_match'


def test_graph_survives_planning_failure_with_scanner_findings_reported(monkeypatch):
    """A provider outage after the scan must never erase registered findings."""
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: {
        'nuclei_template_selections': [{'policy': {'coverage': 'test-scope'}}],
        'verified_findings': [{'finding_id': 'NUC-graphxy01', 'tool_source': 'nuclei',
                               'vulnerability_name': 'Mock graph flow', 'template_id': 'mock-vuln-cve',
                               'severity': 'high', 'target': URL, 'matched_location': URL,
                               'matcher_name': 'regex', 'matcher_status': True,
                               'category': 'nuclei_template_match', 'finding_type': 'potential_vulnerability',
                               'verification_method': 'nuclei_template_match',
                               'verification_level': 'scanner_verified', 'independently_verified': False,
                               'verification_status': 'verified', 'confidence': 'scanner_confirmed',
                               'actual_observation': {}, 'nuclei_metadata': {'template_id': 'mock-vuln-cve'},
                               'verification_evidence': {'result': 'confirmed', 'run_id': 'nuclei-graph-run',
                                                         'verification_method': 'nuclei_template_match',
                                                         'evidence_ref': '/nuclei-x.jsonl', 'evidence_line': 3}}],
        'nuclei_observations': [], 'candidates': [], 'execution_metrics': {'tool_calls_used': 1},
        'errors': [], 'events': [], 'raw_bytes': 0, 'http_services': [], 'discovered_documents': []})
    catalog = {'httpx': {'enabled': True, 'path': '/bin/httpx'}, 'nuclei': {'enabled': True, 'path': '/bin/nuclei'}}
    for module in (planner, tool_registry_module, scanner):
        monkeypatch.setattr(module, 'tool_registry', lambda: catalog)

    def completion(**kw):
        raise RuntimeError('mock provider outage')

    monkeypatch.setattr(planner.litellm, 'completion', completion)
    from src.adaptix.workflow.graph import graph
    run_id = f'nuclei-graph-{int(time.time())}'
    result = graph.invoke({'target': ['http://127.0.0.1:18080/'], 'run_id': run_id,
                           'user_prompt': 'inventarisasi api', 'max_iterations': 4,
                           'tool_call_budget': 8, 'token_budget': 4000,
                           'baseline_disabled': True, 'scanner_disabled': False},
                          config={'recursion_limit': 80})
    verified = [row for row in (result.get('verified_findings') or []) if isinstance(row, dict)]
    assert verified and verified[0]['finding_id'] == 'NUC-graphxy01'
    report = result.get('report') or {}
    assert [row['finding_id'] for row in report.get('nuclei_verified_findings', [])] == ['NUC-graphxy01']
    assert report['metrics']['research_comparison']['scanner_verified_findings'] == 1
    assert report['metrics']['research_comparison']['independently_verified_findings'] == 0
    checkpoint = json.loads(open(result['checkpoint_ref'], encoding='utf-8').read())
    assert [row['finding_id'] for row in checkpoint['verified_findings']] == ['NUC-graphxy01']
    assert '## Nuclei scanner matches (1)' in result['markdown_report']
