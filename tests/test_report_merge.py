"""Every proven class must reach `findings`, not only the probe-trace ones.

Measured defect this locks: a live run (js-tool-194124) had five verified findings -
BOLA high, SQLi high, browser XSS medium, and two UNION extractions - but the report
carried one, because `result['findings']` was assigned `build_findings(state)` and that
function can only synthesize from `probe_traces`. BOLA and browser XSS never write a
probe trace.

The unit under test is `_merge_report_findings`. `collect_findings` itself refuses a
finding without a signed proof on disk, so a synthetic state cannot reach `verified` -
that is the reflector's evidence discipline working, not a gap in this test.
"""
import glob
import json
import os
import sys

sys.path.insert(0, '/root/projects/adaptix')

from src.adaptix.agents.reflector import (_merge_report_findings, _report_identity,
                                          collect_findings)

BOLA = {'evidence_id': 'EV-1', 'source_tool': 'authorization_probe',
        'finding_type': 'broken_object_level_authorization', 'severity': 'high',
        'target': 'http://h/rest/basket/8', 'verification_status': 'verified'}
XSS = {'evidence_id': 'EV-2', 'source_tool': 'script_probe',
       'finding_type': 'cross_site_scripting', 'severity': 'medium',
       'target': 'http://h/#/search?q=x', 'verification_status': 'verified'}
SQLI_WEB = {'finding_id': 'WEB-001', 'finding_type': 'sql_injection', 'severity': 'high',
            'target': 'http://h/search?q=a', 'parameter': 'q',
            'verification_status': 'confirmed'}
SQLI_ORACLE = {'evidence_id': 'EV-3', 'source_tool': 'injection_probe',
               'finding_type': 'sql_injection', 'severity': 'high',
               'target': 'http://h/search?q=a', 'verification_status': 'verified'}
UNION = {'evidence_id': 'EV-4', 'source_tool': 'http_request',
         'finding_type': 'sql_injection', 'severity': 'high',
         'target': 'http://h/search?q=a%29%29+UNION+SELECT+1', 'parameter': 'q',
         'verification_status': 'verified'}
INCONCLUSIVE = {'evidence_id': 'EV-5', 'finding_type': 'potential_vulnerability',
                'severity': 'medium', 'target': 'http://h/metrics',
                'verification_status': 'inconclusive'}
SCANNER = {'finding_id': 'NUC-1', 'finding_type': 'potential_vulnerability',
           'severity': 'medium', 'target': 'http://h/metrics',
           'verification_status': 'scanner_matched',
           'verification_method': 'nuclei_template_match'}
UNION_EXTRACT = {'evidence_id': 'EV-EXTRACT-1', 'source_tool': 'union_extract',
                 'finding_type': 'sql_injection', 'target': 'http://h/search',
                 'url': 'http://h/search?q=x%27%29%29%20UNION%20SELECT%201%2C2%2C3--',
                 'parameter': 'q',
                 'payload': "x')) UNION SELECT 1,2,3--",
                 'verification_status': 'verified', 'severity': 'critical',
                 'impact_proven': True, 'impact': 'union_data_extraction',
                 'extracted_classes': ['password_hash']}


def test_bola_and_browser_xss_reach_the_report():
    merged = _merge_report_findings([], [BOLA, XSS])
    kinds = {row.get('finding_type') for row in merged}
    assert kinds == {'broken_object_level_authorization', 'cross_site_scripting'}, kinds


def test_probe_and_oracle_records_of_one_vulnerability_are_one_row():
    merged = _merge_report_findings([SQLI_WEB], [SQLI_ORACLE, UNION])
    sql = [row for row in merged if row.get('finding_type') == 'sql_injection']
    assert len(sql) == 1, sql
    # The strongest identity survives: the web finding keeps its report id.
    assert sql[0].get('finding_id') == 'WEB-001', sql[0]


def test_payload_is_not_part_of_finding_identity():
    first = {'finding_type': 'sql_injection', 'target': 'http://h/search?q=a',
             'parameter': 'q'}
    second = {'finding_type': 'sql_injection', 'target': 'http://h/search?q=b',
              'parameter': 'q'}
    assert _report_identity(first) == _report_identity(second)


def test_an_inconclusive_record_never_reaches_findings():
    merged = _merge_report_findings([], [INCONCLUSIVE])
    assert merged == [], merged

def test_a_scanner_match_is_not_a_final_finding():
    merged = _merge_report_findings([], [SCANNER])
    assert merged == [], merged

def test_a_verified_extraction_keeps_its_exact_url_and_payload():
    merged = _merge_report_findings([], [UNION_EXTRACT])
    assert len(merged) == 1, merged
    assert merged[0]['url'] == UNION_EXTRACT['url'], merged[0]
    assert merged[0]['payload'] == UNION_EXTRACT['payload'], merged[0]
    assert merged[0]['extracted_classes'] == ['password_hash'], merged[0]

def test_collect_findings_carries_the_extraction_reproduction_into_the_report():
    raw = {'class': 'sql_injection', 'target': 'http://h/search',
           'url': UNION_EXTRACT['url'], 'parameter': 'q',
           'payload': UNION_EXTRACT['payload'], 'impact_proven': True,
           'impact': 'union_data_extraction', 'extracted_classes': ['password_hash'],
           'rows_returned': 3, 'verification_status': 'verified',
           'severity': 'critical', 'source_tool': 'union_extract'}
    out = collect_findings({'injection_findings': [raw]})
    row = next(row for row in out['findings'] if row.get('finding_type') == 'sql_injection')
    assert row['url'] == UNION_EXTRACT['url'], row
    assert row['payload'] == UNION_EXTRACT['payload'], row
    assert row['reproduction']['payload'] == UNION_EXTRACT['payload'], row


def test_a_real_run_reports_every_class_it_verified():
    """Regression against the measured checkpoint: one row became four."""
    run = '/root/projects/adaptix/artifacts/scans/js-tool-194124'
    checkpoints = sorted(glob.glob(run + '/checkpoint*.json'))
    if not checkpoints:
        return  # artifact not present in this checkout
    state = json.load(open(checkpoints[-1]))
    out = collect_findings(state)
    kinds = {str(row.get('finding_type') or row.get('category'))
             for row in out.get('findings') or []}
    assert 'broken_object_level_authorization' in kinds, kinds
    assert 'cross_site_scripting' in kinds, kinds
    assert 'sql_injection' in kinds, kinds


def test_the_markdown_opens_with_one_row_per_vulnerability():
    """A reader must not have to dedupe five sealed records into four holes."""
    from src.adaptix.reporting.report import markdown_report
    report = {
        'status': 'completed_partial', 'target': ['http://h'], 'stop_reason': None,
        'metrics': {}, 'verified_findings': [], 'scanner_matched_findings': [],
        'inconclusive_findings': [], 'findings': [
            {'finding_type': 'sql_injection', 'severity': 'high',
             'verification_status': 'confirmed', 'target': 'http://h/search?q=a',
             'verification_basis': 'deterministic_replay'},
            {'finding_type': 'cross_site_scripting', 'severity': 'medium',
             'verification_status': 'verified', 'target': 'http://h/#/s?q=x',
             'source_tool': 'script_probe'},
        ],
    }
    md = markdown_report(report)
    assert '## Findings (2)' in md, md[:400]
    assert md.count('| 1 |') == 1 and md.count('| 2 |') == 1, md[:900]
