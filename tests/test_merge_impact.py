"""A proven extraction must survive the merge and the report.

Measured defect this locks: a live run extracted a real password hash through the UNION
injection and the report still listed one row - the SQLi match. `collect_findings` reads
`verified_findings`; `union_extract` wrote `injection_findings`, and the merge that
combined the two records dropped `impact_proven`. Impact that no deliverable shows is
impact the run did not have.
"""
import sys

sys.path.insert(0, '/root/projects/adaptix')

from src.adaptix.agents.reflector import _merge_entry, _merge_report_findings

BOOLEAN = {
    'target': 'http://h/rest/search?q=%27%29%29+OR+1%3D1--', 'finding_type': 'sql_injection',
    'severity': 'high', 'verification_status': 'verified', 'finding_id': 'WEB-001',
}
EXTRACTION = {
    'target': 'http://h/rest/search', 'parameter': 'q', 'finding_type': 'sql_injection',
    'impact': 'union_data_extraction', 'extracted_classes': ['password_hash'],
    'impact_proven': True, 'evidence_basis': 'union_extraction_executed',
    'severity': 'critical', 'verification_status': 'verified',
    'source_tool': 'union_extract', 'rows_returned': 3,
}


def test_the_merge_keeps_the_proven_impact():
    merged = _merge_entry(BOOLEAN, EXTRACTION)
    assert merged['impact_proven'] is True, merged
    assert merged['extracted_classes'] == ['password_hash'], merged
    assert merged['severity'] == 'critical', merged
    assert merged['finding_id'] == 'WEB-001', merged


def test_the_report_shows_one_row_that_carries_the_impact():
    rows = _merge_report_findings([], [BOOLEAN, EXTRACTION])
    assert len(rows) == 1, rows
    assert rows[0]['impact_proven'] is True, rows[0]
    assert rows[0]['extracted_classes'] == ['password_hash'], rows[0]
