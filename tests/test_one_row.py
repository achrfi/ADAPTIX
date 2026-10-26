"""One hole is one row: the boolean proof and the extraction must merge.

Measured defect this locks: the oracle record wrote the whole URL into
`actual_observation.parameter`, so its identity became (path, full-URL, class) while the
extraction recorded (path, 'q', class). The same SQL injection appeared twice - once as a
`critical` row carrying the extracted password hash and once as a plain `high` match - and
an operator reading the report could not tell they were one hole.
"""
import sys

sys.path.insert(0, '/root/projects/adaptix')

from src.adaptix.agents.reflector import _merge_report_findings, _parameter_name

URL = 'http://h/rest/search?q=%27%29%29+OR+1%3D1--'

BOOLEAN = {
    'target': URL, 'finding_type': 'sql_injection', 'severity': 'high',
    'verification_status': 'verified',
    'actual_observation': {'method': 'GET', 'parameter': _parameter_name(URL)},
    'parameter': _parameter_name(URL),
}
EXTRACTION = {
    'target': 'http://h/rest/search', 'parameter': 'q', 'finding_type': 'sql_injection',
    'impact_proven': True, 'extracted_classes': ['password_hash'],
    'severity': 'critical', 'verification_status': 'verified',
    'source_tool': 'union_extract', 'evidence_basis': 'union_extraction_executed',
}


def test_the_parameter_name_is_extracted_not_the_url():
    assert _parameter_name(URL) == 'q'
    assert _parameter_name('http://h/path') == ''
    assert _parameter_name('http://h/#/view?term=1') == 'term'


def test_one_hole_is_one_row():
    rows = _merge_report_findings([], [BOOLEAN, EXTRACTION])
    assert len(rows) == 1, rows
    assert rows[0]['impact_proven'] is True, rows[0]
    assert rows[0]['extracted_classes'] == ['password_hash'], rows[0]
    assert rows[0]['severity'] == 'critical', rows[0]
