"""An extraction must find a proven injection in whichever bucket recorded it.

Measured defect this locks: with the baseline sweep disabled, the SQL injection probe
writes its evidence to `findings` (`finding_type`, `path_key`, `parameter`) and leaves
`injection_findings` empty. `union_extract` read only the latter and returned
"no verified injection finding names a target and parameter" on a run that had just
proven one - so the escalation never ran and the objective was reported not assessed.
"""
import sys

sys.path.insert(0, '/root/projects/adaptix')

from src.adaptix.tools.union_extract import _injection_record, _target_and_parameter

PROBE_FINDING = {
    'finding_id': 'WEB-001',
    'finding_type': 'sql_injection',
    'parameter': 'q',
    'path_key': 'http://127.0.0.1:3000/rest/products/search',
    'target': 'http://127.0.0.1:3000/rest/products/search?q=%27%29%29+UNION+SELECT+9--',
    'reproduction': {'payload': "a')) UNION SELECT 1--", 'parameter': 'q'},
    'title': 'SQL injection indicator',
}

BASIS_ONLY_FINDING = {
    'source_tool': 'injection_probe',
    'target': "http://127.0.0.1:3000/rest/products/search?q=a%27+OR+1%3D1--",
    'parameter': 'q',
    'payload': "a' OR 1=1--",
    'verification_status': 'verified',
    'verification_basis': 'differential_injection',
}


def test_a_basis_only_probe_record_is_recognized():
    record = _injection_record(BASIS_ONLY_FINDING)
    assert record == ('http://127.0.0.1:3000/rest/products/search', 'q', "a' OR 1=1--"), record


def test_the_probe_bucket_is_read():
    # The exact shape a baseline-free run produces.
    base, parameter, payload = _target_and_parameter({'findings': [PROBE_FINDING]})
    assert base == 'http://127.0.0.1:3000/rest/products/search'
    assert parameter == 'q'
    assert payload == "a')) UNION SELECT 1--"


def test_the_parameter_can_come_from_the_query_string():
    finding = dict(PROBE_FINDING)
    finding.pop('parameter')
    finding.pop('reproduction')
    finding['path_key'] = ''
    finding['target'] = 'http://h/item?id=4'
    record = _injection_record(finding)
    assert record == ('http://h/item', 'id', ''), record


def test_a_scanner_match_is_not_escalated_as_an_injection():
    scanner = {'finding_type': 'potential_vulnerability', 'parameter': 'q',
               'target': 'http://h/metrics', 'verification_basis': 'nuclei_template_match'}
    assert _target_and_parameter({'findings': [scanner]}) == ('', '', '')


def test_an_injection_bucket_still_wins_when_present():
    first = {'finding_type': 'sql_injection', 'parameter': 'q',
             'path_key': 'http://h/a'}
    second = {'finding_type': 'sql_injection', 'parameter': 'id',
              'path_key': 'http://h/b'}
    base, parameter, _payload = _target_and_parameter(
        {'injection_findings': [second], 'findings': [first]})
    assert (base, parameter) == ('http://h/b', 'id')


def test_a_finding_that_is_not_an_injection_is_ignored():
    # A scanner match and an XSS finding must not be escalated as SQL injection.
    state = {'findings': [{'finding_type': 'potential_vulnerability', 'parameter': 'q',
                           'path_key': 'http://h/metrics'},
                          {'finding_type': 'cross_site_scripting', 'parameter': 'q',
                           'path_key': 'http://h/search'}]}
    assert _target_and_parameter(state) == ('', '', '')
