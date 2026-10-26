"""The token line reports tokens used; findings carry what the operator acts on."""
import glob
import json
import sys

sys.path.insert(0, '/root/projects/adaptix')

from src.adaptix.reporting.finding_ids import finding_ref
from src.adaptix.ui.state import TokenMeter, finding_detail, finding_rows

RUN = '/root/projects/adaptix/artifacts/scans/js-long-114926'


def _state():
    return json.load(open(sorted(glob.glob(RUN + '/checkpoint*.json'))[-1]))


def test_the_token_line_prints_tokens_used_and_nothing_else():
    # Measured: the line read "out 0 in 0 total 0 calls 5 failed 5 | last out 0 in 0 |"
    # while the ledger held 666,503 charged tokens, because failed calls carry no
    # per-call split. A zero must never stand in for an unknown.
    meter = TokenMeter(prompt_tokens=0, completion_tokens=0, charged=666503,
                       provider_calls=21, failed_calls=11, budget=9000000)
    line = meter.summary(100)
    assert 'used 666,503' in line
    assert 'calls' not in line and 'failed' not in line and 'last' not in line


def test_no_usage_bar_is_rendered():
    import pathlib
    screen = pathlib.Path(
        '/root/projects/adaptix/src/adaptix/ui/screen.py').read_text()
    assert "meter_lines = ['tokens  ' + view.tokens.summary(width)]" in screen
    assert "'usage   '" not in screen


def test_each_finding_reports_endpoint_payload_and_class():
    rows = finding_rows(_state())
    assert rows, 'the measured run has findings'
    detail = finding_detail(rows[0])
    assert detail['endpoint'] and detail['endpoint'].count('?') == 0, detail['endpoint']
    assert detail['parameter'], detail
    assert detail['payload'], detail
    assert detail['class'], detail
    assert detail['cwe'], detail
    assert detail['cause'] == '' and detail['mitigation'] == '', detail


def test_model_explanations_are_preferred_over_static_labels():
    row = {'evidence_id': 'EV-1', 'finding_type': 'sql_injection',
           'target': 'http://h/search?q=a', 'parameter': 'q', 'severity': 'high'}
    detail = finding_detail(row, {finding_ref(row): {
        'title': 'SQL injection pada pencarian',
        'cause': 'Model: nilai q dirangkai ke query.',
        'impact': 'Model: data lain terbaca.',
        'remediation': 'Model: gunakan parameter binding.'}})
    assert detail['title'] == 'SQL injection pada pencarian'
    assert detail['cause'].startswith('Model:')
    assert detail['mitigation'].startswith('Model:')
    assert 'Penyebab belum dicatat' not in detail['cause']


def test_one_hole_is_one_row():
    rows = finding_rows(_state())
    identities = [(row.get('target', '').split('?')[0], str(row.get('parameter') or ''),
                   str(row.get('class') or row.get('finding_type') or '')) for row in rows]
    assert len(identities) == len(set(identities)), identities
