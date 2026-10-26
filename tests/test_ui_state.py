"""The live view must agree with the run it is showing.

Measured motivation: the report deduplicates findings and reads token counts from the
provider ledger. A screen that counted differently would show numbers the deliverable
does not contain, and an operator would trust the screen.
"""
import sys

sys.path.insert(0, '/root/projects/adaptix')

from src.adaptix.ui.state import (LiveView, finding_detail, finding_rows,
                                  read_tokens, view_from_report, view_from_state)

LEDGER = [
    {'provider_call': True, 'source': 'provider', 'tokens_charged': 20112,
     'prompt_tokens': 20112, 'completion_tokens': 940, 'model': 'autoapp/minimax-m3',
     'result': 'valid_decision'},
    {'provider_call': True, 'source': 'provider', 'tokens_charged': 20480,
     'prompt_tokens': 20480, 'completion_tokens': 1080, 'model': 'autoapp/minimax-m3',
     'result': 'valid_decision'},
    {'provider_call': False, 'source': 'cache', 'tokens_charged': 0,
     'result': 'valid_decision'},
]


def test_completion_tokens_are_summed_from_the_provider_ledger():
    meter = read_tokens({'token_ledger': LEDGER, 'token_budget': 5_000_000})
    assert meter.completion_tokens == 2020
    assert meter.prompt_tokens == 40592
    assert meter.total == 42612
    assert meter.provider_calls == 2
    assert meter.cache_hits == 1
    assert meter.last_completion == 1080


def test_a_starved_call_is_counted_as_a_failure_not_as_output():
    meter = read_tokens({'token_ledger': [
        {'provider_call': True, 'source': 'reservation', 'tokens_charged': 3072,
         'prompt_tokens': 0, 'completion_tokens': 0,
         'result': 'reasoning_starvation', 'error_type': 'ProviderStarvation'}]})
    assert meter.failed_calls == 1
    assert meter.completion_tokens == 0
    assert meter.charged == 3072


def test_remaining_budget_never_goes_negative():
    meter = read_tokens({'token_ledger': LEDGER, 'token_budget': 1000})
    assert meter.remaining == 0
    assert meter.used_fraction == 1.0


def test_an_unlimited_budget_reports_no_remaining():
    meter = read_tokens({'token_ledger': LEDGER, 'token_budget': None})
    assert meter.remaining is None
    assert 'budget' not in meter.summary()


def test_a_run_before_its_first_pass_uses_metrics_not_zero():
    meter = read_tokens({'planner_metrics': {'last_prompt_tokens': 20112,
                                            'last_completion_tokens': 700,
                                            'llm_calls': 1}})
    assert meter.prompt_tokens == 20112
    assert meter.completion_tokens == 700


def test_findings_are_deduplicated_by_path_parameter_and_class():
    state = {'injection_findings': [
        {'class': 'sql_injection', 'target': 'http://h/s?q=a', 'parameter': 'q'},
        {'class': 'sql_injection', 'target': 'http://h/s?q=UNION', 'parameter': 'q'}],
        'idor_findings': [{'finding_type': 'broken_object_level_authorization',
                           'target': 'http://h/rest/basket/8'}],
        'script_findings': [{'finding_type': 'cross_site_scripting',
                             'target': 'http://h/#/search?q=x'}]}
    rows = finding_rows(state)
    assert len(rows) == 3, rows


def test_probe_buckets_do_not_add_blank_rows_to_the_live_view():
    sql_url = 'http://h/rest/products/search?q=a'
    xss_url = 'http://h/#/?q=payload'
    state = {
        'findings': [
            {'finding_id': 'NUC-1', 'finding_type': 'potential_vulnerability',
             'severity': 'medium', 'target': 'http://h/metrics',
             'verification_status': 'scanner_matched'},
            {'evidence_id': 'EV-1', 'finding_type': 'sql_injection',
             'severity': 'high', 'target': sql_url, 'parameter': 'q',
             'verification_status': 'verified'},
            {'evidence_id': 'EV-2', 'finding_type': 'cross_site_scripting',
             'severity': 'medium', 'target': xss_url, 'parameter': 'q',
             'verification_status': 'verified'}],
        'injection_findings': [
            {'target': sql_url, 'parameter': 'q', 'verification_status': 'verified',
             'verification_basis': 'differential_injection'}],
        'script_findings': [
            {'target': xss_url, 'parameter': 'q', 'verification_status': 'verified',
             'verification_basis': 'browser_execution'}],
    }
    rows = finding_rows(state)
    assert len(rows) == 3, rows
    assert all(row.get('severity') for row in rows), rows
    assert all(row.get('class') for row in rows), rows
    assert {row['class'] for row in rows} == {
        'potential_vulnerability', 'sql_injection', 'cross_site_scripting'}


def test_the_final_report_view_discards_unverified_scanner_matches():
    report = {
        'findings': [
            {'evidence_id': 'EV-1', 'finding_type': 'sql_injection',
             'severity': 'high', 'target': 'http://h/search?q=a',
             'verification_status': 'verified'},
            {'finding_id': 'NUC-1', 'finding_type': 'potential_vulnerability',
             'severity': 'medium', 'target': 'http://h/metrics',
             'verification_status': 'scanner_matched'}],
        'scanner_matched_findings': [
            {'finding_id': 'NUC-1', 'finding_type': 'potential_vulnerability',
             'severity': 'medium', 'target': 'http://h/metrics',
             'verification_status': 'scanner_matched'}],
    }
    view = view_from_report(report)
    assert len(view.findings) == 1, view.findings
    assert view.details[0]['status'] == 'verified', view.details

def test_a_sql_extraction_shows_the_injected_url_and_payload():
    url = 'http://h/search?q=x%27%29%29%20UNION%20SELECT%201%2C2%2C3--'
    payload = "x')) UNION SELECT 1,2,3--"
    row = {'evidence_id': 'EV-EXTRACT-1', 'finding_type': 'sql_injection',
           'target': 'http://h/search', 'url': url, 'parameter': 'q',
           'payload': payload, 'verification_status': 'verified',
           'severity': 'critical', 'extracted_classes': ['password_hash']}
    detail = finding_detail(row)
    assert detail['endpoint'] == 'http://h/search', detail
    assert detail['url'] == url, detail
    assert detail['payload'] == payload, detail

def test_a_legacy_sqli_row_falls_back_to_its_signed_replay_url():
    url = 'http://h/search?q=a%27+OR+1%3D1--'
    row = {'evidence_id': 'EV-1', 'finding_type': 'sql_injection',
           'target': 'http://h/search', 'parameter': 'q',
           'verification_status': 'verified',
           'verification_evidence': {'url': url}}
    detail = finding_detail(row)
    assert detail['url'] == url, detail
    assert detail['payload'] == "a' OR 1=1--", detail

def test_a_probe_record_without_a_canonical_row_still_has_a_class():
    rows = finding_rows({'script_findings': [
        {'target': 'http://h/#/?q=x', 'parameter': 'q',
         'verification_basis': 'browser_execution'}]})
    assert rows[0]['class'] == 'cross_site_scripting'


def test_the_view_keeps_configuration_when_a_snapshot_arrives():
    view = LiveView(model='m', target=['http://h'], identity='/tmp/id.json',
                    token_budget=1234)
    merged = view_from_state({'iterations': 3, 'token_ledger': LEDGER}, view)
    assert merged.identity == '/tmp/id.json'
    assert merged.token_budget == 1234
    assert merged.iteration == 3
    assert merged.tokens.completion_tokens == 2020


def test_progress_tracks_the_current_langgraph_node():
    from src.adaptix.ui.state import view_from_progress

    view = view_from_progress({'node': 'baseline_reconnaissance', 'phase': 'running',
                               'iteration': 0, 'stop_reason': None})
    assert view.workflow_node == 'baseline_reconnaissance'
    assert view.workflow_phase == 'running'
    assert view.status == 'running'
    assert 'graph baseline_reconnaissance running' in view.header_lines()[-1]


def test_report_narrative_reaches_the_live_view_and_token_meter():
    from src.adaptix.ui.state import view_from_report

    report = {
        'status': 'completed_partial', 'stop_reason': 'no_new_actions',
        'llm_model': 'openai/test', 'findings': [{
            'evidence_id': 'EV-1', 'finding_type': 'sql_injection', 'severity': 'high',
            'target': 'http://h/search?q=a', 'parameter': 'q'}],
        'finding_explanations': {'EV-1': {
            'title': 'SQL injection', 'cause': 'Model cause', 'impact': 'Model impact',
            'remediation': 'Model remedy'}},
        'narrative': {'title': 'Laporan model', 'executive_summary': 'Ringkasan model'},
        'token_ledger': [{'provider_call': True, 'source': 'provider',
                          'tokens_charged': 1200, 'prompt_tokens': 1000,
                          'completion_tokens': 200, 'model': 'openai/test'}],
        'budget_status': {'token_budget': {'configured': 50000}},
    }
    view = view_from_report(report)
    assert view.status == 'completed_partial'
    assert view.model == 'openai/test'
    assert view.details[0]['cause'] == 'Model cause'
    assert view.details[0]['mitigation'] == 'Model remedy'
    assert view.narrative['executive_summary'] == 'Ringkasan model'
    assert view.tokens.charged == 1200
