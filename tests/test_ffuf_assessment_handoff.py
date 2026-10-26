"""ffuf import -> adaptive pentest graph handoff (opt-in) offline tests.

All scenarios are offline synthetic fixtures: ffuf documents are constructed in
memory, no target is contacted, no model is called and no scanner executes.
The contract under test: without the explicit operator opt-in the import stays
review-only exactly as before; with ``ffuf_into_assessment`` the imported
observations are released to the planner as unverified provenance only - they
never gain a verified label, and every scope, budget, policy and approval gate
of the existing graph still applies. These tests prove bookkeeping and
provenance, not detection recall.
"""
import time

import pytest

from src.adaptix.processing import ffuf as ffuf_module
from src.adaptix.agents.capabilities import (endpoint_provenance, eligible_targets,
                                            missing_prerequisites)
from src.adaptix.workflow.nodes import execute_action

PORT = 18080
URL = f'http://127.0.0.1:{PORT}/api/v1/echo'
DOCUMENT = [{'sha256': 'a' * 64, 'bytes': 4242, 'method': 'GET',
             'results': [{'url': URL, 'status': 200, 'length': 12, 'words': 2, 'lines': 1},
                         {'url': f'http://127.0.0.1:{PORT}/wildcard', 'status': 200}]}]


def _state(**extra):
    state = {
        'run_id': 'ffuf-handoff-fixture', 'target': ['http://127.0.0.1'],
        'hosts': ['127.0.0.1'], 'scope_ports': [PORT],
        'scope_aliases': {}, 'scope_networks': [], 'scope_manifest': {'hosts': ['127.0.0.1']},
        'time_budget_seconds': 600, 'tool_call_budget': 5, 'run_started_at': time.time(),
        'execution_metrics': {}, 'raw_bytes': 0, 'errors': [], 'events': [],
        'ffuf_import_documents': [dict(d) for d in DOCUMENT],
    }
    state.update(extra)
    return state


def _imported(state):
    update = ffuf_module.import_ffuf_documents(state)
    return {**state, **update}


# --- review-only stays the default --------------------------------------------

def test_import_without_optin_stays_review_only():
    merged = _imported(_state())
    assert ffuf_module.is_operator_review(merged) is True
    assert merged['operator_recon_review_only'] is True
    assert merged['baseline_disabled'] is True and merged['scanner_disabled'] is True
    assert all(row['verification_status'] == 'operator_supplied_unverified'
               for row in merged['ffuf_observations'])


def test_daemon_default_execute_action_stops_review_only():
    state = _imported(_state())
    result = execute_action(state)
    assert result['stop_reason'] == 'operator_recon_review_only'


def test_planner_flags_carry_through_import_receipts():
    merged = _imported(_state())
    assert all(row.get('assessment_seed') is False for row in merged['ffuf_imports'])
    assert ffuf_module.import_summary(merged)['mode'] == 'operator_supplied_offline_review'


# --- explicit opt-in releases unverified provenance only ----------------------

def test_optin_import_skips_review_only_markers():
    merged = _imported(_state(ffuf_into_assessment=True))
    assert ffuf_module.is_operator_review(merged) is False
    assert not merged.get('operator_recon_review_only')
    assert not merged.get('baseline_disabled') and not merged.get('scanner_disabled')
    assert any('released to planning' in event for event in merged['events'])
    assert all(row['assessment_seed'] is True for row in merged['ffuf_imports'])
    assert ffuf_module.import_summary(merged)['mode'] == 'operator_supplied_assessment_seed'


def test_optin_observations_keep_unverified_provenance():
    merged = _imported(_state(ffuf_into_assessment=True))
    for row in merged['ffuf_observations']:
        assert row['verification_status'] == 'operator_supplied_unverified'
        assert row['route_existence_verified'] is False
        assert row['source'] == 'operator_ffuf_json'
        assert row['source_sha256']


def test_optin_observations_gain_planner_provenance():
    from src.adaptix.security.scope import endpoint_key
    merged = _imported(_state(ffuf_into_assessment=True))
    provenance = endpoint_provenance(merged)
    row = provenance.get(endpoint_key(URL))
    assert row is not None
    assert 'operator_ffuf_json' in row['sources']
    assert 200 in row['status_codes']
    assert 'GET' in row['methods']
    assert any('ffuf_observation' in row['kinds'] for row in provenance.values())


def test_optin_endpoint_is_eligible_for_bounded_request():
    merged = _imported(_state(ffuf_into_assessment=True))
    action = {'tool': 'http_request', 'target': URL, 'method': 'GET'}
    assert missing_prerequisites(merged, action) == [], \
        'unverified seeds are provenance for a bounded request, not refusal'
    eligible = eligible_targets(merged, 'http_request')
    assert URL in [row['url'] for row in eligible]


def test_optin_out_of_scope_observations_stay_outside_planning():
    documents = [{'sha256': 'b' * 64, 'bytes': 100, 'method': 'GET',
                  'results': [{'url': 'http://example.org/api/v1/echo', 'status': 200}]}]
    merged = _imported(_state(ffuf_into_assessment=True, ffuf_import_documents=documents))
    assert merged['ffuf_observations'] == [], 'out-of-scope rows are rejected at the import boundary'
    assert any('outside_scope' in key for row in merged['ffuf_imports']
               for key in row.get('rejection_counts', {}))


def test_optin_execute_action_leaves_review_only_gate():
    merged = _imported(_state(ffuf_into_assessment=True, status='scope_ok',
                              authorization={'type': 'local_loopback'},
                              planned_actions=[]))
    result = execute_action(merged)
    assert result['stop_reason'] != 'operator_recon_review_only', \
        'seed mode must not be routed through the review-only stop'


def test_optin_run_reports_seed_mode(tmp_path):
    from src.adaptix.reporting.report import markdown_report
    markdown = markdown_report({
        'status': 'scan_completed', 'target': 'http://127.0.0.1', 'stop_reason': 'no_new_actions',
        'metrics': {}, 'ffuf_imports': [{'source_sha256': 'a' * 64, 'rejected_rows': 0}],
        'ffuf_observations': [{'url': URL, 'status_code': 200, 'method': 'GET',
                               'source_sha256': 'a' * 64}],
        'ffuf_into_assessment': True})
    assert 'unverified inventory' in markdown
    assert 'released to planning as unverified inventory' in markdown
    unseeded = markdown_report({
        'status': 'scan_completed', 'target': 'http://127.0.0.1', 'stop_reason': 'no_new_actions',
        'metrics': {}, 'ffuf_imports': [{'source_sha256': 'a' * 64, 'rejected_rows': 0}],
        'ffuf_observations': [{'url': URL, 'status_code': 200, 'method': 'GET',
                               'source_sha256': 'a' * 64}]})
    assert 'released to planning' not in unseeded


def test_optin_planner_context_keeps_status_honest():
    """The planner payload in seed mode comes from the normal path, not review-only."""
    from src.adaptix.agents import planner as planner_module
    merged = _imported(_state(ffuf_into_assessment=True))
    assert not merged.get('operator_recon_review_only')
    # Simulate the mode flip the old code applied pre-handoff; with the opt-in it
    # must not be applied at planning time.
    from src.adaptix.processing.ffuf import is_operator_review
    assert is_operator_review(merged) is False, 'planning must not be forced into evaluation-only'
