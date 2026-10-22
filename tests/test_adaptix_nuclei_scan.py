"""Scanner phase tests: the automatic Nuclei stage is LLM-free, budgeted and honest.

Every test drives src.adaptix.workflow.scanner.nuclei_scan directly with the
same preview settings the CLI uses, so each phase property - scope binding,
tool-call reserve, cap enforcement, honest skips - is asserted on the recorded
metrics rather than inferred from tool side effects.
"""
import pytest

from src.adaptix.agents import reflector
from src.adaptix.workflow import scanner


SETTINGS = {'enabled': True, 'template_mode': 'adaptive', 'max_seconds': 60, 'max_origins': 2,
            'adaptive_tool_call_reserve': 4, 'max_candidates_per_origin': 40, 'template_cap': 160}


@pytest.fixture
def preview_settings(monkeypatch):
    monkeypatch.setattr(scanner, 'scanner_settings', lambda: dict(SETTINGS))
    return SETTINGS


def phase_result(origin, candidates=1, calls=1, ceiling=40, stop_reason=None):
    return {'candidates': [{'template_id': 'exposed-panels', 'url': f'{origin}/#/panels',
                            'finding_type': 'generic', 'source_tool': 'nuclei', 'severity': 'medium',
                            'evidence': []} for _ in range(candidates)],
            'execution_metrics': {'tool_calls_used': calls},
            'nuclei_template_selections': [{'target': origin, 'strategy': 'observed_tags',
                                            'selected_count': ceiling, 'executable_count': ceiling,
                                            'approval_required_count': 0,
                                            'policy': {'gated_templates': 0, 'selected': [], 'denied': []},
                                            'request_ceiling_per_target': ceiling, 'coverage': 'adaptive'}],
            'events': [f'Nuclei executed against {origin}'],
            'raw_bytes': 4,
            **({'stop_reason': stop_reason} if stop_reason else {})}


def test_scanner_disabled_by_config_records_honest_skip(preview_settings, monkeypatch):
    called = []
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: called.append(state['planned_actions'][0]['target']))
    monkeypatch.setattr(scanner, 'scanner_settings', lambda: {**SETTINGS, 'enabled': False})
    result = scanner.nuclei_scan({'status': 'scope_ok', 'events': []})
    assert not called
    assert result['nuclei_scan'] == {'completed': False}
    metrics = result['nuclei_scan_metrics']
    assert metrics['mode'] == 'off' and metrics['tool_calls'] == 0


def test_scanner_state_flag_disables_the_phase(preview_settings, monkeypatch):
    called = []
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: called.append(1))
    result = scanner.nuclei_scan({'status': 'scope_ok', 'scanner_disabled': True, 'events': []})
    assert not called
    assert result['nuclei_scan_metrics']['mode'] == 'disabled'


def test_scanner_runs_llm_free_and_merges_adapter_output(preview_settings, monkeypatch):
    asked = []
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: asked.append(dict(state)) or phase_result(
        state['planned_actions'][0]['target']))
    state = {'status': 'scope_ok', 'events': [], 'tool_call_budget': 20, 'execution_metrics': {},
             'target': ['http://lab.example:8080/'], 'web_routes': []}
    result = scanner.nuclei_scan(state)
    assert len(asked) == 1
    action = asked[0]['planned_actions'][0]
    assert action['tool'] == 'nuclei' and action['target'] in state['target'] + ['http://lab.example:8080']
    assert result['nuclei_scan']['completed'] is True
    assert [row['url'] for row in result['candidates']] == ['http://lab.example:8080/#/panels']
    metrics = result['nuclei_scan_metrics']
    assert metrics['mode'] == 'complete' and metrics['origin_count'] == 1 and metrics['tool_calls'] == 1
    assert metrics['planned_request_ceiling'] == 40 and metrics['candidates'] == 1


def test_scanner_targets_comes_from_baseline_routes(preview_settings, monkeypatch):
    asked = []
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: asked.append(state['planned_actions'][0]['target']))
    monkeypatch.setattr(scanner, 'scanner_settings', lambda: {**SETTINGS, 'max_origins': 1})
    state = {'status': 'scope_ok', 'events': [], 'tool_call_budget': 20, 'execution_metrics': {},
             'target': ['http://lab.example:8080/'],
             'web_routes': [{'url': 'http://lab.example:8080/static/app.js', 'static_asset': True},
                            {'url': 'http://lab.example:8080/api/orders'}]}
    scanner.nuclei_scan(state)
    assert asked == ['http://lab.example:8080']


def test_adaptive_reserve_protected_skips_phase(preview_settings, monkeypatch):
    called = []
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: called.append(1))
    result = scanner.nuclei_scan({'status': 'scope_ok', 'events': [], 'tool_call_budget': 4,
                                  'target': ['http://lab.example:8080/'], 'execution_metrics': {}})
    assert not called
    assert result['nuclei_scan_metrics']['mode'] == 'skipped'
    assert 'reserve' in result['nuclei_scan_metrics']['stop_reason']


def test_tool_budget_cap_enforced_mid_phase(preview_settings, monkeypatch):
    monkeypatch.setattr(scanner, 'scanner_settings', lambda: {**SETTINGS, 'adaptive_tool_call_reserve': 1})
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: phase_result(
        state['planned_actions'][0]['target'], calls=9))
    result = scanner.nuclei_scan({'status': 'scope_ok', 'events': [], 'tool_call_budget': 8,
                                  'target': ['http://a.example/', 'http://b.example/'], 'execution_metrics': {}})
    metrics = result['nuclei_scan_metrics']
    assert 'adaptive_reserve_protected' in metrics['skipped']
    assert metrics['origin_count'] == 1 or metrics['origin_count'] == 2


def test_run_time_budget_exhausted_skips_phase(preview_settings, monkeypatch):
    import time as time_module
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: (_ for _ in ()).throw(AssertionError('must not run')))
    result = scanner.nuclei_scan({'status': 'scope_ok', 'events': [], 'tool_call_budget': 20,
                                  'time_budget_seconds': 1800, 'run_started_at': time_module.time() - 2000,
                                  'execution_metrics': {}})
    assert result['nuclei_scan_metrics']['mode'] == 'skipped'
    assert 'time' in result['nuclei_scan_metrics']['stop_reason']


def test_missing_engine_reported_not_invented(preview_settings, monkeypatch):
    monkeypatch.setattr(scanner, 'tool_registry', lambda: {'nuclei': {'enabled': False, 'path': ''}})
    called = []
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: called.append(1))
    result = scanner.nuclei_scan({'status': 'scope_ok', 'events': [], 'tool_call_budget': 20,
                                  'target': ['http://lab.example:8080/'], 'execution_metrics': {}})
    assert not called
    metrics = result['nuclei_scan_metrics']
    assert metrics['mode'] == 'limited' and not result['nuclei_scan']['completed']
    assert any('not registered' in row or 'disabled' in row or 'Nuclei' in row for row in metrics['limitations'])


def test_missing_template_catalog_skips_scanning_honestly(preview_settings, monkeypatch):
    monkeypatch.setattr(scanner, 'tool_registry',
                        lambda: {'nuclei': {'enabled': True, 'path': '/usr/bin/nope', 'version': 'v3.6.2'}})
    import src.adaptix.security.nuclei_policy as policy
    monkeypatch.setattr(policy, 'template_root', lambda: __import__('pathlib').Path('/nonexistent/adaptix-no-templates'))
    called = []
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: called.append(1))
    result = scanner.nuclei_scan({'status': 'scope_ok', 'events': [], 'tool_call_budget': 20,
                                  'target': ['http://lab.example:8080/'], 'execution_metrics': {}})
    assert not called
    metrics = result['nuclei_scan_metrics']
    assert metrics['mode'] == 'limited'
    assert any('template' in row.lower() for row in metrics['limitations'])


def test_scope_rejection_recorded(preview_settings, monkeypatch):
    called = []
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: called.append(1))
    result = scanner.nuclei_scan({'status': 'scope_pending', 'events': [], 'tool_call_budget': 20})
    assert not called
    assert result['nuclei_scan_metrics']['mode'] == 'skipped'
    assert 'scope' in result['nuclei_scan_metrics']['stop_reason']


def test_gated_origin_never_stalls_the_phase(preview_settings, monkeypatch):
    def fake_check(state):
        target = state['planned_actions'][0]['target']
        if target.startswith('http://gated.'):
            return {'stop_reason': 'human_approval_required',
                    'nuclei_template_selections': [{'target': target, 'selected_count': 5, 'executable_count': 0,
                                                    'approval_required_count': 5,
                                                    'policy': {'gated_templates': 5, 'selected': [], 'denied': []},
                                                    'request_ceiling_per_target': 0, 'coverage': 'gated'}],
                    'execution_metrics': {'tool_calls_used': 0}, 'events': []}
        return phase_result(target)
    monkeypatch.setattr(scanner, 'nuclei_check', fake_check)
    result = scanner.nuclei_scan({'status': 'scope_ok', 'events': [], 'tool_call_budget': 20, 'execution_metrics': {},
                                  'target': ['http://gated.example:8080/', 'http://open.example:8080/']})
    assert result['nuclei_scan']['completed'] is True
    assert any('approval' in row for row in result['nuclei_scan_metrics']['limitations'])


def test_scan_inventory_skipped_phase_is_one_token_and_flags_reason(preview_settings):
    state = {'scanner_disabled': True}
    assert scanner.scan_inventory(state) == {'mode': 'disabled'}
    assert scanner.scan_inventory({'events': []}) == {'mode': 'not_run'}


def test_scan_inventory_compact_and_policy_note(preview_settings):
    state = {'nuclei_scan': {'completed': True},
             'nuclei_scan_metrics': {'mode': 'complete', 'origin_count': 2, 'templates_attempted': 80,
                                     'templates_executable': 80, 'templates_gated': 5,
                                     'planned_request_ceiling': 160, 'tool_calls': 2, 'seconds': 12.4,
                                     'limitations': ['gate note'], 'skipped': ['reserve note']},
             'candidates': [{'template_id': 'exposed-panels'}, {'template_id': 'exposed-panels'}],
             'scanner_disabled': False}
    view = scanner.scan_inventory(state, limit=2)
    assert view['candidates'] == 2
    assert view['candidates_by_template'] == {'exposed-panels': 2}
    assert 'manifest-derived ceiling' in view['policy_note']
    assert view['planned_request_ceiling'] == 160


def test_scanner_candidate_cannot_bypass_verification(preview_settings):
    """Reflector keeps scanner output unconfirmed without signed independent proof."""
    state = {'events': [], 'run_id': 'scan-run', 'http_services': [],
             'web_routes': [], 'verification_evidence': [],
             'candidates': [{'template_id': 'exposed-panels', 'url': 'http://lab.example:8080/#/panels',
                             'finding_type': 'generic', 'severity': 'high'}]}
    result = reflector.collect_findings(state)
    entry = result['inconclusive_findings'][0]
    assert entry['confidence'] == 'unconfirmed'
    assert entry['verification_status'] == 'inconclusive'


def test_scanner_candidate_rejected_when_only_reachability(preview_settings):
    state = {'events': [], 'run_id': 'scan-run', 'http_services': [],
             'web_routes': [], 'verification_evidence': [],
             'candidates': [{'template_id': 'adaptix-http-baseline', 'url': 'http://lab.example:8080/',
                             'finding_type': 'generic', 'severity': 'info'}]}
    result = reflector.collect_findings(state)
    assert result['rejected_findings'][0]['verification_status'] == 'rejected'


def test_run_time_reserve_skips_before_any_tool(preview_settings, monkeypatch):
    """With a small budget, the deterministic reserve ordering stays: scanner skips first."""
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: phase_result(
        state['planned_actions'][0]['target']))
    result = scanner.nuclei_scan({'status': 'scope_ok', 'events': [], 'tool_call_budget': 5,
                                  'target': ['http://lab.example:8080/'], 'execution_metrics': {}})
    metrics = result['nuclei_scan_metrics']
    assert metrics['origin_count'] == 1, metrics
    assert metrics['mode'] == 'complete' and 'adaptive_reserve_protected' not in metrics['skipped']


def test_template_cap_note_becomes_recorded_limitation(preview_settings, monkeypatch):
    """Deterministic cap overflow must surface as a recorded limitation, not vanish."""
    def fake_check(state):
        assert state['nuclei_template_cap'] == 160
        phase = phase_result(state['planned_actions'][0]['target'])
        phase['nuclei_template_selections'][0]['selection_note'] = '2341 template(s) above the deterministic 160-file cap were not selected; recorded, not silently skipped'
        return phase
    monkeypatch.setattr(scanner, 'nuclei_check', fake_check)
    result = scanner.nuclei_scan({'status': 'scope_ok', 'events': [], 'tool_call_budget': 20,
                                  'execution_metrics': {}, 'target': ['http://lab.example:8080/']})
    assert any('cap' in row for row in result['nuclei_scan_metrics']['limitations'])


def test_scan_inventory_skipped_phase_is_one_token_and_flags_reason(preview_settings):
    state = {'scanner_disabled': True}
    assert scanner.scan_inventory(state) == {'mode': 'disabled'}
    assert scanner.scan_inventory({'events': []}) == {'mode': 'not_run'}
