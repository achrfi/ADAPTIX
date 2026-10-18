"""Report only evidence-backed verification status and actual planner mode."""
from src.adaptix.workflow.events import log
from src.adaptix.agents.planner import budget_exhausted
from src.adaptix.agents.decisions import is_timeout_error
from src.adaptix.security.scope import action_scope_units


def _termination(state, stop):
    """Distinguish a provider timeout from the run's own time budget being exhausted.

    ``planner_mode`` alone cannot tell these apart: a clamped provider call that
    times out at the end of the run is recorded as a planner error even though the
    run simply ran out of wall-clock time.
    """
    planner = state.get('planner_metrics', {})
    mode = planner.get('mode')
    budget_seconds = state.get('time_budget_seconds')
    elapsed = None
    if state.get('run_started_at') is not None:
        import time
        elapsed = round(time.time() - float(state['run_started_at']), 2)
    remaining = None
    if budget_seconds is not None and elapsed is not None:
        remaining = round(max(0.0, float(budget_seconds) - elapsed), 2)
    from src.adaptix.agents.decisions import is_timeout_error
    timeout_errors = [row for row in state.get('token_ledger', []) if is_timeout_error(row.get('error_type'))]
    provider_timeout = bool(timeout_errors) or is_timeout_error(planner.get('last_error'))
    clamped = [row for row in timeout_errors if row.get('deadline_clamped')]
    deadline_clamped = bool(clamped) or bool(provider_timeout and remaining is not None and remaining < 75)
    run_time_exhausted = stop == 'time_budget_exhausted' or mode == 'stopped_deadline' or deadline_clamped
    if stop == 'time_budget_exhausted' or mode == 'stopped_deadline':
        cause, detail = 'run_time_exhaustion', 'Stopped before a provider call because the run deadline was too close'
    elif deadline_clamped:
        cause, detail = 'run_time_exhaustion', 'Provider call timed out after being clamped to the remaining run time'
    elif provider_timeout:
        cause, detail = 'provider_timeout', str(planner.get('last_error') or 'provider call timed out')
    elif mode == 'llm_error':
        cause, detail = 'provider_error', str(planner.get('last_error') or 'provider error')
    elif stop in ('budget_exhausted', 'context_budget_exhausted', 'budget_insufficient_for_candidates'):
        cause, detail = 'budget_exhausted', str(stop)
    elif stop in ('policy_rejected', 'authorization_invalid', 'execution_not_authorized', 'tool_not_registered', 'human_approval_required'):
        cause, detail = 'policy', stop
    elif stop in (None, 'no_new_actions', 'reflection_rejected', 'policy_rejections_exhausted'):
        cause, detail = 'objective', str(stop or 'no further action proposed')
    else:
        cause, detail = 'other', str(stop)
    return {'cause': cause, 'provider_timeout': provider_timeout, 'run_time_exhausted': bool(run_time_exhausted),
            'deadline_clamped_timeout': deadline_clamped,
            'run_time_remaining_seconds': remaining, 'time_budget_seconds': budget_seconds,
            'elapsed_seconds': elapsed, 'mode': mode, 'stop_reason': stop, 'detail': detail}


def final_report(state):
    from src.adaptix.agents.reflector import collect_findings
    state = {**state, **collect_findings(state)}
    planner = state.get('planner_metrics', {})
    manifest = state.get('scope_manifest', {})
    touched = set(state.get('scope_touched', []))
    if manifest:
        for action in state.get('attempted_actions', []):
            touched.update(action_scope_units(action, state, manifest))
    deferred = set(state.get('scope_deferred', [])) - touched
    total = int(manifest.get('total_units', len(state.get('hosts', []))))
    progress = {'total_target_units': total, 'touched_target_units': len(touched),
                'deferred_target_units': len(deferred), 'untouched_target_units': max(0, total - len(touched)),
                'unprocessed_target_units': max(0, total - len(touched | deferred)),
                'touched': sorted(touched), 'deferred': sorted(deferred),
                'meaning': 'Touched means an action was attempted, not complete vulnerability coverage'}
    stop = state.get('stop_reason') or ('budget_exhausted' if budget_exhausted(state) else None)
    termination = _termination(state, stop)
    limited_templates = [row for row in state.get('nuclei_template_selections', []) if row.get('coverage') == 'observation_subset']
    objective_status = (state.get('reflection_assessment') or {}).get('goal_status', 'not_assessed')
    partial = objective_status in ('uncertain', 'blocked') or bool(limited_templates) or progress['untouched_target_units'] > 0 or stop in ('budget_exhausted', 'time_budget_exhausted', 'context_budget_exhausted', 'budget_insufficient_for_candidates', 'policy_rejections_exhausted', 'reflection_rejected')
    report = {'status': 'completed_with_errors' if state.get('errors') or state.get('stop_reason') in ('planner_unavailable', 'policy_rejected', 'authorization_invalid', 'execution_not_authorized', 'tool_not_registered') else 'completed_partial' if partial else 'scan_completed',
              'mode': planner.get('mode', 'not_started'),
              'recon_inventory': state.get('recon_inventory', []),
              'token_ledger': state.get('token_ledger', []),
              'approval_audit': state.get('approval_audit', []),
              'lab_manifest': state.get('lab_manifest', {}),
              'user_prompt': state.get('user_prompt', ''),
              'self_reflection': planner.get('self_reflection', ''),
              'reflection_assessment': state.get('reflection_assessment'),
              'objective_status': objective_status,
              'reflection_history': state.get('reflection_history', []),
              'target': state.get('target'), 'authorization': state.get('authorization', {}),
              'hosts': state.get('hosts', []), 'scope_aliases': state.get('scope_aliases', {}),
              'scope_ports': state.get('scope_ports', []),
              'scope_manifest': manifest, 'scope_progress': progress,
              'planning_history': state.get('planning_history', []),
              'tool_profiles': state.get('tool_profiles', {}),
              'action_outcomes': state.get('action_outcomes', []), 'iterations': state.get('iterations', 0),
              'services': state.get('services', []), 'planned_actions': state.get('attempted_actions', []),
              'http_services': state.get('http_services', []), 'candidates': state.get('candidates', []),
              'nuclei_template_selections': state.get('nuclei_template_selections', []),
              'limitations': [{'target': row['target'], 'reason': 'Unapproved active templates were excluded',
                               'manifest_ref': row.get('manifest_ref'), 'approval_required_count': row.get('approval_required_count')}
                              for row in limited_templates],
              'verified_findings': state.get('verified_findings', []),
              'rejected_findings': state.get('rejected_findings', []),
              'inconclusive_findings': state.get('inconclusive_findings', []),
              'findings': state.get('findings', []),
              'hypotheses': state.get('hypotheses', []),
              'web_routes': state.get('web_routes', []),
              'probe_traces': state.get('probe_traces', []),
              'request_audit': state.get('request_audit', []),
              'termination': termination,
              'stop_reason': stop,
              'idor_findings': state.get('idor_findings', []),
              'api_operations': state.get('api_operations', []), 'api_observations': state.get('api_observations', []),
              'scenario_candidates': state.get('scenario_candidates', []),
              'scenario_validations': state.get('scenario_validations', []),
              'rejected_actions': state.get('rejected_actions', []), 'discovery_limitations': state.get('discovery_limitations', []),
              'browser_evidence': state.get('browser_evidence', []),
              'metrics': state.get('metrics', {}), 'errors': state.get('errors', [])}
    if stop == 'human_approval_required':
        report['status'] = 'awaiting_human_approval'
    from src.adaptix.evidence.sanitize import sanitize, scenario_secrets
    report = sanitize(report, scenario_secrets(state))
    from src.adaptix.evidence.audit import export_bundle
    events = log(state, f'Final Report: {report["status"]}')
    try:
        bundle = export_bundle(state, report, events)
    except OSError:
        bundle = {}
        report['status'] = 'completed_with_errors'
        report['errors'] = list(report['errors']) + ['Audit storage unavailable; no complete evidence bundle']
    return {'status': report['status'], 'report': report, 'artifact_bundle': bundle, 'events': events}


def blocked_report(state):
    report = {'status': 'scope_blocked', 'target': state.get('target'), 'hosts': [],
              'verified_findings': [], 'errors': state.get('errors', []), 'metrics': {'llm_calls': 0}}
    from src.adaptix.evidence.audit import export_bundle
    events = log(state, 'Final Report: scope_blocked')
    try:
        bundle = export_bundle(state, report, events)
    except OSError:
        bundle = {}
        report['errors'] = list(report['errors']) + ['Audit storage unavailable']
    return {'report': report, 'events': events, 'artifact_bundle': bundle}
