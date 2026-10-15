"""Report only evidence-backed verification status and actual planner mode."""
from src.adaptix.workflow.events import log
from src.adaptix.agents.planner import budget_exhausted
from src.adaptix.security.scope import action_scope_units


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
    limited_templates = [row for row in state.get('nuclei_template_selections', []) if row.get('coverage') == 'observation_subset']
    objective_status = (state.get('reflection_assessment') or {}).get('goal_status', 'not_assessed')
    partial = objective_status in ('uncertain', 'blocked') or bool(limited_templates) or progress['untouched_target_units'] > 0 or stop in ('budget_exhausted', 'context_budget_exhausted', 'budget_insufficient_for_candidates', 'policy_rejections_exhausted', 'reflection_rejected')
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
