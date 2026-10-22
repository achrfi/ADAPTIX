"""Report only evidence-backed verification status and actual planner mode."""
from src.adaptix.workflow.events import log
from src.adaptix.agents.planner import budget_exhausted, budget_stop_reason
from src.adaptix.agents.decisions import is_timeout_error
from src.adaptix.security.scope import action_scope_units


PLANNING_FAILURE_DETAILS = {
    'planning_failure_no_decision': 'Model repeatedly returned no executable action while authorized alternatives remained',
    'planner_decision_invalid': 'Model decision failed schema validation; bounded repair produced no usable action',
    'no_feasible_action': 'Proposed actions were not executable; no feasible action could be selected',
}

# Cumulative-budget stop reasons carry their budget's name straight into the
# termination report; a generic "budget exhausted" naming hides which limit
# actually stopped the run (bench-auto-14 hit its iteration cap while tokens,
# tool calls and time all had headroom and was reported as generic exhaustion).
BUDGET_STOPS = {'token_budget_exhausted', 'time_budget_exhausted',
                'tool_call_budget_exhausted', 'iteration_budget_exhausted'}

# Stagnation-class stops: the run could not make meaningful planning progress.
# This is the accurate termination answer in unlimited mode, where no budget
# counter will fire first.
STAGNATION_STOPS = {'no_new_actions', 'policy_rejections_exhausted', 'reflection_rejected',
                    'no_feasible_action', 'planning_failure_no_decision',
                    'planner_decision_invalid', 'planning_stagnation'}


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
    # A stop produced while the run clock was already at zero means time was the
    # exhausted resource, whatever budget accounting produced the stop reason.
    time_ran_out = (remaining is not None and remaining <= 0
                    and stop in ('budget_insufficient_for_candidates', 'no_feasible_action'))
    run_time_exhausted = stop == 'time_budget_exhausted' or mode == 'stopped_deadline' or deadline_clamped or time_ran_out
    achieved = (state.get('reflection_assessment') or {}).get('goal_status') == 'achieved'
    if stop == 'time_budget_exhausted' or mode == 'stopped_deadline':
        cause, detail = 'run_time_exhaustion', 'Stopped before a provider call because the run deadline was too close'
    elif deadline_clamped:
        cause, detail = 'run_time_exhaustion', 'Provider call timed out after being clamped to the remaining run time'
    elif provider_timeout:
        cause, detail = 'provider_timeout', str(planner.get('last_error') or 'provider call timed out')
    elif stop == 'operator_cancelled':
        cause, detail = 'operator_cancelled', 'Operator signalled cancellation; the in-flight node finished and the run reported its partial evidence'
    elif stop in BUDGET_STOPS:
        cause, detail = stop, {'token_budget_exhausted': 'The cumulative model token budget was reached',
                               'time_budget_exhausted': 'The wall-clock run budget was reached',
                               'tool_call_budget_exhausted': 'The cumulative executed tool-call budget was reached',
                               'iteration_budget_exhausted': 'The planning-pass (iteration) budget was reached'}[stop]
    elif stop == 'context_budget_exhausted':
        cause, detail = 'context_window_exceeded', 'The compacted prompt no longer fits the model context window beside the smallest valid decision'
    elif stop in PLANNING_FAILURE_DETAILS:
        cause, detail = 'planning_stagnation', PLANNING_FAILURE_DETAILS[stop]
    elif mode == 'llm_error':
        cause, detail = 'provider_error', str(planner.get('last_error') or 'provider error')
    elif stop in ('budget_exhausted', 'budget_insufficient_for_candidates'):
        # Legacy generic name: report the currently reached limit explicitly.
        specific = budget_stop_reason(state) if stop == 'budget_exhausted' else None
        if specific:
            cause, detail = specific, 'Reported under its historical generic name; the actually reached limit is named here'
        elif time_ran_out:
            cause, detail = 'run_time_exhaustion', f'{stop} while the run time budget was already exhausted'
        else:
            cause, detail = 'budget_exhausted', str(stop)
    elif stop in ('policy_rejected', 'authorization_invalid', 'execution_not_authorized', 'tool_not_registered', 'human_approval_required'):
        cause, detail = 'policy', stop
    elif stop in (None, 'no_new_actions', 'reflection_rejected', 'policy_rejections_exhausted'):
        # No further useful work was proposed: completed objective or stagnant run.
        if achieved:
            cause, detail = 'objective_completed', str(stop or 'No further action was needed; the objective evidence is complete')
        else:
            cause, detail = 'planning_stagnation', str(stop or 'no further action proposed despite an incomplete objective')
    else:
        cause, detail = 'other', str(stop)
    return {'cause': cause, 'provider_timeout': provider_timeout, 'run_time_exhausted': bool(run_time_exhausted),
            'deadline_clamped_timeout': deadline_clamped,
            'run_time_remaining_seconds': remaining, 'run_time_budget_unlimited': budget_seconds is None,
            'time_budget_seconds': budget_seconds, 'time_budget_unlimited': budget_seconds is None,
            'elapsed_seconds': elapsed, 'mode': mode, 'stop_reason': stop, 'detail': detail}


def _budget_summary(state, planner):
    """Configured cumulative budgets beside their actual consumption.

    Unlimited appears as ``'unlimited'`` with the consumption still metered, so a
    report never hints at a budget number that was never configured.
    """
    from src.adaptix.workflow.budget import budget_limit, DEFAULT_TOKEN_BUDGET, DEFAULT_TOOL_CALL_BUDGET, DEFAULT_MAX_ITERATIONS
    token_limit = budget_limit(state, 'token_budget', DEFAULT_TOKEN_BUDGET)
    tool_limit = budget_limit(state, 'tool_call_budget', DEFAULT_TOOL_CALL_BUDGET)
    iteration_limit = budget_limit(state, 'max_iterations', DEFAULT_MAX_ITERATIONS)
    time_limit = budget_limit(state, 'time_budget_seconds', 1800)
    tokens = int(planner.get('tokens_used', 0) or 0)
    calls = int((state.get('execution_metrics') or {}).get('tool_calls_used', 0) or 0)
    iterations = int(state.get('iterations', 0) or 0)
    elapsed = None
    if state.get('run_started_at') is not None:
        import time
        elapsed = round(time.time() - float(state['run_started_at']), 2)
    return {
        'token_budget': {'configured': 'unlimited' if token_limit is None else token_limit,
                         'used': tokens, 'remaining': None if token_limit is None else max(0, token_limit - tokens)},
        'time_budget_seconds': {'configured': 'unlimited' if time_limit is None else time_limit,
                                'used_seconds': elapsed,
                                'remaining_seconds': (None if time_limit is None or elapsed is None
                                                      else max(0.0, float(time_limit) - elapsed))},
        'tool_call_budget': {'configured': 'unlimited' if tool_limit is None else tool_limit,
                             'used': calls, 'remaining': None if tool_limit is None else max(0, tool_limit - calls)},
        'max_iterations': {'configured': 'unlimited' if iteration_limit is None else iteration_limit,
                           'used': iterations, 'remaining': None if iteration_limit is None else max(0, iteration_limit - iterations)},
        'meaning': 'Consumption is metered whether or not a limit is configured; remaining is null for unlimited budgets',
    }


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
    stop = state.get('stop_reason') or budget_stop_reason(state) or None
    termination = _termination(state, stop)
    # Phase-level attribution: sum of recorded node runtimes vs the whole run clock.
    # The residual is wall time no recorded phase explains (e.g. a provider outage's
    # connection lag or a process-level suspension); it is named rather than hidden.
    phases = list(state.get('phase_runtime') or [])
    recorded_seconds = round(sum(float(row.get('seconds', 0)) for row in phases), 3)
    if termination.get('elapsed_seconds') is not None:
        outside = round(max(0.0, float(termination['elapsed_seconds']) - recorded_seconds), 3)
    else:
        outside = None
    metrics = dict(state.get('metrics', {}) or {})
    metrics['phase_runtime'] = phases
    metrics['recorded_phase_seconds'] = recorded_seconds
    metrics['outside_recorded_phases_seconds'] = outside
    counts: dict[str, int] = {}
    for row in state.get('action_outcomes', []):
        tool = str((row.get('action') or row).get('tool') or '?')
        counts[tool] = counts.get(tool, 0) + 1
    metrics['executions_by_tool'] = dict(sorted(counts.items()))
    # Deterministic-baseline vs model-driven adaptive split. Recorded, never
    # derived from assumptions: a disabled or skipped baseline reports it did not run.
    baseline = state.get('baseline_metrics') or {}
    marker = state.get('baseline_recon') or {}
    baseline_seconds = round(float(baseline.get('seconds', 0) or 0), 3)
    metrics['baseline_reconnaissance'] = {
        'enabled': marker.get('mode') not in (None, 'disabled', 'not_run'),
        'mode': marker.get('mode') or 'not_run', 'completed': bool(marker.get('completed')),
        'seconds': baseline_seconds, 'tool_calls': int(baseline.get('tool_calls', 0) or 0),
        'tools_by_tool': baseline.get('tools_by_tool', {}), 'steps': baseline.get('steps', []),
        'skipped': baseline.get('skipped', []), 'limitations': baseline.get('limitations', []),
        'stop_reason': baseline.get('stop_reason'),
        'web_routes': int(baseline.get('web_routes', 0) or 0),
        'documents_probed': int(baseline.get('documents_probed', 0) or 0)}
    elapsed_total = termination.get('elapsed_seconds')
    metrics['adaptive_seconds'] = (round(max(0.0, float(elapsed_total) - baseline_seconds), 3)
                                   if elapsed_total is not None else None)
    # Automatic Nuclei phase metrics, recorded separately from adaptive actions.
    scan = state.get('nuclei_scan_metrics') or {}
    scan_marker = state.get('nuclei_scan') or {}
    metrics['nuclei_scan_phase'] = {
        'enabled': bool(scan_marker.get('completed')) or scan.get('mode') in ('complete', 'limited'),
        'mode': scan.get('mode') or 'not_run', 'completed': bool(scan_marker.get('completed')),
        'engine_version': scan.get('engine_version'),
        'seconds': float(scan.get('seconds', 0) or 0), 'tool_calls': int(scan.get('tool_calls', 0) or 0),
        'origins_scanned': int(scan.get('origin_count', 0) or 0),
        'templates_attempted': int(scan.get('templates_attempted', 0) or 0),
        'templates_executable': int(scan.get('templates_executable', 0) or 0),
        'templates_gated': int(scan.get('templates_gated', 0) or 0),
        'planned_request_ceiling': int(scan.get('planned_request_ceiling', 0) or 0),
        'scanner_candidates': len([row for row in state.get('candidates', [])
                                   if isinstance(row, dict)]),
        'limitations': scan.get('limitations', []), 'skipped': scan.get('skipped', []),
        'stop_reason': scan.get('stop_reason')}
    # LLM waste accounting: truncated calls are classified in the token ledger.
    ledger_rows = [row for row in state.get('token_ledger', []) if isinstance(row, dict)]
    providers = [row for row in ledger_rows if row.get('provider_call')]
    truncated = [row for row in providers
                 if (row.get('finish_reason') == 'length' or row.get('envelope') == 'too_large')
                 and row.get('result') != 'valid_decision']
    metrics['llm_truncated_calls'] = len(truncated)
    metrics['llm_truncated_wasted_tokens'] = sum(int(row.get('tokens_charged', 0) or 0) for row in truncated)
    hypothesis_rows = [row for row in state.get('hypotheses', []) if isinstance(row, dict)]
    metrics['hypotheses'] = {
        'created': len(hypothesis_rows),
        'candidate': sum(1 for row in hypothesis_rows if row.get('status') == 'candidate'),
        'inconclusive': sum(1 for row in hypothesis_rows if row.get('status') == 'inconclusive'),
        'refuted': sum(1 for row in hypothesis_rows if row.get('status') == 'refuted'),
        'supported': sum(1 for row in hypothesis_rows if row.get('status') == 'supported')}
    # Vulnerability-discovery productivity measured on recorded data only. A zero
    # stays a zero: none of these ratios invent a result. Nuclei scanner-verified
    # rows and independently verified rows are counted separately: a template
    # match match is the engine's own verdict, not a result this run produced
    # through its own testing, so the research-success numbers below count the
    # verified-by-this-run rows only.
    tokens = int(planner.get('tokens_used', 0) or 0)
    verified = state.get('verified_findings', [])
    scanner_verified = [row for row in verified if isinstance(row, dict)
                        and row.get('verification_level') == 'scanner_verified']
    independently_verified = [row for row in verified if isinstance(row, dict)
                              and row.get('verification_level') != 'scanner_verified']
    rejected_rows = state.get('rejected_findings', [])
    metrics['verification_rates'] = {
        'verified_findings_per_10k_llm_tokens': (round(len(independently_verified) * 10000 / tokens, 3) if tokens else None),
        'verified_findings_per_execution_hour': (
            round(len(independently_verified) / float(termination.get('elapsed_seconds') or 0), 6)
            if float(termination.get('elapsed_seconds') or 0) > 0 else None),
        'false_positive_rate': (round(len(rejected_rows) / max(1, len(rejected_rows) + len(independently_verified)), 3)
                                if rejected_rows else None),
        'hypothesis_to_verified_conversion': (round(len(independently_verified) / len(hypothesis_rows), 3) if hypothesis_rows else None),
        'scanner_request_ceiling': int((scan.get('planned_request_ceiling', 0) or 0)
                                       + sum(int((row.get('request_ceiling_per_target') or 0))
                                             for row in state.get('nuclei_template_selections', [])
                                             if isinstance(row, dict))),
        'truncated_llm_calls': metrics['llm_truncated_calls']}
    # Research comparison aggregation (configuration A vs B). Every value is derived
    # from recorded data of this run; nothing here compares absent runs.
    configuration = ('hybrid_nuclei' if metrics['nuclei_scan_phase']['completed']
                     else 'hybrid_baseline' if metrics['baseline_reconnaissance']['enabled']
                     else 'adaptive_only')
    metrics['research_comparison'] = {
        'configuration': configuration,
        'total_llm_tokens': int(planner.get('tokens_used', 0) or 0),
        'llm_calls': int(planner.get('llm_calls', 0) or 0),
        'planning_passes': sum(1 for row in state.get('planning_history', []) if isinstance(row, dict)),
        'executed_actions': len(state.get('action_outcomes', [])),
        'discovery_coverage': {'services': len(state.get('services', [])),
                               'web_routes': len(state.get('web_routes', [])),
                               'api_operations': len(state.get('api_operations', [])),
                               'documents_probed': metrics['baseline_reconnaissance']['documents_probed']},
        'baseline_seconds': baseline_seconds, 'adaptive_seconds': metrics['adaptive_seconds'],
        # Research success counts only what this run verified through its own
        # deterministic testing; the engine-vouched scanner rows are reported
        # alongside, never inside this number.
        'verified_findings': len(independently_verified),
        'scanner_verified_findings': len(scanner_verified),
        'independently_verified_findings': len(independently_verified),
        'inconclusive_findings': len(state.get('inconclusive_findings', [])),
        'rejected_findings': len(state.get('rejected_findings', []))}
    metrics['finding_classes'] = {
        'nuclei_scanner_verified': len(scanner_verified),
        'independently_verified': len(independently_verified),
        'unverified_candidates': len(state.get('inconclusive_findings', []))}
    limited_templates = [row for row in state.get('nuclei_template_selections', []) if row.get('coverage') == 'observation_subset']
    objective_status = (state.get('reflection_assessment') or {}).get('goal_status', 'not_assessed')
    partial = objective_status in ('uncertain', 'blocked') or bool(limited_templates) or progress['untouched_target_units'] > 0 or stop in ('budget_exhausted', 'time_budget_exhausted', 'token_budget_exhausted', 'tool_call_budget_exhausted', 'iteration_budget_exhausted', 'context_budget_exhausted', 'budget_insufficient_for_candidates', 'policy_rejections_exhausted', 'reflection_rejected', 'planning_stagnation', *PLANNING_FAILURE_DETAILS)
    planning_rows = [row for row in state.get('planning_history', []) if isinstance(row, dict)]
    planning_diagnostics = {
        'planning_passes': len(planning_rows),
        'zero_action_passes': sum(1 for row in planning_rows if not row.get('selected')),
        'consecutive_empty_plans': int(state.get('consecutive_empty_plans', 0) or 0),
        'consecutive_schema_failures': int(state.get('consecutive_schema_failures', 0) or 0),
        'stop_reason': stop,
        'meaning': 'Planning diagnostics describe decision quality; zero-action passes are not completed assessment coverage',
    }
    report = {'status': 'completed_with_errors' if state.get('errors') or state.get('stop_reason') in ('planner_unavailable', 'policy_rejected', 'authorization_invalid', 'execution_not_authorized', 'tool_not_registered', *PLANNING_FAILURE_DETAILS) else 'completed_partial' if partial else 'scan_completed',
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
              'planning_diagnostics': planning_diagnostics,
              'tool_profiles': state.get('tool_profiles', {}),
              'action_outcomes': state.get('action_outcomes', []), 'iterations': state.get('iterations', 0),
              'services': state.get('services', []), 'planned_actions': state.get('attempted_actions', []),
              'http_services': state.get('http_services', []), 'candidates': state.get('candidates', []),
              'nuclei_template_selections': state.get('nuclei_template_selections', []),
              'limitations': [{'target': row['target'], 'reason': 'Unapproved active templates were excluded',
                               'manifest_ref': row.get('manifest_ref'), 'approval_required_count': row.get('approval_required_count')}
                              for row in limited_templates],
              'verified_findings': state.get('verified_findings', []),
              'nuclei_verified_findings': scanner_verified,
              'independently_verified_findings': independently_verified,
              'unverified_candidate_findings': state.get('inconclusive_findings', []),
              'nuclei_observations': state.get('nuclei_observations', []),
              'rejected_findings': state.get('rejected_findings', []),
              'inconclusive_findings': state.get('inconclusive_findings', []),
              'findings': state.get('findings', []),
              'hypotheses': state.get('hypotheses', []),
              'web_routes': state.get('web_routes', []),
              'probe_traces': state.get('probe_traces', []),
              'request_audit': state.get('request_audit', []),
              'termination': termination,
              'budget_status': _budget_summary(state, planner),
              'stop_reason': stop,
              'idor_findings': state.get('idor_findings', []),
              'api_operations': state.get('api_operations', []), 'api_observations': state.get('api_observations', []),
              'scenario_candidates': state.get('scenario_candidates', []),
              'scenario_validations': state.get('scenario_validations', []),
              'rejected_actions': state.get('rejected_actions', []), 'discovery_limitations': state.get('discovery_limitations', []),
              'browser_evidence': state.get('browser_evidence', []),
              'metrics': metrics, 'errors': state.get('errors', [])}
    if stop == 'human_approval_required':
        report['status'] = 'awaiting_human_approval'
    from src.adaptix.evidence.sanitize import sanitize, scenario_secrets
    report = sanitize(report, scenario_secrets(state))
    from src.adaptix.evidence.audit import export_bundle
    events = log(state, f'Final Report: {report["status"]}')
    markdown = markdown_report(report)
    # The markdown artifact needs a run identity; diagnostic report states without
    # one are still rendered, just not persisted to the artifacts directory.
    if state.get('run_id'):
        try:
            from src.adaptix.evidence.storage import artifact_path, save_text
            save_text(artifact_path(state, 'report', 'summary', 'md'), markdown)
        except (OSError, KeyError):
            events = list(events) + ['Markdown report could not be written to the artifacts directory']
    try:
        bundle = export_bundle(state, report, events)
    except OSError:
        bundle = {}
        report['status'] = 'completed_with_errors'
        report['errors'] = list(report['errors']) + ['Audit storage unavailable; no complete evidence bundle']
    return {'status': report['status'], 'report': report, 'artifact_bundle': bundle,
            'markdown_report': markdown, 'events': events}


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
    return {'report': report, 'events': events, 'artifact_bundle': bundle,
            'markdown_report': markdown_report(report)}


def markdown_report(report):
    """Markdown rendering of the final report, split by verification provenance.

    Three sections on purpose: the scanner rows Nuclei vouched for with its own
    template matchers, the rows this run's deterministic evidence confirmed, and
    the candidates that never left the unverified bucket.
    """
    scanner_rows = report.get('nuclei_verified_findings') or [row for row in report.get('verified_findings', [])
                                                              if isinstance(row, dict)
                                                              and row.get('verification_level') == 'scanner_verified']
    independent_rows = report.get('independently_verified_findings') or [row for row in report.get('verified_findings', [])
                                                                        if isinstance(row, dict)
                                                                        and row.get('verification_level') != 'scanner_verified']
    candidates = report.get('unverified_candidate_findings') or report.get('inconclusive_findings', [])
    lines = [f"# ADAPTIX assessment report ({report.get('status')})",
             '',
             f"- target: `{report.get('target')}`",
             f"- stop reason: `{report.get('stop_reason')}`",
             f"- configuration: `{(report.get('metrics', {}).get('research_comparison') or {}).get('configuration')}`",
             '']
    lines.append(f"## Nuclei scanner-verified findings ({len(scanner_rows)})")
    lines.append('')
    if not scanner_rows:
        lines.append('_None recorded._')
    for row in scanner_rows:
        lines.append(f"- **{row.get('finding_id')}** {row.get('vulnerability_name')} — severity "
                     f"`{row.get('severity')}` — template `{row.get('template_id')}` — matched "
                     f"`{row.get('matched_location')}` (matcher: `{row.get('matcher_name')}`)")
        lines.append(f"  - verification: `{row.get('verification_method')}` / `{row.get('verification_level')}`, "
                     f"independently_verified: {str(row.get('independently_verified')).lower()}; "
                     f"evidence: `{row.get('verification_evidence', {}).get('evidence_ref')}`")
    lines.append('')
    lines.append(f"## Independently verified findings ({len(independent_rows)})")
    lines.append('')
    if not independent_rows:
        lines.append('_None recorded._')
    for row in independent_rows:
        evidence = row.get('verification_evidence') or {}
        lines.append(f"- **{row.get('evidence_id')}** {row.get('finding_type')} — severity "
                     f"`{row.get('severity')}` — target `{row.get('target')}` (tool: `{row.get('source_tool')}`)")
        lines.append(f"  - verification: `{(evidence or {}).get('verification_method', 'recorded proof')}` "
                     f"/ `{row.get('verification_level', 'independently_verified')}`, "
                     f"independently_verified: true; evidence: `{row.get('evidence_ref') or (evidence or {}).get('evidence_ref')}`")
    lines.append('')
    lines.append(f"## Unverified candidate findings ({len(candidates)})")
    lines.append('')
    if not candidates:
        lines.append('_None recorded._')
    for row in candidates[:40]:
        lines.append(f"- {row.get('finding_type')} — target `{row.get('target')}` — "
                     f"status `{row.get('verification_status', 'inconclusive')}` — {row.get('reason')}")
    lines.append('')
    observations = report.get('nuclei_observations', [])
    lines.append(f"## Informational Nuclei observations ({len(observations)})")
    lines.append('')
    for row in observations[:40]:
        lines.append(f"- `{row.get('template_id')}` — matched `{row.get('matched_location')}` — "
                     f"severity `{row.get('severity')}`")
    lines.append('')
    return '\n'.join(lines)
