"""ADAPTIX unified module. Migrated from tested running code."""
import secrets
import ipaddress
import time
from src.adaptix.config import config
from src.adaptix.security.scope import resolve_scope, normalize_requests, scope_ports, scope_is_loopback, scope_window, scope_contains_ip, is_scope_unit, action_scope_units, unit_host
from src.adaptix.security.authorization import verify_scope_grant
from src.adaptix.workflow.events import log
from src.adaptix.tools.nmap import reconnaissance
from src.adaptix.tools.httpx import httpx_probe
from src.adaptix.tools.nuclei import nuclei_check
from src.adaptix.tools.playwright import browser_observe
from src.adaptix.tools.idor import idor_test
from src.adaptix.agents.planner import adaptive_planning
from src.adaptix.agents.reflector import reflection_verification
from src.adaptix.processing.observations import observation_processing
from src.adaptix.reporting.report import final_report, blocked_report


def scope_guard(state):
    policy = config('scope.yaml')
    run_id = state.get('run_id') or secrets.token_hex(6)
    try:
        requested = normalize_requests(state.get('target', []))
        if state.get('grant'):
            manifest, grant_id = verify_scope_grant(state['grant'], state['target'], state.get('principal'), policy)
            authorization = {'type': 'signed_grant', 'grant_id': grant_id}
        else:
            manifest = resolve_scope(state['target'], policy)
            if not policy.get('allow_loopback_without_grant', False) or not scope_is_loopback(manifest):
                raise ValueError('Target non-loopback membutuhkan signed grant (--grant).')
            authorization = {'type': 'local_loopback'}
        # A context window scales with run budget, never with a fixed target cap.
        from src.adaptix.workflow.budget import budget_limit, DEFAULT_TOOL_CALL_BUDGET, DEFAULT_MAX_ITERATIONS, DEFAULT_TOKEN_BUDGET
        def _room(key, default):
            limit = budget_limit(state, key, default)
            return None if limit is None else max(1, limit)
        model_context = int(state.get('model_context_tokens', 4096))
        token_room = _room('token_budget', DEFAULT_TOKEN_BUDGET)
        token_floor = max(1, min(token_room, model_context) // 128) if token_room is not None else model_context // 128
        rooms = [room for room in (_room('tool_call_budget', DEFAULT_TOOL_CALL_BUDGET),
                                   _room('max_iterations', DEFAULT_MAX_ITERATIONS), token_floor) if room]
        count = max(1, min(rooms))
        window = scope_window(manifest, [], count)
        hosts = list(manifest['hosts']) + [unit_host(u) for u in window if scope_contains_ip(unit_host(u), manifest)]
        update = {'scope_manifest': manifest, 'scope_networks': manifest['networks'],
                'scope_aliases': manifest['aliases'], 'scope_ports': scope_ports(state['target'], policy),
                'scope_touched': [], 'scope_deferred': [], 'run_started_at': time.time(),
                'run_id': run_id, 'status': 'scope_ok', 'hosts': list(dict.fromkeys(hosts)),
                'authorization': authorization,
                'static_profiles': [], 'static_swept': [],
                'recon_wordlist': state.get('recon_wordlist'),
                'events': log(state, f'Scope Guard: approved compact scope, {manifest["total_units"]} target units')}
        from src.adaptix.processing.ffuf import import_ffuf_documents, is_operator_review
        if is_operator_review(state):
            update.update(operator_recon_review_only=True, baseline_disabled=True, scanner_disabled=True)
        return {**update, **import_ffuf_documents({**state, **update})}
    except (ValueError, TypeError, KeyError) as exc:
        return {'run_id': run_id, 'status': 'scope_blocked', 'hosts': [], 'scope_aliases': {},
                'scope_ports': [], 'scope_networks': [], 'errors': [str(exc)],
                'events': log(state, f'Scope Guard: BLOCKED - {exc}')}


def state_update(state):
    from src.adaptix.evidence.audit import checkpoint
    update = {'iterations': int(state.get('iterations', 0)) + 1, 'events': log(state, 'State Update: workflow pass recorded')}
    try:
        path = checkpoint({**state, **update})
        if path:
            update['checkpoint_ref'] = path
        else:
            update['events'] = list(update['events']) + ['Checkpoint: skipped; existing artifacts for this '
                                                        'run directory belong to a different session'
                                                        ' (diagnostic replays need a fresh run ID)']
    except OSError:
        update['stop_reason'] = 'evidence_storage_unavailable'
        update['errors'] = list(state.get('errors', [])) + ['Checkpoint storage unavailable; execution stopped']
    return update


def advance_action(state):
    cursor = int(state.get('action_cursor', 0))
    actions = state.get('planned_actions', [])
    attempted = list(state.get('attempted_actions', []))
    if cursor < len(actions):
        attempted.append(actions[cursor])
    return {'action_cursor': cursor + 1, 'attempted_actions': attempted,
            'events': log(state, f'Action completed: {cursor + 1}/{len(actions)}')}


def execute_action(state):
    """Revalidate at execution boundary, dispatch one registered capability."""
    from src.adaptix.processing.ffuf import is_operator_review
    if is_operator_review(state):
        return {'stop_reason': 'operator_recon_review_only', 'planned_actions': []}
    from src.adaptix.agents.planner import _approved_actions, budget_stop_reason
    from src.adaptix.tools.registry import tool_registry, tool_handlers
    stop = budget_stop_reason(state)
    if stop:
        return {'stop_reason': stop}
    if state.get('status') != 'scope_ok' or not state.get('authorization'):
        return {'stop_reason': 'execution_not_authorized'}
    try:
        policy = config('scope.yaml')
        if state.get('grant'):
            manifest, _ = verify_scope_grant(state['grant'], state['target'], state.get('principal'), policy)
        else:
            manifest = resolve_scope(state['target'], policy)
            if not policy.get('allow_loopback_without_grant', False) or not scope_is_loopback(manifest):
                raise ValueError('Unsigned external scope')
        if manifest != state.get('scope_manifest', manifest):
            raise ValueError('Pinned scope changed')
    except (ValueError, KeyError):
        return {'stop_reason': 'authorization_invalid'}
    state = {**state, 'scope_manifest': manifest, 'scope_networks': manifest['networks'],
             'scope_aliases': manifest['aliases'], 'scope_ports': scope_ports(state['target'], policy),
             'hosts': list(dict.fromkeys(manifest['hosts'] + [ip for ip in state.get('hosts', []) if scope_contains_ip(ip, manifest)]))}
    registry = tool_registry()
    available = {n for n, s in registry.items() if s.get('enabled') and s.get('path')}
    actions = _approved_actions(state, state.get('planned_actions', []), available)
    if len(actions) != 1:
        return {'stop_reason': 'policy_rejected'}
    from src.adaptix.agents.priority import rank_actions
    from src.adaptix.agents.planner import _budget
    if actions[0].get('priority') is not None:
        feasible, deferred = rank_actions(state, actions, _budget(state, state.get('planner_metrics', {})))
        if not feasible:
            from src.adaptix.workflow.budget import remaining_seconds
            from src.adaptix.agents.planner import MIN_PROVIDER_SECONDS
            reason = ('time_budget_exhausted' if remaining_seconds(state) < MIN_PROVIDER_SECONDS
                      else 'budget_insufficient_for_candidates')
            why = '; '.join(str(d.get('reason', ''))[:120] for d in deferred) or 'no reason recorded'
            return {'stop_reason': reason,
                    'errors': list(state.get('errors', [])) + ['Planned action refused: ' + why]}
    action = actions[0]
    from src.adaptix.agents.action_identity import execution_identity
    action = {**action, 'execution_identity': execution_identity(action, state)}
    actions = [action]
    from src.adaptix.security.action_policy import approval_for
    specification = registry[action['tool']]
    if action['tool'] == 'nuclei':
        from src.adaptix.security.nuclei_policy import prepare_scan
        try:
            scan_manifest = prepare_scan(state, action['target'], config('scope.yaml')['limits'])
        except (OSError, ValueError) as exc:
            return {'errors': list(state.get('errors', [])) + ['Nuclei policy preflight: ' + str(exc)[:180]],
                    'attempted_actions': list(state.get('attempted_actions', [])) + [action],
                    'policy_feedback': [{'kind': 'capability', 'code': 'template_manifest_unavailable',
                                         'reason': 'Template manifest unavailable; choose another useful tool or report the limitation'}],
                    'events': log(state, 'Nuclei: preflight failed before any network request')}
        active_execution = scan_manifest['approval_required_count'] and (scan_manifest['approval']['result'] == 'allowed' or not scan_manifest['executable_count'])
        specification = {'risk': 'state_change' if active_execution else 'observe',
                         'manifest_sha256': scan_manifest['manifest_sha256']}
        action['manifest_sha256'] = scan_manifest['manifest_sha256']
        # The manifest is now a fact: its request ceiling gives the engine's fastest
        # possible finish at the configured rate. A scan whose honest floor exceeds
        # the remaining run time is deferred, not executed past the deadline - the
        # execution that consumed a whole short run before input testing deserves
        # the same working estimate at ranking and execution time.
        from src.adaptix.workflow.budget import remaining_seconds as _remaining_seconds
        from src.adaptix.config import config as _config
        limits = _config('scope.yaml')['limits']
        from src.adaptix.agents.priority import nuclei_seconds_floor
        manifest_wall = (
            scan_manifest['request_ceiling_per_target'] / max(1, int(limits['rate_per_second']))
            + int(limits.get('concurrent_requests', 10)) * 5 + 25
            if scan_manifest['request_ceiling_per_target'] else nuclei_seconds_floor(state))
        left = _remaining_seconds(state)
        if manifest_wall and left > 0 and manifest_wall > left:
            summary = {key: value for key, value in scan_manifest.items() if key not in ('_chosen', 'templates')}
            summary['execution_status'] = 'deferred_time_budget'
            return {'nuclei_template_selections': list(state.get('nuclei_template_selections', [])) + [summary],
                    'policy_feedback': [{'kind': 'budget', 'code': 'manifest_would_not_fit_deadline',
                                         'action': action,
                                         'reason': f'The approved manifest of {scan_manifest["executable_count"]} executable '
                                                   f'templates needs about {int(manifest_wall)} seconds at the configured rate '
                                                   f'but about {int(left)} seconds remain. Propose a scan with a smaller '
                                                   'template set or use request-level checks instead.'}],
                    'approval_audit': list(state.get('approval_audit', [])) + [{
                        'action': action, 'result': 'deferred',
                        'reason': 'manifest would exceed the remaining run time'}],
                    'events': log(state, 'Nuclei: deferred before execution; manifest floor exceeds the remaining run time')}
    else:
        # Risk comes from what the request would actually do, not from its verb.
        from src.adaptix.security.guard import action_effect
        specification = {**specification, **action_effect({**state, 'tool_catalog': registry}, action)}
    approval = approval_for(state, action, specification)
    if action['tool'] == 'nuclei':
        approval['manifest_ref'] = scan_manifest['manifest_ref']
    approval_audit = list(state.get('approval_audit', [])) + [{'action': action, **approval}]
    if approval['result'] != 'allowed':
        pending = {}
        if action['tool'] == 'nuclei':
            summary = {key: value for key, value in scan_manifest.items() if key not in ('_chosen', 'templates')}
            summary['execution_status'] = 'approval_required'
            pending['nuclei_template_selections'] = list(state.get('nuclei_template_selections', [])) + [summary]
        return {**pending, 'stop_reason': 'human_approval_required', 'approval_audit': approval_audit,
                'events': log(state, 'Policy: state-changing action blocked without exact human approval')}
    dispatch = tool_handlers()
    if action['tool'] not in dispatch:
        return {'stop_reason': 'tool_not_registered'}
    working = {**state, 'planned_actions': actions, 'action_cursor': 0}
    if action['tool'] == 'nmap':
        target = action['target']
        pins = state.get('scope_aliases', {}).get(target)
        working['hosts'] = [pins[0] if pins else target]
    else:
        from urllib.parse import urlsplit
        host = urlsplit(action['target']).hostname
        if host and scope_contains_ip(host, manifest):
            working['hosts'] = list(dict.fromkeys(state.get('hosts', []) + [host]))
    if action['tool'] == 'idor':
        working['idor_scenarios'] = [s for s in state.get('idor_scenarios', []) if s.get('name') == action['target']]
        working.pop('idor_findings', None)
    from src.adaptix.agents.priority import observation_facts, record_outcome
    before = observation_facts(state)
    started = time.monotonic()
    try:
        result = dispatch[action['tool']](working)
        # A tool result carries only its own additions, so the keys a capability can prove
        # into must be accumulated at this boundary. `verified_findings` was missing:
        # `union_extract` executed a real password-hash extraction and wrote the record
        # there, the next tool result replaced the list, and the report showed the plain
        # SQLi match with no impact - the proof existed and never reached the deliverable.
        for key in ('services', 'idor_findings', 'injection_findings', 'script_findings',
                    'verified_findings', 'verification_evidence'):
            if key in result:
                merged = list(state.get(key) or [])
                for entry in (result[key] or []):
                    if entry not in merged:
                        merged.append(entry)
                result[key] = merged
        if 'candidates' in result:
            # Candidate identity is (template_id, endpoint) — stable across reruns.
            # Re-merging at the execution boundary keeps a repeated tool result
            # from duplicating a candidate and keeps prior candidates (including
            # their unchanged evidence) when a later tool result is empty.
            from src.adaptix.processing.normalize import deduplicate
            result['candidates'] = deduplicate('candidates',
                                               list(state.get('candidates', [])) + list(result['candidates']))
    except Exception as exc:
        # The exception type alone is unattributable: "Tool failed: TypeError" cost two
        # debugging rounds because the message carried no location. Record where it broke.
        detail = '%s: %s' % (type(exc).__name__, exc)
        # `exc.__traceback__` is a traceback, not a frame: walking it needs tb_next.
        tb = exc.__traceback__
        while tb is not None and tb.tb_next is not None:
            tb = tb.tb_next
        if tb is not None:
            detail += ' at %s:%s' % (tb.tb_frame.f_code.co_filename.rsplit('/', 1)[-1],
                                     tb.tb_lineno)
        result = {'errors': list(state.get('errors', [])) + ['Tool failed: ' + detail]}
    profiles, outcome = record_outcome(state, before, result, action, time.monotonic() - started)
    result['tool_profiles'] = profiles
    result['approval_audit'] = approval_audit
    result['action_outcomes'] = list(state.get('action_outcomes', [])) + [outcome]
    result['recent_evidence_keys'] = outcome['new_evidence_keys']
    touched = list(state.get('scope_touched', []))
    for unit in action_scope_units(action, working, manifest):
        if unit not in touched:
            touched.append(unit)
    result['scope_touched'] = touched
    result['attempted_actions'] = list(state.get('attempted_actions', [])) + actions
    return result
