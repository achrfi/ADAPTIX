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
        count = max(1, min(int(state.get('tool_call_budget', 20)), int(state.get('max_iterations', 20)), max(1, min(int(state.get('token_budget', 50000)), int(state.get('model_context_tokens', 4096))) // 128)))
        window = scope_window(manifest, [], count)
        hosts = list(manifest['hosts']) + [unit_host(u) for u in window if scope_contains_ip(unit_host(u), manifest)]
        return {'scope_manifest': manifest, 'scope_networks': manifest['networks'],
                'scope_aliases': manifest['aliases'], 'scope_ports': scope_ports(state['target'], policy),
                'scope_touched': [], 'scope_deferred': [], 'run_started_at': time.time(),
                'run_id': run_id, 'status': 'scope_ok', 'hosts': list(dict.fromkeys(hosts)),
                'authorization': authorization,
                'events': log(state, f'Scope Guard: approved compact scope, {manifest["total_units"]} target units')}
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
    from src.adaptix.agents.planner import _approved_actions, budget_exhausted
    from src.adaptix.tools.registry import tool_registry, tool_handlers
    if budget_exhausted(state):
        return {'stop_reason': 'budget_exhausted'}
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
        feasible, _ = rank_actions(state, actions, _budget(state, state.get('planner_metrics', {})))
        if not feasible:
            return {'stop_reason': 'budget_insufficient_for_candidates'}
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
                    'policy_feedback': [{'action': action, 'reason': 'Template manifest unavailable; choose another useful tool or report the limitation'}],
                    'events': log(state, 'Nuclei: preflight failed before any network request')}
        active_execution = scan_manifest['approval_required_count'] and (scan_manifest['approval']['result'] == 'allowed' or not scan_manifest['executable_count'])
        specification = {'risk': 'state_change' if active_execution else 'observe',
                         'manifest_sha256': scan_manifest['manifest_sha256']}
        action['manifest_sha256'] = scan_manifest['manifest_sha256']
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
        for key in ('services', 'idor_findings'):
            if key in result:
                result[key] = list(state.get(key, [])) + result[key]
    except Exception as exc:
        result = {'errors': list(state.get('errors', [])) + [f'Tool failed: {type(exc).__name__}']}
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
