"""ADAPTIX unified module. Migrated from tested running code."""
import secrets
import ipaddress
from src.adaptix.config import config
from src.adaptix.security.scope import expand_targets, normalize_requests
from src.adaptix.security.authorization import verify_grant
from src.adaptix.workflow.events import log
from src.adaptix.tools.nmap import reconnaissance
from src.adaptix.tools.httpx import httpx_probe
from src.adaptix.tools.nuclei import nuclei_check
from src.adaptix.tools.playwright import browser_observe
from src.adaptix.agents.planner import adaptive_planning
from src.adaptix.agents.reflector import reflection_verification
from src.adaptix.processing.observations import observation_processing
from src.adaptix.reporting.report import final_report, blocked_report


def scope_guard(state):
    """Check per-run grant before any external scanning, with loopback dev exemption."""
    from src.adaptix.security.authorization import verify_grant
    policy = config('scope.yaml')
    run_id = state.get('run_id') or secrets.token_hex(6)
    try:
        if policy.get('authorization_required', True) and not state.get('authorization_confirmed'):
            raise ValueError('Konfirmasi izin (--authorized) wajib')
        requested = normalize_requests(state.get('target', []))
        grant_path = state.get('grant')
        if grant_path:
            hosts, grant_id = verify_grant(grant_path, requested, state.get('principal'), policy)
            authorization = {'type': 'signed_grant', 'grant_id': grant_id}
        else:
            hosts = expand_targets(requested, policy, require_allowlist=False)
            if not (policy.get('allow_loopback_without_grant', False)
                    and all(__import__('ipaddress').ip_address(ip).is_loopback for ip in hosts)):
                raise ValueError('Target non-loopback membutuhkan signed grant (--grant).')
            authorization = {'type': 'local_loopback'}
        return {'run_id': run_id, 'status': 'scope_ok', 'hosts': hosts, 'authorization': authorization,
                'events': log(state, f'Scope Guard: approved {len(hosts)} pinned host(s)')}
    except (ValueError, TypeError, KeyError) as exc:
        return {'run_id': run_id, 'status': 'scope_blocked', 'hosts': [], 'errors': [str(exc)],
                'events': log(state, f'Scope Guard: BLOCKED - {exc}')}

def state_update(state):
    return {'iterations': int(state.get('iterations', 0)) + 1, 'events': log(state, 'State Update: workflow pass recorded')}
