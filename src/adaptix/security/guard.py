"""Minimal deterministic security guard.

This module is the only place where an action is refused for *security* reasons:
authorization, pinned scope, host/port/URL boundaries, redirect containment and
human approval for state-changing effects. Everything else about an action (does
the run hold the evidence the tool needs, is the action worth doing, what should be
tested next) belongs to the LLM and to the capability contract in
``src.adaptix/agents/capabilities.py``.

The guard never reasons about vulnerability classes, endpoint priorities or attack
order. It is not bypassable by planner text, reflection, tool output or policy
feedback: it reads only trusted state (the signed grant, the pinned manifest and
the registry) and the concrete action about to execute.
"""
import re
from urllib.parse import urlsplit

from src.adaptix.config import config
from src.adaptix.security.ports import ports_for_state
from src.adaptix.security.scope import allowed_url, endpoint_key, scope_contains_ip

# Request shapes that can change or destroy target state. A request is treated by
# its actual effect, not by its verb alone: a body-carrying GET or a request aimed
# at an administrative path is a state change even though the method is safe.
DESTRUCTIVE_PATH = re.compile(
    r'/(?:createdb|create-db|reset|delete|destroy|drop|dropall|wipe|purge|logout|logoutall|'
    r'shutdown|restart|restartcontainer|factory-reset)(?:/|$)',
    re.I)
MUTATING_METHODS = ('POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')


def allowed_url_for_state(state, url):
    """The single scope predicate every adapter and the planner share."""
    manifest = state.get('scope_manifest') or {}
    hosts = manifest.get('hosts') if manifest else state.get('hosts', [])
    aliases = manifest.get('aliases') if manifest else state.get('scope_aliases', {})
    networks = manifest.get('networks') if manifest else state.get('scope_networks', [])
    ports = set(ports_for_state(state, config('scope.yaml')['limits']))
    return allowed_url(url, hosts or [], ports, aliases or {}, networks or [])


def is_destructive(target):
    """True when the URL path names a state-changing administrative resource.

    This is a safety boundary, not a heuristic: requesting one of these paths can
    reset or destroy target state even with a safe HTTP verb, so it is classified
    by effect rather than by method.
    """
    try:
        return bool(DESTRUCTIVE_PATH.search(urlsplit(target).path))
    except (TypeError, ValueError):
        return False


def action_effect(state, action):
    """Classify the real effect of an action from the registry and the concrete input.

    A capability the trusted registry declares state-changing always is. A registry
    entry marked ``observe`` is escalated when the concrete request would actually
    change state, so the decision follows the effect rather than the verb alone.
    """
    registry = config('tools.yaml')['tools']
    tool = action.get('tool')
    spec = (state.get('tool_catalog') or {}).get(tool) or registry.get(tool) or {}
    risk = spec.get('risk', 'observe')
    operation = spec.get('operation', 'observe')
    if risk == 'state_change':
        return {'risk': 'state_change', 'operation': operation or 'state_change', 'basis': 'registry'}
    if tool == 'nuclei':
        return {'risk': 'template_dependent', 'operation': 'scan', 'basis': 'template_policy'}
    method = str(action.get('method') or 'GET').upper()
    reasons = []
    if method in MUTATING_METHODS:
        reasons.append('mutating_method')
    if action.get('body'):
        reasons.append('request_body')
    if tool == 'http_request' and is_destructive(action.get('target', '')):
        reasons.append('destructive_path')
    if operation == 'authorization_test_get' and method not in ('GET', 'HEAD'):
        reasons.append('non_get_authorization_test')
    if not reasons:
        return {'risk': 'observe', 'operation': operation, 'basis': 'registry'}
    return {'risk': 'state_change', 'operation': operation or 'state_change',
            'basis': 'actual_effect', 'reasons': reasons}


def redirect_allowed(state, location, origin):
    """Server-supplied redirects may never leave the pinned scope."""
    if not location:
        return True
    from urllib.parse import urljoin
    return allowed_url_for_state(state, urljoin(origin, location))


def guard_action(state, action, resolved_url=None):
    """Return ``{'allowed': bool, 'code': str, 'reason': str}`` for one action.

    Scope and host/port/URL containment only. Approval is decided at the execution
    boundary by :mod:`src.adaptix.security.action_policy`, because it depends on the
    signed approval set rather than on the action text. ``resolved_url`` lets a
    named-scenario tool be checked against the URL it will actually request.
    """
    tool, target = action.get('tool'), action.get('target', '')
    manifest = state.get('scope_manifest') or {}
    hosts = manifest.get('hosts') if manifest else state.get('hosts', [])
    aliases = manifest.get('aliases') if manifest else state.get('scope_aliases', {})
    networks = manifest.get('networks') if manifest else state.get('scope_networks', [])
    if tool == 'nmap':
        if not (target in aliases or scope_contains_ip(target, {'hosts': hosts or [], 'networks': networks or []})):
            return {'allowed': False, 'code': 'host_outside_scope',
                    'reason': 'Host is not part of the pinned authorized scope'}
        return {'allowed': True, 'code': 'ok', 'reason': ''}
    if tool in ('scenario', 'idor'):
        # A named scenario resolves to a URL; when no such scenario exists the
        # capability contract reports the missing fixture, not a scope failure.
        if not resolved_url:
            return {'allowed': True, 'code': 'ok', 'reason': ''}
        if str(action.get('method') or 'GET').upper() != 'GET':
            return {'allowed': False, 'code': 'scenario_method_not_get',
                    'reason': 'A named-scenario tool may only issue a bounded GET of a real object'}
        url = resolved_url
    else:
        url = target
    if not endpoint_key(url):
        return {'allowed': False, 'code': 'malformed_target', 'reason': 'Target is not an http/https URL'}
    if not allowed_url(url, hosts or [], set(ports_for_state(state, config('scope.yaml')['limits'])),
                       aliases or {}, networks or []):
        return {'allowed': False, 'code': 'url_outside_scope',
                'reason': 'Endpoint host or port is outside the pinned authorized scope'}
    return {'allowed': True, 'code': 'ok', 'reason': ''}


def guard_scenario_request(state, scenario):
    """A configured scenario may only issue a safe, in-scope GET of a real object."""
    method = str(scenario.get('method', 'GET')).upper()
    if method != 'GET':
        return {'allowed': False, 'code': 'scenario_method', 'reason': 'Scenario is not a bounded GET'}
    try:
        url = scenario['base_url'].rstrip('/') + scenario['path_template'].format(object_id=scenario['object_id'])
    except (KeyError, ValueError, TypeError):
        return {'allowed': False, 'code': 'scenario_unresolved', 'reason': 'Scenario does not resolve to a URL'}
    if not allowed_url_for_state(state, url):
        return {'allowed': False, 'code': 'scenario_outside_scope',
                'reason': 'Scenario URL is outside the pinned authorized scope'}
    return {'allowed': True, 'code': 'ok', 'reason': '', 'url': url}