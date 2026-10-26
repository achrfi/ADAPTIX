"""Completed actions are memoized by semantic parameters, not just tool/URL."""
import hashlib
import json
from pathlib import Path
from src.adaptix.config import config, ROOT


def nuclei_signature(state, target):
    from src.adaptix.tools.nuclei_profiles import adaptive_profile
    settings = config('scope.yaml')['limits']
    mode = settings.get('nuclei_templates', 'default')
    selection = adaptive_profile(state, target) if mode == 'adaptive' else {'strategy': 'configured', 'tags': []}
    paths = mode if isinstance(mode, list) else ['templates/http-response.yaml'] if mode == 'baseline' else []
    files = []
    for value in paths:
        path = (ROOT / value).resolve()
        members = [path] if path.is_file() else sorted(path.rglob('*.yaml')) if path.is_dir() else []
        files.extend((str(member), hashlib.sha256(member.read_bytes()).hexdigest()) for member in members)
    policy = config('nuclei.yaml').get('policy', {})
    revision = None
    if not paths:
        from src.adaptix.security.nuclei_policy import template_root
        index = template_root() / '.templates-index'
        revision = hashlib.sha256(index.read_bytes()).hexdigest() if index.is_file() else None
    return {'mode': mode, 'strategy': selection['strategy'], 'tags': selection['tags'], 'files': files, 'policy': policy, 'catalog_revision': revision}


def execution_identity(action, state):
    from src.adaptix.security.scope import endpoint_key
    target = endpoint_key(action['target']) if '://' in action['target'] else action['target']
    data = {'tool': action['tool'], 'target': target}
    if action['tool'] == 'scenario':
        # Credential refresh can unblock validation; never expose credentials to the model.
        data['identity_revision'] = hashlib.sha256(json.dumps(state.get('identity_context', {}), sort_keys=True).encode()).hexdigest()
    if action['tool'] == 'nuclei':
        data['profile'] = nuclei_signature(state, action['target'])
    if action['tool'] == 'http_request':
        data['method'] = str(action.get('method') or 'GET').upper()
        if action.get('body'):
            data['body'] = hashlib.sha256(str(action['body']).encode()).hexdigest()
        if action.get('headers'):
            data['headers'] = hashlib.sha256(json.dumps(action['headers'], sort_keys=True, default=str).encode()).hexdigest()
        if action.get('identity'):
            data['identity'] = str(action['identity'])
    if action['tool'] == 'static_discovery':
        # A different wordlist profile is a different sweep over the same origin.
        data['profile'] = str(action.get('profile') or 'common')
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()


def _baseline_already_discovered(tool, target, state):
    """Discovery work the deterministic baseline already did on this input.

    Baseline tool calls never enter ``attempted_actions`` (the model authored no
    plan), so the usual repetition check cannot see them. Completion is read from
    what the baseline actually recorded: a web_discover on an origin it seeded, an
    api_discover on a document it fetched or whose unusable response it logged.
    Without the baseline-metrics step there is no "already ran" claim for a
    re-seeded web_discover: fuller, tool-specific reasons cover that case.
    """
    from src.adaptix.security.scope import endpoint_key
    key = endpoint_key(target)
    if not key:
        return False
    for step in ((state.get('baseline_metrics') or {}).get('steps') or []):
        if isinstance(step, dict) and step.get('tool') == tool:
            step_key = endpoint_key(str(step.get('target') or ''))
            if step_key is not None and step_key[:3] == key[:3]:
                return True
    if tool != 'api_discover':
        return False
    probed = {endpoint_key(u)[:4] for u in state.get('discovered_documents', [])
              if isinstance(u, str) and endpoint_key(u) and endpoint_key(u)[:3] == key[:3]}
    limited = {endpoint_key(str(row.get('url')))[:4] for row in state.get('discovery_limitations', [])
               if isinstance(row, dict) and endpoint_key(str(row.get('url')))}
    # Only a usable observation counts as finished discovery: a failed probe must
    # stay re-openable through the missing-prerequisite nuance (new evidence can
    # make it eligible again), never as a blanket "already completed".
    observed = {endpoint_key(str(row.get('url')))[:4] for row in state.get('api_observations', [])
                if isinstance(row, dict) and not row.get('reason')
                and row.get('document_kind') not in ('http_error', 'invalid_json')
                and endpoint_key(str(row.get('url')))}
    return key[:4] in (probed | limited | observed)


def already_completed(action, state):
    if action['tool'] in ('web_discover', 'api_discover') and action.get('target'):
        if _baseline_already_discovered(action['tool'], action['target'], state):
            return True
    identity = execution_identity(action, state)
    for old in state.get('attempted_actions', []):
        if old['tool'] != action['tool']:
            continue
        if old.get('execution_identity'):
            if old['execution_identity'] == identity:
                return True
            continue
        # Legacy rows without an execution identity compare semantically, not by
        # raw string: http://host:port and http://host:port/ are one fetch, so
        # they must complete each other instead of sneaking past the guard.
        from src.adaptix.security.scope import endpoint_key
        old_key = endpoint_key(str(old['target'])) if '://' in str(old['target']) else str(old['target'])
        new_key = endpoint_key(action['target']) if '://' in action['target'] else action['target']
        if old_key != new_key:
            continue
        if action['tool'] == 'nuclei':
            selections = [row for row in state.get('nuclei_template_selections', []) if row.get('target') == action['target']]
            if not selections or selections[-1].get('tags') == nuclei_signature(state, action['target'])['tags']:
                return True
        else:
            return True
    return False
