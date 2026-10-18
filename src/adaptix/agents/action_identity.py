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
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()


def already_completed(action, state):
    identity = execution_identity(action, state)
    for old in state.get('attempted_actions', []):
        if old['tool'] != action['tool']:
            continue
        if old.get('execution_identity'):
            if old['execution_identity'] == identity:
                return True
        elif old['target'] != action['target']:
            continue
        elif action['tool'] == 'nuclei':
            selections = [row for row in state.get('nuclei_template_selections', []) if row.get('target') == action['target']]
            if not selections or selections[-1].get('tags') == nuclei_signature(state, action['target'])['tags']:
                return True
        else:
            return True
    return False
