"""ADAPTIX unified module. Migrated from tested running code."""
import json
from src.adaptix.config import config, ROOT
from src.adaptix.tools.registry import tool_registry, run_tool
from src.adaptix.evidence.storage import artifact_path, save_text
from src.adaptix.workflow.events import log
from src.adaptix.workflow.budget import tool_budget_available, record_tool_call
from src.adaptix.security.scope import allowed_url, endpoint_key


def nuclei_check(state):
    registry = tool_registry()
    actions = state.get('planned_actions', [])
    cursor = int(state.get('action_cursor', 0))
    intended = ([actions[cursor]['target']] if actions and cursor < len(actions) and actions[cursor]['tool'] == 'nuclei'
                else [x['url'] for x in state.get('http_services', [])] if not actions else [])
    observed = {endpoint_key(x['url']) for x in state.get('http_services', [])}
    endpoints = [url for url in intended if endpoint_key(url) in observed]
    errors = list(state.get('errors', []))
    if not tool_budget_available(state):
        return {'events': log(state, 'Nuclei: skipped, tool-call budget exhausted')}
    if not endpoints:
        return {'events': log(state, 'Nuclei: skipped; no live endpoints')}
    if not registry['nuclei']['enabled']:
        return {'events': log(state, 'Nuclei: disabled in config')}
    if not registry['nuclei']['path']:
        errors.append('Nuclei unavailable: ' + registry['nuclei']['detail'])
        return {'errors': errors, 'events': log(state, 'Nuclei: missing')}
    cfg = config('scope.yaml')['limits']
    template = str(ROOT / 'templates/http-response.yaml')
    argv = [registry['nuclei']['path'], '-t', template, '-j', '-silent', '-duc',
            '-c', str(cfg['concurrent_requests']), '-rl', str(cfg['rate_per_second']), '-timeout', '5', '-dr', '-or', '-ot']
    result = run_tool(argv, timeout=max(int(cfg['timeout_seconds']), 60), stdin='\n'.join(endpoints) + '\n')
    execution_metrics = record_tool_call(state, 'nuclei')
    raw = result['stdout']
    save_text(artifact_path(state, 'nuclei', endpoints[0], 'jsonl'), raw)
    if result['returncode'] != 0:
        errors.append('Nuclei: ' + result['stderr'][:200])
    candidates = []
    approved = {endpoint_key(url) for url in endpoints}
    allowed_ports = {key[2] for key in approved if key}
    for line in raw.splitlines():
        try:
            row = json.loads(line)
            url = row.get('matched-at') or row.get('host', '')
            if endpoint_key(url) not in approved or not allowed_url(url, state['hosts'], allowed_ports):
                continue
            candidates.append({'template_id': row.get('template-id', ''),
                               'url': url, 'severity': row.get('info', {}).get('severity', 'info'),
                               'status': 'candidate_unverified',
                               'finding_type': ('service_reachability' if row.get('template-id') == 'adaptix-http-baseline'
                                                else 'potential_vulnerability')})
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
    previous = list(state.get('candidates', []))
    previous_keys = {(x['template_id'], endpoint_key(x['url'])) for x in previous}
    previous.extend(c for c in candidates if (c['template_id'], endpoint_key(c['url'])) not in previous_keys)
    return {'candidates': previous, 'execution_metrics': execution_metrics, 'raw_bytes': state.get('raw_bytes', 0) + len(raw.encode()),
            'errors': errors, 'events': log(state, f'Nuclei: {len(candidates)} unverified matches')}
