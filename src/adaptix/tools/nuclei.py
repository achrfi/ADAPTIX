"""ADAPTIX unified module. Migrated from tested running code."""
import json
import time
from src.adaptix.config import config, ROOT
from src.adaptix.tools.registry import tool_registry, run_tool
from src.adaptix.evidence.storage import artifact_path, save_text
from src.adaptix.workflow.events import log
from src.adaptix.workflow.budget import tool_budget_available, record_tool_call, tool_timeout, remaining_seconds
from src.adaptix.security.scope import allowed_url, endpoint_key
from src.adaptix.security.transport import bind_cli_urls, logical_url
from src.adaptix.tools.nuclei_profiles import adaptive_profile
from src.adaptix.security.nuclei_policy import prepare_scan, materialize


def template_selection(settings):
    """An empty -t selection delegates discovery/exclusions to the Nuclei engine."""
    selection = settings.get('nuclei_templates', 'default')
    if selection == 'default':
        return [], False
    if selection == 'baseline':
        return ['-t', str(ROOT / 'templates/http-response.yaml')], True
    if not isinstance(selection, list) or not selection:
        raise ValueError('nuclei_templates must be adaptive, default, baseline, or a nonempty list of local paths')
    flags = []
    for value in selection:
        if not isinstance(value, str) or not value.strip():
            raise ValueError('Nuclei template paths must be nonempty strings')
        path = (ROOT / value).resolve()
        if not path.exists():
            raise ValueError(f'Nuclei template path does not exist: {value}')
        flags.extend(['-t', str(path)])
    return flags, False


def nuclei_check(state):
    registry = tool_registry()
    actions = state.get('planned_actions', [])
    cursor = int(state.get('action_cursor', 0))
    intended = ([actions[cursor]['target']] if actions and cursor < len(actions) and actions[cursor]['tool'] == 'nuclei'
                else [x['url'] for x in state.get('http_services', [])] if not actions else [])
    endpoints = intended
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
    adaptive = cfg.get('nuclei_templates') == 'adaptive'
    # A tag observed at one origin must never select templates for another origin.
    grouped = {}
    for url in endpoints:
        key = endpoint_key(url)
        grouped.setdefault(key, []).append(url)
    groups = list(grouped.values())
    execution_metrics = dict(state.get('execution_metrics', {}))
    selections = list(state.get('nuclei_template_selections', []))
    raw_bytes = state.get('raw_bytes', 0)
    candidates = []
    technologies = {}
    events = list(state.get('events', []))
    for group in groups:
        working = {**state, 'execution_metrics': execution_metrics}
        if not tool_budget_available(working) or remaining_seconds(working) <= 0:
            errors.append('Nuclei: budget exhausted before all selected origins could be scanned')
            break
        bound_urls, bindings, domain_flags = bind_cli_urls(group, state)
        manifest = prepare_scan(state, group[0], cfg)
        selection = {key: value for key, value in manifest.items() if key not in ('_chosen', 'templates')}
        selection['policy'] = {'coverage': manifest['coverage'], 'gated_templates': manifest['approval_required_count'], 'manifest_ref': manifest['manifest_ref']}
        exact_path = manifest['exact_path']
        if not manifest['executable_count']:
            selection['execution_status'] = 'approval_required' if manifest['selected_count'] else 'no_matching_templates'
            selections.append(selection)
            if manifest['selected_count']:
                return {'nuclei_template_selections': selections, 'stop_reason': 'human_approval_required', 'execution_metrics': execution_metrics,
                        'events': log({'events': events}, 'Nuclei: exact manifest approval required before execution')}
            continue
        template_flags = materialize(state, manifest)
        if manifest['approval']['result'] == 'allowed' and manifest['approval_required_count']:
            import os
            claim = artifact_path(state, 'nuclei-approval-use', manifest['approval']['approval_id'] + manifest['manifest_sha256'], 'json')
            try:
                descriptor = os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'w') as stream:
                    json.dump({'manifest_sha256': manifest['manifest_sha256'], 'target': group[0]}, stream)
            except FileExistsError:
                return {'stop_reason': 'human_approval_required', 'errors': errors + ['Nuclei manifest approval was already consumed'],
                        'events': log({'events': events}, 'Nuclei: single-use manifest approval cannot be replayed')}
        selection['targets'] = group
        argv = [registry['nuclei']['path'], *template_flags, '-j', '-silent', '-duc',
                '-c', str(cfg['concurrent_requests']), '-rl', str(cfg['rate_per_second']), '-timeout', '5', '-dr', '-or', '-ot']
        argv.extend(domain_flags)
        events = log({'events': events}, f'Nuclei selection: {selection["strategy"]}, tags={selection["tags"]}, target={group[0]}')
        timeout = tool_timeout(working, int(cfg.get('nuclei_timeout_seconds', max(int(cfg['timeout_seconds']), 60))))
        if manifest['approval']['result'] == 'allowed':
            timeout = min(timeout, max(.001, manifest['approval']['expires_at'] - time.time()))
        argv.extend(['-retries', '0'])
        result = run_tool(argv, timeout=timeout, stdin='\n'.join(bound_urls) + '\n')
        execution_metrics = record_tool_call(working, 'nuclei')
        raw = result['stdout']
        raw_bytes += len(raw.encode())
        selection['execution_status'] = 'completed' if result['returncode'] == 0 else 'error_or_partial'
        selections.append(selection)
        save_text(artifact_path(state, 'nuclei-selection', group[0], 'json'), json.dumps(selection, indent=2))
        save_text(artifact_path(state, 'nuclei', group[0], 'jsonl'), raw)
        if result['returncode'] != 0:
            errors.append('Nuclei: ' + result['stderr'][:200])
        approved = {endpoint_key(url) for url in group}
        approved_origins = {key[:3] for key in approved if key}
        allowed_ports = {key[2] for key in approved if key}
        for line in raw.splitlines():
            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    continue
                url = logical_url(row.get('matched-at') or row.get('host', ''), bindings, allow_paths=not exact_path)
                key = endpoint_key(url)
                selected = key in approved if exact_path else bool(key and key[:3] in approved_origins)
                if not selected or not allowed_url(url, state['hosts'], allowed_ports, state.get('scope_aliases'), state.get('scope_networks')):
                    continue
                candidates.append({'template_id': row.get('template-id', ''),
                                   'url': url, 'severity': row.get('info', {}).get('severity', 'info'),
                                   'status': 'candidate_unverified',
                                   'finding_type': ('service_reachability' if row.get('template-id') == 'adaptix-http-baseline'
                                                    else 'potential_vulnerability')})
                if selection.get('strategy') == 'native_automatic':
                    from src.adaptix.tools.nuclei_profiles import _product
                    mapping = config('nuclei.yaml')['technology_tags']
                    match = _product(row.get('matcher-name', ''))
                    if match in {_product(value) for value in mapping}:
                        technologies.setdefault(group[0], set()).add(match)
            except (json.JSONDecodeError, TypeError, ValueError, AttributeError):
                continue
    previous = list(state.get('candidates', []))
    from src.adaptix.processing.normalize import deduplicate
    previous = deduplicate('candidates', previous + candidates)
    http_services = list(state.get('http_services', []))
    for target, detected in technologies.items():
        entry = next((dict(row) for row in http_services if endpoint_key(row['url']) == endpoint_key(target)), {'url': target})
        entry['tech'] = sorted(set(entry.get('tech', [])) | detected)
        entry['technology_source'] = 'nuclei_readonly_discovery'
        http_services = deduplicate('http_services', http_services + [entry])
    return {'candidates': previous, 'execution_metrics': execution_metrics, 'raw_bytes': raw_bytes,
            'http_services': http_services,
            'nuclei_template_selections': selections,
            'errors': errors, 'events': log({'events': events}, f'Nuclei: {len(candidates)} unverified matches')}
