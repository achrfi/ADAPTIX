"""Automatic deterministic Nuclei scanning between baseline and adaptive planning.

The phase never involves an LLM decision. It reuses the existing Nuclei adapter
(nuclei_check) verbatim, so every safety property the adapter enforces - exact
template manifests, mechanical inspection, scope binding, shared rate limits,
human approval - stays authoritative. The phase adds only what an automatic
stage must decide itself: which in-scope origins, one bounded wall-clock phase,
a protected tool-call reserve for the adaptive loop, honest accounting (exact
per-request counts are not observable in Nuclei JSONL output, so it records the
manifest-derived request ceiling plus policy-enforced rate limits), and a
compact structured view of scanner output for the planner.
"""
import time
from src.adaptix.config import config
from src.adaptix.processing.observations import observation_processing
from src.adaptix.security.scope import endpoint_key
from src.adaptix.tools.nuclei import nuclei_check
from src.adaptix.tools.registry import tool_registry
from src.adaptix.workflow.budget import remaining_seconds
from src.adaptix.workflow.events import log


def scanner_settings():
    """Validated scanner policy; an invalid operator config fails loudly."""
    raw = config('scanner.yaml').get('nuclei_scan') or {}
    errors = []
    extras = set(raw) - {'enabled', 'max_seconds', 'max_origins', 'adaptive_tool_call_reserve',
                         'template_mode', 'max_candidates_per_origin', 'template_cap',
                         'vulnerability_assessment'}
    if extras:
        errors.append('unknown scanner settings: ' + ', '.join(sorted(extras)))
    if not isinstance(raw.get('enabled', False), bool):
        errors.append('enabled must be a boolean')
    values = {}
    for name in ('max_seconds', 'max_origins', 'adaptive_tool_call_reserve', 'max_candidates_per_origin', 'template_cap'):
        default = 0 if name == 'adaptive_tool_call_reserve' else None
        value = raw.get(name, default)
        if not isinstance(value, int) or isinstance(value, bool) or value < (0 if name == 'adaptive_tool_call_reserve' else 1):
            errors.append(f'{name} must be a '
                          + ('non-negative' if name == 'adaptive_tool_call_reserve' else 'positive')
                          + ' integer')
        else:
            values[name] = value
    mode = str(raw.get('template_mode', 'adaptive'))
    if mode not in ('adaptive', 'observation', 'off', 'assessment'):
        errors.append('template_mode must be adaptive, observation, assessment, or off')
    values['template_mode'] = mode
    assessment = raw.get('vulnerability_assessment', False)
    if not isinstance(assessment, bool):
        errors.append('vulnerability_assessment must be a boolean')
    values['vulnerability_assessment'] = bool(assessment)
    if errors:
        raise ValueError('Invalid scanner.yaml: ' + '; '.join(errors))
    return {'enabled': bool(raw.get('enabled')), **values}


def _engine_version():
    """Detected Nuclei engine version from the run's own registry validation."""
    import re
    spec = tool_registry().get('nuclei') or {}
    version = spec.get('version') or ''
    # Registry captures the CLI banner including ANSI color and INFO framing;
    # reports should read like 'v3.6.2', not terminal noise.
    match = re.search(r'v\d+(?:\.\d+)+', str(version))
    return match.group(0) if match else None


def _absorb(events, seen, source):
    """Append not-yet-recorded run events; never reorder or duplicate."""
    for row in source or ():
        if isinstance(row, str) and row not in seen:
            seen.add(row)
            events.append(row)


def _merge_records(path, existing, addition):
    """Merge an adapter result into working state; dict rows dedupe by equality."""
    if isinstance(existing, dict) and isinstance(addition, dict):
        merged = {**existing}
        for key, value in addition.items():
            if isinstance(value, list) and isinstance(merged.get(key), list):
                seen = list(merged[key])
                for row in value:
                    if not any(row == old for old in seen):
                        seen.append(row)
                merged[key] = seen
            else:
                merged[key] = value
        return merged
    if isinstance(existing, list) and isinstance(addition, list):
        merged = list(existing)
        for row in addition:
            try:
                if row in merged:
                    continue
            except TypeError:
                pass
            if not any(row == old for old in merged if isinstance(old, dict)):
                merged.append(row)
        return merged
    return addition if addition is not None else existing


def _scan_origins(state):
    """In-scope authorities with observed HTTP surface.

    Origins come only from routes the baseline discovered or the run's own
    target list - nothing invented, no DNS or port expansion.
    """
    origins = {}
    for route in state.get('web_routes', []):
        if isinstance(route, dict) and not route.get('static_asset'):
            key = endpoint_key(route.get('url') or '')
            if key:
                origins.setdefault(key[:3], key)
    targets = state.get('target', [])
    targets = [targets] if isinstance(targets, str) else list(targets)
    for url in targets:
        key = endpoint_key(url or '')
        if key:
            origins.setdefault(key[:3], key)
    return [f'{scheme}://{host}:{port}' for scheme, host, port, *_ in origins.values()]


def scan_inventory(state, limit=8, settings=None):
    """Compact token-bounded model view of what the deterministic scan produced."""
    settings = settings or scanner_settings()
    metrics = state.get('nuclei_scan_metrics') or {}
    if not metrics and not state.get('nuclei_scan'):
        # A phase that never ran stays one token: zeros would cost context budget
        # and imply a scan where none happened.
        return {'mode': 'disabled' if state.get('scanner_disabled') else 'not_run'}
    candidates = [row for row in state.get('candidates', []) if isinstance(row, dict)]
    from collections import Counter
    by_id = Counter(str(row.get('template_id') or 'unknown') for row in candidates)
    return {'mode': metrics.get('mode') or ('disabled' if state.get('scanner_disabled') else 'not_run'),
            'engine_version': metrics.get('engine_version'),
            'seconds': metrics.get('seconds'),
            'origins_scanned': metrics.get('origin_count', 0),
            'templates_attempted': metrics.get('templates_attempted', 0),
            'templates_executable': metrics.get('templates_executable', 0),
            'templates_gated': metrics.get('templates_gated', 0),
            'planned_request_ceiling': metrics.get('planned_request_ceiling'),
            'policy_note': 'Exact request counts are not observable in Nuclei output; the scanner records the manifest-derived ceiling and policy-enforced rate limits.',
            'candidates': len(candidates),
            'candidates_by_template': dict(sorted(by_id.items())[:limit]),
            'category_counts': dict(sorted((metrics.get('category_counts') or {}).items(),
                                           key=lambda kv: -kv[1])[:6]) if metrics.get('category_counts') else [],
            'limitations': list(metrics.get('limitations', []))[:4],
            'skipped': list(metrics.get('skipped', []))[:2],
            'tool_calls': metrics.get('tool_calls', 0),
            'template_mode': settings['template_mode']}


def _skip(state, settings, events, seen, mode, reason, metrics_extra=None):
    """Honest skip recorded before any tool ran; metrics stay auditable."""
    metrics = {'mode': mode, 'stop_reason': reason, 'engine_version': _engine_version(),
               'origin_count': 0, 'templates_attempted': 0, 'templates_executable': 0,
               'templates_gated': 0, 'planned_request_ceiling': 0, 'tool_calls': 0,
               'limitations': [metrics_extra] if metrics_extra else [], 'skipped': [reason],
               'seconds': 0.0}
    _absorb(events, seen, [f'Nuclei Scan: {mode}; {reason}'])
    return {'nuclei_scan': {'completed': False}, 'nuclei_scan_metrics': metrics, 'events': events}


def _merge_selective(working, phase):
    """Merge the gated-origin result but never a halt signal into the phase."""
    merged = {**working}
    for key in ('nuclei_template_selections', 'execution_metrics', 'errors', 'raw_bytes'):
        if key in phase:
            merged[key] = _merge_records(key, merged.get(key), phase[key])
    return merged


def nuclei_scan(state):
    """One bounded, LLM-free Nuclei pass over in-scope origins.

    Skips honestly when the phase is disabled, the run has no clock or tool
    budget, the adaptive reserve would be consumed, Nuclei is unavailable, or
    the template catalog is missing. Success is recorded, never assumed.
    """
    settings = scanner_settings()
    events = list(state.get('events', []))
    seen = set(events)
    started = time.monotonic()
    if state.get('scanner_assessment'):
        # The operator's per-run authorization opens the assessment profile; the
        # yaml still must allow it, so the authorization is always an explicit,
        # reviewable pair of facts.
        if settings.get('vulnerability_assessment') and settings['template_mode'] not in ('off',):
            settings = {**settings, 'template_mode': 'assessment'}
        elif not settings.get('vulnerability_assessment'):
            limit_event = 'Nuclei assessment: operator authorized --assessment but scanner.yaml has vulnerability_assessment: false; phase skipped'
            return _skip(state, settings, events, seen, 'skipped', 'assessment not authorized in scanner.yaml',
                         metrics_extra=limit_event)
    deadline = started + min(float(settings['max_seconds']), max(0.0, remaining_seconds(state)))
    registry = tool_registry()
    spec = registry.get('nuclei') or {}

    if not settings['enabled'] or settings['template_mode'] == 'off' or state.get('scanner_disabled'):
        return _skip(state, settings, events, seen, 'disabled' if state.get('scanner_disabled') else 'off',
                     'disabled by configuration')
    if state.get('status') != 'scope_ok':
        return _skip(state, settings, events, seen, 'skipped', 'scope not approved')
    if (state.get('nuclei_scan') or {}).get('completed'):
        return _skip(state, settings, events, seen, 'skipped', 'already completed; not repeating')
    if remaining_seconds(state) <= 0 or time.monotonic() >= deadline:
        return _skip(state, settings, events, seen, 'skipped', 'no run time remaining')
    reserve = max(0, int(settings['adaptive_tool_call_reserve']))
    from src.adaptix.workflow.budget import budget_limit, DEFAULT_TOOL_CALL_BUDGET
    tool_limit = budget_limit(state, 'tool_call_budget', DEFAULT_TOOL_CALL_BUDGET)
    # The scan phase budget is the total budget minus the adaptive loop reserve.
    # We allow up to 8 scanner invocations (origins), but only as many as the
    # budget allows after reserving capacity for the planner. An unlimited
    # tool-call budget leaves the 8-origin cap as the phase's own configuration.
    cap = (8 if tool_limit is None
           else min(tool_limit - reserve, 8))
    if cap < 1:
        return _skip(state, settings, events, seen, 'skipped',
                     'the protected adaptive tool-call reserve leaves no phase budget')
    limitations, skipped = [], []
    if not spec.get('enabled') or not spec.get('path'):
        limitations.append(('Nuclei disabled in tools configuration' if not spec.get('enabled')
                            else 'Nuclei unavailable: ' + str(spec.get('detail', ''))[:120])
                           + '; adaptive HTTP testing continues without scanner-only discovery')
    else:
        try:
            from src.adaptix.security.nuclei_policy import template_root
            http_root = template_root() / 'http'
            if not http_root.is_dir() or not any(http_root.rglob('*.yaml')):
                raise ValueError('no HTTP template found in the installed catalog')
        except (OSError, ValueError) as exc:
            limitations.append('Nuclei template catalog unavailable: ' + str(exc)[:120]
                               + '; templates are never silently downloaded, so scanner-only discovery is skipped')
    if limitations:
        metrics = {'mode': 'limited', 'stop_reason': 'scanner_unavailable', 'engine_version': _engine_version(),
                   'origin_count': 0, 'templates_attempted': 0, 'templates_executable': 0, 'templates_gated': 0,
                   'planned_request_ceiling': 0, 'tool_calls': 0, 'limitations': limitations, 'skipped': [],
                   'seconds': round(time.monotonic() - started, 3)}
        _absorb(events, seen, ['Nuclei Scan: limited; ' + limitations[0]])
        return {'nuclei_scan': {'completed': False}, 'nuclei_scan_metrics': metrics, 'events': events}

    origins = _scan_origins(state)
    if len(origins) > settings['max_origins']:
        limitations.append(f'{len(origins) - settings["max_origins"]} origin(s) above the {settings["max_origins"]} origin cap were not scanned')
        origins = origins[:settings['max_origins']]
    if not origins:
        metrics = {'mode': 'limited', 'stop_reason': 'no_observed_origin', 'engine_version': _engine_version(),
                   'origin_count': 0, 'templates_attempted': 0, 'templates_executable': 0, 'templates_gated': 0,
                   'planned_request_ceiling': 0, 'tool_calls': 0,
                   'limitations': ['no in-scope HTTP origin observed for template scanning'], 'skipped': [],
                   'seconds': round(time.monotonic() - started, 3)}
        _absorb(events, seen, ['Nuclei Scan: limited; no in-scope HTTP origin'])
        return {'nuclei_scan': {'completed': False}, 'nuclei_scan_metrics': metrics, 'events': events}

    working = {**state}
    phase_selection_start = len(state.get('nuclei_template_selections', []))
    candidate_baseline = len(state.get('candidates', []))
    origin_count = 0
    for origin in origins:
        used = (int((working.get('execution_metrics') or {}).get('tool_calls_used', 0))
                - int((state.get('execution_metrics') or {}).get('tool_calls_used', 0)))
        if used >= cap:
            skipped.append('adaptive_reserve_protected')
            limitations.append(f'{len(origins) - origin_count} origin(s) unscanned: the adaptive tool-call reserve is protected')
            break
        if time.monotonic() >= deadline or remaining_seconds(state) <= 0:
            skipped.append('phase_time_limit' if time.monotonic() >= deadline else 'run_time_budget')
            limitations.append(f'{len(origins) - origin_count} origin(s) unscanned within the phase budget')
            break
        # The very adapter a model-planned action would use, driven with a
        # deterministic planned action: manifests, approvals, scope binding and
        # shared rate limits are identical - only the LLM decision is removed.
        scoped = {**working, 'planned_actions': [{'tool': 'nuclei', 'target': origin,
                                                  'reason': 'deterministic baseline scan', 'priority': 1}],
                  'action_cursor': 0, 'nuclei_template_mode': settings['template_mode'],
                  'nuclei_template_cap': settings['template_cap']}
        try:
            phase = nuclei_check(scoped)
        except (ValueError, OSError, TypeError, KeyError) as exc:
            limitations.append(f'{origin}: scanner preflight failed: {str(exc)[:120]}')
            continue
        if not isinstance(phase, dict):
            limitations.append(f'{origin}: adapter returned no structured result')
            continue
        # A gated origin never stalls the deterministic phase: the approval is
        # still bound to the exact manifest; the origin is recorded and the rest
        # continue scanning.
        if phase.get('stop_reason') == 'human_approval_required':
            limitations.append(f'{origin}: template manifest requires operator approval before execution')
            working = _merge_selective(working, phase)
            continue
        for key, value in phase.items():
            if key == 'events':
                _absorb(events, seen, value)
            elif key in ('stop_reason', 'planned_actions'):
                continue
            else:
                working = {**working, key: _merge_records(key, working.get(key), value)}
        origin_count += 1
    selections = [row for row in working.get('nuclei_template_selections', [])
                  if isinstance(row, dict)][phase_selection_start:]
    limitations.extend(str(row.get('selection_note')) for row in selections if row.get('selection_note'))
    categories = {}
    for row in selections:
        for tag, count in (row.get('category_counts') or {}).items():
            categories[tag] = categories.get(tag, 0) + int(count or 0)
    deltas = int((working.get('execution_metrics') or {}).get('tool_calls_used', 0)) - int((state.get('execution_metrics') or {}).get('tool_calls_used', 0))
    metrics = {'mode': 'complete' if origin_count else 'limited',
               'stop_reason': 'complete' if origin_count else 'phase_limited',
               'engine_version': _engine_version(),
               'origin_count': origin_count,
               'templates_attempted': sum(int(row.get('selected_count', 0) or 0) for row in selections),
               'templates_executable': sum(int(row.get('executable_count', 0) or 0) for row in selections),
               'templates_gated': sum(int((row.get('approval_required_count', 0) or 0)
                                          or (row.get('policy') or {}).get('gated_templates', 0)) for row in selections),
               'planned_request_ceiling': sum(int(row.get('request_ceiling_per_target', 0) or 0) for row in selections),
               'tool_calls': deltas,
               'tools_by_tool': {'nuclei': origin_count},
               'category_counts': dict(sorted(categories.items(), key=lambda kv: -kv[1])) if categories else {},
               'template_mode': settings['template_mode'],
               'candidates': len(working.get('candidates', [])) - candidate_baseline,
               'limitations': limitations, 'skipped': skipped,
               'seconds': round(time.monotonic() - started, 3)}
    summary = (f'Nuclei Scan: {metrics["mode"]}; {origin_count} origin(s), {metrics["tool_calls"]} tool call(s), '
               f'template ceiling {metrics["planned_request_ceiling"]} request(s), '
               f'{metrics["candidates"]} unverified candidate(s)'
               + (f'; {len(limitations)} limitation(s)' if limitations else ''))
    update = {key: working.get(key) for key in ('web_routes', 'candidates', 'http_services',
                                                'nuclei_template_selections', 'execution_metrics',
                                                'raw_bytes', 'discovered_documents', 'errors',
                                                # Scanner-verified findings and the informational
                                                # observations the engine produced leave the phase
                                                # in the same keys the rest of the workflow carries.
                                                'verified_findings', 'nuclei_observations')
              if working.get(key) is not None}
    update['candidates'] = [row for row in update.get('candidates', [])
                            if isinstance(row, dict)][:settings['max_candidates_per_origin'] * max(1, origin_count)]
    update['nuclei_scan'] = {'completed': origin_count > 0}
    update['nuclei_scan_metrics'] = metrics
    update['events'] = events
    _absorb(events, seen, [summary])
    processed = observation_processing({**update, 'candidates': update.get('candidates', [])})
    for key, value in processed.items():
        if key != 'events' and key not in ('nuclei_scan', 'nuclei_scan_metrics'):
            update[key] = value
    update['events'] = events
    return update
