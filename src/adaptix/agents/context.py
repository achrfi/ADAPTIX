"""Adaptive context compression for planner passes.

Compression is staged and measurement-driven: every pass records how many tokens
the uncompressed context required, how many are available, and which stages were
applied. Objective, authorization, scope, untested endpoint candidates, recent
evidence, uncertainty, action outcomes and policy feedback are preserved by
construction: bulk inventories are summarized or shortened, never authoritative
control data. If no context that keeps those essentials fits, the pass stops with
diagnostics instead of silently stripping security controls.
"""
import json


# Authoritative fields compression may shorten but never delete.
ESSENTIAL_FIELDS = frozenset({
    'user_request', 'authorization', 'scope_window', 'requested_endpoints',
    'scope_summary', 'domain_aliases', 'budget', 'reflection', 'stagnation',
    'controller_assessment', 'policy_feedback', 'rejected_actions',
    'identity_context_summary', 'discovery_limitations', 'web_route_summary',
    'evidence_summary', 'available_endpoints', 'observations',
    'tool_eligibility', 'documentation_attempts',
})

# Observation kinds whose rows are evidence references rather than bulk text.
EVIDENCE_OBSERVATIONS = frozenset({'probe_traces'})


def _encoded(payload):
    return json.dumps(payload, ensure_ascii=False, separators=(',', ':'), default=str)


def _shorten(value, limit):
    value = str(value)
    if len(value) <= limit:
        return value
    return value[:max(80, limit - 3)] + '...'


def _nonempty(value):
    """True when a field still carries content (never emptied by compression)."""
    return bool(value) if isinstance(value, (list, dict, str)) else value is not None


def _halve(value):
    value = str(value)
    return value[:max(80, len(value) // 2)] if len(value) > 160 else value


def _observed(payload):
    observations = payload.get('observations')
    return observations if isinstance(observations, dict) else {}


def _summarize_routes(payload):
    """Route inventories become counts plus a prioritized subset, not full repeats."""
    observations = _observed(payload)
    rows = observations.get('web_routes')
    if not isinstance(rows, list) or len(rows) <= 4:
        return False
    keep = max(4, len(rows) // 2)
    summary = payload.get('web_route_summary')
    if isinstance(summary, dict):
        summary['shown'] = keep
        summary['summarized'] = True
    compact = []
    for row in rows[:keep]:
        if not isinstance(row, dict):
            continue
        compact.append({key: row[key] for key in ('url', 'method', 'kind', 'api_like', 'evidence_ref')
                        if key in row})
    observations['web_routes'] = compact
    return True


def _prioritize_endpoints(payload):
    """Keep the strongest untested endpoint candidates; they are ranked already."""
    rows = payload.get('available_endpoints')
    if not isinstance(rows, list) or len(rows) <= 6:
        return False
    payload['available_endpoints'] = rows[:max(6, len(rows) // 2)]
    return True


def _compress_assessment(payload):
    """Controller verdict stays verbatim in shape; only its prose is bounded."""
    assessment = payload.get('controller_assessment')
    if not isinstance(assessment, dict):
        return False
    changed = False
    for key in ('uncertainty', 'failure'):
        value = str(assessment.get(key) or '')
        if len(value) > 160:
            assessment[key] = _shorten(value, 160)
            changed = True
    refs = assessment.get('evidence_refs')
    if isinstance(refs, list) and len(refs) > 6:
        assessment['evidence_refs'] = refs[:6]
        changed = True
    return changed


def _compress_tool_catalog(payload):
    changed = False
    registry = payload.get('tool_registry')
    if isinstance(registry, dict):
        for spec in registry.values():
            if isinstance(spec, dict) and len(str(spec.get('description', ''))) > 120:
                spec['description'] = _shorten(spec['description'], 120)
                changed = True
    profiles = payload.get('tool_profiles')
    if isinstance(profiles, dict):
        for spec in profiles.values():
            if isinstance(spec, dict):
                for key, value in list(spec.items()):
                    if isinstance(value, str) and len(value) > 120:
                        spec[key] = _shorten(value, 120)
                        changed = True
    # Eligibility counts and examples stay; only the prose is bounded, so a rejected
    # action is never contradicted by a stripped capability report.
    return changed


def _compress_history(payload):
    """Shorten and thin decision history; the newest entries stay intact."""
    changed = False
    for field in ('attempted_actions', 'rejected_actions', 'policy_feedback',
                  'discovery_limitations', 'recent_action_outcomes'):
        rows = payload.get(field)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            for key in ('reason', 'progress_reason', 'hypothesis'):
                if len(str(row.get(key) or '')) > 160:
                    row[key] = _shorten(row[key], 160)
                    changed = True
        keep = {'attempted_actions': 8, 'rejected_actions': 8, 'policy_feedback': 8,
                'discovery_limitations': 6, 'recent_action_outcomes': 6}[field]
        if len(rows) > keep:
            payload[field] = rows[-keep:] if field in ('attempted_actions', 'recent_action_outcomes') else rows[:keep]
            changed = True
    for field, keep in (('hypotheses', 6), ('hypothesis_seeds', 6), ('findings', 6),
                        ('scenario_candidates', 6), ('api_operations', 6),
                        ('documentation_attempts', 6)):
        rows = payload.get(field)
        if isinstance(rows, list) and len(rows) > keep:
            payload[field] = rows[:keep]
            changed = True
    return changed


def _compress_observation_rows(payload):
    """Bound bulky prose inside observation rows; urls, methods and refs stay."""
    changed = False
    for kind, rows in _observed(payload).items():
        if kind in EVIDENCE_OBSERVATIONS or not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            for key, value in list(row.items()):
                if key in ('url', 'method', 'kind', 'evidence_ref', 'parameter'):
                    continue
                if isinstance(value, str) and len(value) > 120:
                    row[key] = _shorten(value, 120)
                    changed = True
    return changed


def _trim_largest_list(collections):
    populated = [values for values in collections if len(values) > 1]
    if not populated:
        return False
    largest = max(populated, key=lambda values: len(json.dumps(values, default=str)))
    largest.pop()
    return True


def _trim_api_records(payload):
    api = payload.get('observations', {}).get('api_observations', [])
    bulky = next((row for row in api if len(row.get('records', [])) > 1), None)
    if not bulky:
        return False
    names = set(payload.get('identity_context_summary', {}).get('identities', []))
    bulky['records'].sort(key=lambda r: any(r.get(k) in names for k in ('owner', 'user', 'username')), reverse=True)
    bulky['records'] = bulky['records'][:max(1, len(bulky['records']) // 2)]
    return True


def _trim_browser(payload):
    browser = payload.get('observations', {}).get('browser_evidence', [])
    bulky = next((row for row in browser if len(row.get('text_excerpt', '')) > 80 or len(row.get('links', [])) > 1), None)
    if not bulky:
        return False
    if len(bulky.get('text_excerpt', '')) > 80:
        bulky['text_excerpt'] = bulky['text_excerpt'][:max(80, len(bulky['text_excerpt']) // 2)]
    elif len(bulky.get('links', [])) > 1:
        bulky['links'] = bulky['links'][:max(1, len(bulky['links']) // 2)]
    return True


def _trim_scope_window(payload):
    if len(payload.get('scope_window', [])) <= 1:
        return False
    from src.adaptix.security.scope import unit_host
    dropped = payload['scope_window'].pop()
    host = unit_host(dropped)
    if not any(unit_host(unit) == host for unit in payload['scope_window']):
        payload['domain_aliases'].pop(host, None)
    payload['requested_endpoints'] = [url for url in payload.get('requested_endpoints', []) if url != dropped]
    return True


def _degrade(payload):
    """Presentation-only degradation: never delete current evidence or reflection."""
    reflection = payload.get('reflection')
    if isinstance(reflection, dict):
        for duplicate in ('last_action', 'policy_feedback'):
            if duplicate in reflection:
                reflection.pop(duplicate)
                return True
    for field in ('tool_profiles', 'tool_registry'):
        if payload.get(field):
            payload[field] = {}
            return True
    for row in payload.get('attempted_actions', []):
        if len(str(row.get('reason', ''))) > 160:
            row['reason'] = _halve(row['reason'])
            return True
    for row in payload.get('rejected_actions', []):
        if len(str(row.get('reason', ''))) > 200:
            row['reason'] = _halve(row['reason'])
            return True
    for row in payload.get('policy_feedback', []):
        if len(str(row.get('reason', ''))) > 200:
            row['reason'] = _halve(row['reason'])
            return True
    for row in payload.get('discovery_limitations', []):
        if len(str(row.get('reason', ''))) > 200:
            row['reason'] = _halve(row['reason'])
            return True
    for row in payload.get('recent_action_outcomes', []):
        if len(str(row.get('progress_reason', ''))) > 120:
            row['progress_reason'] = _halve(row['progress_reason'])
            return True
    for field in ('recent_action_outcomes', 'policy_feedback', 'rejected_actions'):
        if len(payload.get(field, [])) > 1:
            payload[field].pop()
            return True
    return False


def _compress_capability(payload):
    """Trim the capability report and the endpoint inventories it points at.

    These are re-derivable views of ``observations``: what must survive is that each
    tool still reports whether it has eligible inputs, never the full list of them.
    """
    changed = False
    eligibility = payload.get('tool_eligibility')
    if isinstance(eligibility, dict):
        for spec in eligibility.values():
            if not isinstance(spec, dict):
                continue
            if isinstance(spec.get('targets'), list) and len(spec['targets']) > 1:
                spec['targets'] = spec['targets'][:1]
                changed = True
            if isinstance(spec.get('requires'), list) and len(spec['requires']) > 1:
                spec['requires'] = spec['requires'][:1]
                changed = True
    for field, keep in (('available_endpoints', 8), ('discovery_targets', 10),
                        ('documentation_attempts', 4)):
        rows = payload.get(field)
        if isinstance(rows, list) and len(rows) > keep:
            payload[field] = rows[:keep]
            changed = True
    return changed


# Stages run cheapest-loss first; destructive trimming runs only after
# summarization has already reclaimed what the pass can spare.
STAGES = (
    ('summarize_routes', _summarize_routes),
    ('prioritize_endpoints', _prioritize_endpoints),
    ('compress_capability', _compress_capability),
    ('compress_assessment', _compress_assessment),
    ('compress_tool_catalog', _compress_tool_catalog),
    ('compress_history', _compress_history),
    ('compress_observation_rows', _compress_observation_rows),
)


def compact_context(payload, system_prompt, token_budget, count_tokens):
    token_budget = max(0, int(token_budget))
    encoded = _encoded(payload)
    required = int(count_tokens(system_prompt, encoded))
    metrics = {'context_available_tokens': token_budget, 'context_required_tokens': required}
    # Essential fields that hold objective, authorization, scope and feedback must
    # stay non-empty: a stage that empties one fails the pass closed.
    baseline = {key: _nonempty(payload.get(key)) for key in ESSENTIAL_FIELDS if key in payload}
    # Only collections that may be emptied safely: the authoritative control fields
    # (capability report, endpoint candidates, feedback) are bounded by their own
    # stages so that trimming can never empty them.
    collections = [payload['services'], payload['known_urls'], payload['attempted_actions'],
                   payload['idor_findings'], payload.get('api_operations', []), payload.get('scenario_candidates', []),
                   payload.get('discovery_targets', []), payload.get('discovery_limitations', []), *payload['observations'].values()]
    removed = 0
    stages = []

    def outcome(compressed, violation=None):
        result = {**metrics, 'context_compressed_tokens': int(compressed),
                  'removed_context_records': removed, 'context_bytes': len(encoded.encode('utf-8')),
                  'context_compression_stages': list(stages)}
        if violation:
            result['context_integrity_violation'] = violation
        return result

    def intact():
        for key, was in baseline.items():
            if was and not _nonempty(payload.get(key)):
                return key
        return None

    if required <= token_budget:
        return encoded, outcome(required)
    while True:
        applied = False
        for name, stage in STAGES:
            if stage(payload):
                stages.append(name)
                removed += 1
                applied = True
                break
        if not applied:
            # Lists are ordered newest/relevant first. Preserve one current item per kind.
            if _trim_largest_list(collections):
                removed += 1
            elif _trim_api_records(payload):
                removed += 1
            elif _trim_browser(payload):
                removed += 1
            elif _trim_scope_window(payload):
                removed += 1
            elif _degrade(payload):
                removed += 1
            else:
                # Preserve the instruction and minimum decision context; stop if they cannot fit.
                encoded = _encoded(payload)
                return None, outcome(int(count_tokens(system_prompt, encoded)))
        violation = intact()
        if violation:
            # Never send a context stripped of authoritative control data.
            encoded = _encoded(payload)
            return None, outcome(int(count_tokens(system_prompt, encoded)), violation)
        encoded = _encoded(payload)
        compressed = int(count_tokens(system_prompt, encoded))
        if compressed <= token_budget:
            return encoded, outcome(compressed)
