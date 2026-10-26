"""One projection for planner context, novelty and marginal token calibration."""
import hashlib
import json
from urllib.parse import urlsplit
from src.adaptix.security.scope import endpoint_key

FIELDS = {
    'ffuf_observations': ('url', 'method', 'status_code', 'length', 'words', 'lines',
                          'source', 'source_sha256', 'verification_status', 'route_existence_verified'),
    'api_observations': ('url', 'status_code', 'document_kind', 'links', 'records'),
    'scenario_validations': ('name', 'validated', 'reason', 'evidence_ref'),
    'services': ('host', 'port', 'protocol', 'service', 'product', 'version', 'tunnel', 'status'),
    'http_services': ('url', 'status_code', 'title', 'tech', 'webserver'),
    'candidates': ('template_id', 'url', 'severity', 'finding_type', 'status'),
    'browser_evidence': ('url', 'title', 'status_code', 'text_excerpt', 'links'),
    'idor_findings': ('scenario', 'target', 'owner_status', 'other_status', 'verification_status',
                      'fixture_validated', 'expected_behavior', 'actual_behavior', 'reason'),
    'nuclei_template_selections': ('target', 'strategy', 'tags', 'execution_status', 'policy'),
    'web_routes': ('url', 'method', 'kind', 'static_asset', 'api_like', 'status_code'),
    'probe_traces': ('url', 'method', 'parameter', 'payload', 'control', 'status_code', 'content_type', 'detected'),
}


def project(kind, row):
    return {key: row.get(key) for key in FIELDS[kind] if key in row}


def evidence_key(kind, row):
    data = json.dumps(project(kind, row), sort_keys=True, default=str, separators=(',', ':'))
    return kind + ':' + hashlib.sha256(data.encode()).hexdigest()[:16]


def prioritize(kind, rows, state):
    fresh = set(state.get('recent_evidence_keys', []))
    window = state.get('scope_window', [])
    last = state.get('attempted_actions', [])[-1:]
    active = {a.get('target') for a in last} | set(window)
    visited_documents = {endpoint_key(value)[:4] for value in state.get('discovered_documents', [])
                         if isinstance(value, str) and endpoint_key(value)}
    def score(index_row):
        index, row = index_row
        url = row.get('url') or row.get('target')
        key = endpoint_key(url) if url else None
        relevant = url in active or row.get('host') in active
        if key:
            relevant = relevant or any(endpoint_key(value) and endpoint_key(value)[:3] == key[:3]
                                       for value in active if isinstance(value, str))
        return (evidence_key(kind, row) in fresh, relevant,
                row.get('verification_status') == 'verified',
                not row.get('static_asset', False),
                kind != 'web_routes' or key is None or key[:4] not in visited_documents,
                bool(row.get('api_like', False)), index)
    return [project(kind, row) for _, row in sorted(enumerate(rows), key=score, reverse=True)]


def grouped_probe_traces(state, rows=None, limit=12):
    """Token-efficient model view: one row per response behaviour.

    Evidence deduplication for the model is separate from the full request audit:
    every distinct request remains a row in ``probe_traces`` (and in
    ``request_audit``), but requests that produced the same status and body are
    collapsed here into one row that lists the values tried. This keeps the
    planner context small without deleting any critical evidence from the state,
    the report or the per-request ``evidence_refs``.
    """
    rows = list(state.get('probe_traces', []) if rows is None else rows)
    order = {id(row): index for index, row in enumerate(prioritize('probe_traces', rows, state))}
    groups = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = (row.get('path_key'), row.get('method'), row.get('status_code'), row.get('body_sha256'))
        groups.setdefault(key, []).append(row)
    ranked = sorted(groups.values(), key=lambda group: min(order.get(id(row), 10 ** 6) for row in group))
    context = []
    for group in ranked[:limit]:
        representative = group[0]
        projected = dict(project('probe_traces', representative))
        refs = [evidence_key('probe_traces', row) for row in group]
        values = list(dict.fromkeys(str(row.get('payload') or '') for row in group))
        detected = {}
        for row in group:
            for item in row.get('detected', []) or []:
                detected[(item.get('category'), item.get('signature'))] = item
        projected.update({
            'parameter': ','.join(sorted({name for row in group
                                          for name in str(row.get('parameter') or '').split(',') if name})),
            'control': all(bool(row.get('control')) for row in group),
            'detected': list(detected.values()),
            'attempts': len(group),
            'values_tried': values[:8],
            'identical_responses': len(group) > 1,
            'evidence_ref': refs[0], 'evidence_refs': refs,
        })
        context.append(projected)
    return context


def web_route_context(state, rows=None, limit=30):
    """Application routes first, static asset references summarised as counts."""
    rows = list(state.get('web_routes', []) if rows is None else rows)
    ordered = prioritize('web_routes', rows, state)
    meaningful = [row for row in ordered if not row.get('static_asset')]
    static = [row for row in ordered if row.get('static_asset')]
    return meaningful[:limit], {'total': len(rows), 'application': len(meaningful),
                                'static_assets': len(static),
                                'api_like': sum(1 for row in ordered if row.get('api_like'))}


def group_traces_by_path(rows):
    """Group probe evidence by path for stagnation checks on the full audit."""
    groups = {}
    for row in rows:
        if isinstance(row, dict):
            groups.setdefault((row.get('path_key'), str(row.get('method') or '').upper()), []).append(row)
    return groups



def marginal_tokens(state, result):
    """Tokenizer estimate of the actual projected delta, never full proof JSON bytes."""
    import litellm
    values = {}
    for kind in FIELDS:
        old = {evidence_key(kind, row) for row in state.get(kind, [])}
        delta = [project(kind, row) for row in result.get(kind, []) if evidence_key(kind, row) not in old]
        if delta:
            values[kind] = delta
    content = json.dumps(values, ensure_ascii=False, separators=(',', ':'))
    try:
        model = state.get('llm_model', 'ollama_chat/qwen3:14b')
        count = lambda text: litellm.token_counter(model=model, messages=[{'role': 'user', 'content': text}])
        return max(0, count(content) - count('{}')), 'projected_delta_tokenizer'
    except Exception:
        return (len(content.encode()) + 2) // 3, 'projected_delta_utf8_estimate'
