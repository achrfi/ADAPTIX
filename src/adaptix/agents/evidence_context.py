"""One projection for planner context, novelty and marginal token calibration."""
import hashlib
import json
from urllib.parse import urlsplit
from src.adaptix.security.scope import endpoint_key

FIELDS = {
    'api_observations': ('url', 'status_code', 'document_kind', 'links', 'records'),
    'scenario_validations': ('name', 'validated', 'reason', 'evidence_ref'),
    'services': ('host', 'port', 'protocol', 'service', 'product', 'version', 'tunnel', 'status'),
    'http_services': ('url', 'status_code', 'title', 'tech', 'webserver'),
    'candidates': ('template_id', 'url', 'severity', 'finding_type', 'status'),
    'browser_evidence': ('url', 'title', 'status_code', 'text_excerpt', 'links'),
    'idor_findings': ('scenario', 'target', 'owner_status', 'other_status', 'verification_status',
                      'fixture_validated', 'expected_behavior', 'actual_behavior', 'reason'),
    'nuclei_template_selections': ('target', 'strategy', 'tags', 'execution_status', 'policy'),
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
    def score(index_row):
        index, row = index_row
        url = row.get('url') or row.get('target')
        key = endpoint_key(url) if url else None
        relevant = url in active or row.get('host') in active
        if key:
            relevant = relevant or any(endpoint_key(value) and endpoint_key(value)[:3] == key[:3]
                                       for value in active if isinstance(value, str))
        return (evidence_key(kind, row) in fresh, relevant,
                row.get('verification_status') == 'verified', index)
    return [project(kind, row) for _, row in sorted(enumerate(rows), key=score, reverse=True)]


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
