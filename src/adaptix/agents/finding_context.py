"""Surface verified findings to the planner so the next decision can escalate on them.

Measured defect: the planner payload carried only `idor_findings`. A verified SQL
injection or DOM XSS never reached the prompt, so a decision like "SQL is indicated,
try a higher-impact payload" was structurally impossible - the model could not see the
SQL finding at all. This adds a bounded, cited view of every verified finding plus the
concrete escalation options for each class.
"""
CLASS_ESCALATIONS = {
    'sql_injection': (
        'run union_extract: it discovers the UNION column count instead of guessing it, '
        'then extracts user emails, password hashes and the database version as proof of impact',
        'stacked statements where the driver allows them',
        'boolean/time blind confirmation on the same parameter',
    ),
    'nosql_injection': (
        'operator injection ($ne/$gt) against the same parameter',
        'authentication bypass with a credential object',
    ),
    'broken_object_level_authorization': (
        'enumerate adjacent object identifiers as the non-owner',
        'attempt write or delete on the foreign object',
        'check whether the same object is reachable unauthenticated',
    ),
    'cross_site_scripting': (
        'session/token theft impact if the script runs authenticated',
        'stored variant at the same sink',
        'privileged action performed through the injected script',
    ),
    'path_traversal': ('read a known file outside the served root',),
    'server_side_request_forgery': ('reach an internal-only endpoint or metadata service',),
}

MAX_FINDINGS = 6


def _sealed_index(state):
    """Sealed records indexed by the URL they prove.

    Measured: `injection_findings` and `script_findings` carry no evidence ref of their
    own; the signed record lives in the run-level `verification_evidence` list, keyed by
    URL. Without this join the planner saw blank refs, read them as "no proof", and
    refused to escalate a finding that was in fact verified.
    """
    index = {}
    for record in state.get('verification_evidence') or []:
        if not isinstance(record, dict):
            continue
        url = str(record.get('url') or '')
        if url and record.get('evidence_ref'):
            index[url] = record['evidence_ref']
    return index


def _evidence_ref(finding, sealed=None):
    """The signed evidence path for a finding, wherever the record keeps it."""
    direct = finding.get('evidence_ref')
    if direct:
        return direct
    proof = finding.get('verification_evidence')
    if isinstance(proof, dict) and proof.get('evidence_ref'):
        return proof['evidence_ref']
    if isinstance(proof, list):
        for row in proof:
            if isinstance(row, dict) and row.get('evidence_ref'):
                return row['evidence_ref']
    target = str(finding.get('target') or '')
    if sealed and target:
        if target in sealed:
            return sealed[target]
        # A probe records the injected URL; the sealed record may name the same path
        # with the clean parameter value. Match on the path only as a last resort.
        base = target.split('?')[0]
        for url, ref in sealed.items():
            if url.split('?')[0] == base:
                return ref
    return ''


def _row(key, finding, sealed=None):
    """A compact, cited view: the planner needs the class, the endpoint and the next step."""
    target = str(finding.get('target') or '')[:200]
    parameter = finding.get('parameter') or finding.get('object_id') or ''
    payload = finding.get('payload') or finding.get('marker') or ''
    return {
        'class': key,
        'target': target,
        'parameter': str(parameter)[:60],
        'payload': str(payload)[:120],
        'verification_basis': finding.get('verification_basis') or '',
        'severity': finding.get('severity') or '',
        'evidence_ref': str(_evidence_ref(finding, sealed))[:160],
        'escalation_options': list(CLASS_ESCALATIONS.get(key, ()))[:3],
    }


def verified_findings(state):
    """Every verified finding the planner may act on, grouped by class, deduplicated."""
    sealed = _sealed_index(state)
    grouped = {}
    sources = (('broken_object_level_authorization', state.get('idor_findings') or []),
               ('sql_injection', state.get('injection_findings') or []),
               ('cross_site_scripting', state.get('script_findings') or []),
               ('path_traversal', state.get('traversal_findings') or []),
               ('server_side_request_forgery', state.get('ssrf_findings') or []))
    for key, rows in sources:
        for finding in rows:
            if not isinstance(finding, dict):
                continue
            if finding.get('verification_status') not in ('verified', None):
                continue
            if finding.get('result') == 'refuted':
                continue
            row = _row(key, finding, sealed)
            signature = (key, row['target'], row['parameter'])
            grouped.setdefault(signature, row)
    # Verified findings first, then the ones that name a payload (most actionable).
    ordered = sorted(grouped.values(),
                     key=lambda r: (not r['evidence_ref'], not r['payload'], r['class']))
    return ordered[:MAX_FINDINGS]


def escalation_block(state):
    """Payload fragment: what is already proven and which escalation is available."""
    rows = verified_findings(state)
    if not rows:
        return {}
    return {
        'verified_findings': rows,
        'finding_escalation_policy': (
            'A verified finding is a lead, not a conclusion. While the objective is not '
            'achieved, a verified class that has not been escalated requires one more '
            'action on the SAME target and parameter, naming the escalation option you '
            'chose in the action reason. For sql_injection call the union_extract tool '
            'instead of http_request: '
            'it derives the UNION column count from the server response, while a '
            'hand-written UNION payload fails whenever the count is wrong and the failure '
            'teaches nothing. '
            'Do not re-send the payload that already proved the issue and do not move to '
            'a new endpoint instead. Returning actions=[] is correct only when every '
            'escalation option for every verified class is already exhausted, infeasible '
            'without missing context, or would fall outside scope - say which, and why.'),
    }
