"""Deterministic hypothesis lifecycle.

Hypotheses are candidate explanations, never findings. The model proposes and
tests them; this module keeps their status grounded in recorded evidence only.
"""
import re

from src.adaptix.evidence.web_signatures import CATEGORY_TITLES, build_findings
from src.adaptix.security.scope import endpoint_key
# Common analyst spellings that do not reduce to the canonical slug. This is a
# vocabulary for *equivalence*, not a catalogue: an unknown class keeps its own
# normalized slug instead of being forced into one of these.
ALIASES = {
    'sqli': 'sql_injection', 'xss': 'cross_site_scripting', 'csrf': 'security_misconfiguration',
    'idor': 'idor_bola', 'bola': 'idor_bola', 'bfla': 'broken_access_control',
    'id_or': 'idor_bola', 'id or': 'idor_bola', 'insecure_direct_object_reference': 'idor_bola',
    'broken_object_level_authorization': 'idor_bola', 'broken_object_authorization': 'idor_bola',
    'object_level_authorization': 'idor_bola', 'object_authorization': 'idor_bola',
    'bola_idor': 'idor_bola', 'idorbola': 'idor_bola', 'owasp api1': 'idor_bola',
    'broken_function_level_authorization': 'broken_access_control',
    'ssrf': 'server_side_request_forgery', 'nosql': 'nosql_injection',
    'traversal': 'path_traversal', 'lfi': 'path_traversal', 'jwt': 'jwt_weakness',
    'auth bypass': 'authentication', 'authentication bypass': 'authentication',
    'info disclosure': 'sensitive_information_exposure',
    'information disclosure': 'sensitive_information_exposure',
    'misconfiguration': 'security_misconfiguration', 'upload': 'file_upload',
}
# Standard OWASP Top 10 / API prefixes an analyst may paste verbatim. Stripping them
# keeps equivalent classes together without limiting the set of classes to a list.
_STANDARD_PREFIX = re.compile(r'^(?:owasp[_\s-]*(?:api[_\s-]*)?(?:top[_\s-]*10)?[_\s-]*)?'
                              r'(?:\d{4}|[a-z]\d{1,2})[_\s-]*(?=[a-z])')


# Reconnaissance tasks are not vulnerability hypotheses. The action that performed
# the task is already recorded as an attempt and an outcome; recording the task
# again as a "hypothesis" only mixes two different kinds of work.
RECON_TASK = re.compile(r'(?:_discovery|_enumeration|_scanning|_assessment|_analysis|_mapping|'
                        r'_observation|_reconnaissance|_inventory)$|^(?:reconnaissance|'
                        r'information_gathering|baseline|reachability)$')


def _norm(value):
    return re.sub(r'[^a-z0-9]+', '_', str(value or '').lower()).strip('_')


def normalize_class(text):
    """Slug for a class name the model supplied, without narrowing it to a catalogue."""
    return _STANDARD_PREFIX.sub('', _norm(text))


def categorize(text, fallback=None):
    """Map free analyst text to a canonical finding category slug.

    Equivalent spellings of the same class collapse together (``id_or``, ``IDOR``
    and ``broken_object_level_authorization`` all become ``idor_bola``). Prose that
    names no known class returns the caller's fallback, so an unrecognised
    intention is not recorded as a vulnerability class.
    """
    normalized = _norm(text)
    spaced = ' ' + str(text or '').lower() + ' '
    if not normalized:
        return fallback
    for alias, slug in ALIASES.items():
        if alias in normalized or (' ' + alias + ' ') in spaced:
            return slug
    for slug in CATEGORY_TITLES:
        if slug in normalized:
            return slug
    return fallback


def _target_key(value):
    """Path-level identity so a probe payload still matches its base endpoint."""
    key = endpoint_key(value) if '://' in str(value or '') else None
    return key[:4] if key else None


def merge_hypotheses(existing, proposed, valid_refs=None):
    """Append novel (category, target) hypotheses; drop unknown evidence refs.

    Model-supplied category spellings are canonicalized so the same class is not
    recorded twice under a free-text and a slug variant. Two proposals are the same
    hypothesis when they share a canonical category and a path-level target, so
    ``?key=1``..``?key=6`` collapse to one entry. A proposal whose every cited
    evidence_ref is unknown is dropped rather than recorded without provenance.
    """
    hypotheses = [dict(h) for h in existing]
    seen = {(h.get('category'), _target_key(h.get('target')) or h.get('target')) for h in hypotheses}
    for item in proposed:
        # An explicitly named vulnerability class is normalized, never dropped: the
        # set of classes the agent may investigate is not limited to the ones listed
        # here. A reconnaissance task is the one thing that is filtered out.
        category = categorize(item.get('category')) or normalize_class(item.get('category'))
        if RECON_TASK.search(category):
            continue
        key = (category, _target_key(item.get('target')) or item.get('target'))
        if key in seen:
            continue
        original = list(item.get('evidence_refs', []))
        refs = original
        if valid_refs is not None:
            refs = [ref for ref in refs if ref in valid_refs]
            if original and not refs:
                # Non-empty but entirely unverifiable provenance: drop, do not invent.
                continue
        hypotheses.append({**item, 'category': category, 'evidence_refs': refs, 'status': 'candidate'})
        seen.add(key)
    return hypotheses


def hypotheses_from_actions(actions):
    """Capture a model's own stated per-action hypothesis when it names a vuln class.

    Only known categories are derived; an unclassifiable intent is left to the
    structured hypotheses field rather than recorded as noise.
    """
    derived = []
    for action in actions:
        category = categorize(action.get('hypothesis'))
        target = action.get('target')
        if not category or not target:
            continue
        derived.append({'category': category, 'target': target,
                        'rationale': str(action.get('hypothesis'))[:400], 'evidence_refs': []})
    return derived


def evidence_hypotheses(state, valid_refs=None):
    """Derive candidate hypotheses from deterministic signatures already recorded.

    A detected signature in a stored probe trace is objective evidence that a
    vulnerability *class* is plausible at that endpoint. This never fabricates a
    class without evidence and always cites the trace that produced it.
    """
    derived, seen = [], set()
    from src.adaptix.agents.evidence_context import evidence_key
    for trace in state.get('probe_traces', []):
        if not isinstance(trace, dict):
            continue
        target = trace.get('path_key') or trace.get('url')
        if not target:
            continue
        for detection in trace.get('detected', []):
            category = detection.get('category')
            key = (category, target)
            if not category or key in seen:
                continue
            seen.add(key)
            signatures = sorted({d.get('signature') for d in trace.get('detected', [])
                                 if d.get('category') == category and d.get('signature')})
            refs = [evidence_key('probe_traces', trace)]
            if valid_refs is not None:
                refs = [ref for ref in refs if ref in valid_refs]
            derived.append({'category': category, 'target': target,
                            'rationale': f'Observed deterministic signature(s) {signatures} at {target}; '
                                         f'status {trace.get("status_code")} corroborates testing, not exploitation',
                            'evidence_refs': refs})
    return derived


def diagnose_hypotheses(state, model=0, actions=0, evidence=0, merged=0):
    """Explain where the current hypothesis set came from, or why it is empty.

    The diagnostic distinguishes a model omission from a schema/context drop or a
    deterministic-synthesis gap so replanning can react to the real cause.
    """
    observed = [field for field in ('probe_traces', 'web_routes', 'browser_evidence',
                                    'http_services', 'api_observations', 'scenario_candidates')
                if state.get(field)]
    signatures = sum(1 for row in state.get('probe_traces', [])
                     if isinstance(row, dict) and row.get('detected'))
    if merged:
        origin = 'model' if model else 'evidence' if evidence else 'action_hint'
        reason = 'hypotheses_present'
    elif not observed:
        origin, reason = 'none', 'no_observations_yet'
    elif model == 0 and actions == 0 and signatures == 0:
        origin, reason = 'model', 'model_omitted_hypotheses_and_no_classifiable_action_hint'
    elif signatures and evidence == 0:
        origin, reason = 'planner', 'signature_synthesis_skipped'
    else:
        origin, reason = 'model', 'model_omitted_hypotheses'
    return {'observed_context': observed, 'probe_signatures': signatures,
            'proposed_by_model': model, 'derived_from_action_hints': actions,
            'derived_from_evidence': evidence, 'total': merged,
            'origin': origin, 'reason': reason}


AUTHORIZATION_CATEGORIES = ('idor_bola', 'broken_access_control')


def _has_authorization_evidence(finding):
    """Authorization support needs two distinct identities, not a status or label."""
    owner, other = finding.get('owner_identity'), finding.get('other_identity')
    if owner and other and owner != other:
        return True
    reproduction = finding.get('reproduction') or {}
    identities = {str(value) for value in (reproduction.get('identities') or []) if value}
    return len(identities) >= 2


def _status(hypothesis, findings, traces, attempted):
    category = _norm(hypothesis.get('category'))
    key = _target_key(hypothesis.get('target'))
    related = [f for f in findings if _norm(f.get('category')) == category
               and (key is None or _target_key(f.get('target')) == key)]
    statuses = {f.get('verification_status') for f in related}
    if 'confirmed' in statuses:
        if category in AUTHORIZATION_CATEGORIES and not any(_has_authorization_evidence(f) for f in related
                                                            if f.get('verification_status') == 'confirmed'):
            # An authorization claim without two-identity evidence stays unresolved.
            return 'inconclusive'
        return 'supported'
    if 'false_positive' in statuses:
        return 'refuted'
    if related:
        return 'inconclusive'
    if key and any(_target_key(t.get('url')) == key for t in traces):
        return 'inconclusive'
    if any(_norm(a.get('hypothesis')) == category or categorize(a.get('hypothesis')) == category
           for a in attempted):
        return 'testing'
    return hypothesis.get('status', 'candidate')


def update_hypotheses(state):
    """Recompute statuses from stored findings, traces and attempted actions."""
    findings = build_findings(state)
    # Authorization evidence lives in reflector findings, not probe signatures;
    # expose it so an idor_bola/broken_access_control hypothesis is only 'supported'
    # when two-identity ownership evidence exists.
    from src.adaptix.agents.reflector import collect_findings
    for row in collect_findings(state).get('verified_findings', []):
        if row.get('finding_type') == 'broken_object_level_authorization':
            findings.append({'category': 'idor_bola', 'target': row.get('target'),
                             'verification_status': 'confirmed',
                             'owner_identity': row.get('owner_identity'), 'other_identity': row.get('other_identity')})
    traces = state.get('probe_traces', [])
    attempted = state.get('attempted_actions', [])
    result = []
    for hypothesis in state.get('hypotheses', []):
        item = dict(hypothesis)
        # Recomputed from stored evidence only; equivalent spellings of the same class
        # stay collapsed after a restart or an externally supplied hypothesis list.
        item['category'] = categorize(item.get('category')) or normalize_class(item.get('category'))
        item['status'] = _status(item, findings, traces, attempted)
        result.append(item)
    return result
