"""Evidence triage; server reachability never confirms a vulnerability."""
import time
from src.adaptix.security.scope import endpoint_key
from src.adaptix.workflow.events import log
from src.adaptix.evidence.verification import load_valid_proof
from src.adaptix.evidence.web_signatures import build_findings, REPORT_STATUS

# External (future) vulnerability-specific verifier may supply explicit replay results.
# Untrusted Nuclei severity and HTTP status never promote a candidate by themselves.


def _proof_for(candidate, proofs, run_id=None):
    for proof in proofs:
        if (proof.get('template_id') == candidate.get('template_id')
                and endpoint_key(proof.get('url', '')) == endpoint_key(candidate.get('url', ''))
                and proof.get('verification_method') in ('deterministic_replay', 'manual_review')
                and proof.get('evidence_ref')
                and proof.get('result') in ('confirmed', 'refuted')):
            record = load_valid_proof(candidate, proof, run_id)
            if record is not None:
                return proof, record
    return None, None


def _private_object_evidence(record):
    """Two distinct identities plus a decisive ownership response pattern, or None.

    A manual-review label without an identity trace is not authorization proof, and
    the promotion must never index into a missing/partial ``requests`` list.
    """
    if not record or record.get('verification_basis') != 'private_object_access':
        return None
    requests = [r for r in (record.get('requests') or []) if isinstance(r, dict)]
    if len(requests) < 2:
        return None
    owner, other = requests[0].get('identity'), requests[1].get('identity')
    if not owner or not other or owner == other:
        return None
    responses = record.get('responses') or []
    if len(responses) >= 2:
        owner_response, other_response = responses[0], responses[1]
        owner_ok = isinstance(owner_response.get('status_code'), int) and 200 <= owner_response['status_code'] < 300
        other_blocked = other_response.get('status_code') in (401, 403, 404)
        same_body = (owner_response.get('status_code') == other_response.get('status_code')
                     and owner_response.get('body_sha256') == other_response.get('body_sha256'))
        if not owner_ok or not (other_blocked or same_body):
            return None
    return {'owner_identity': owner, 'other_identity': other}


def collect_findings(state):
    """Unify scanner and IDOR results; authenticate proof and count each assessment once."""
    http_by_url = {endpoint_key(item.get('url', '')): item for item in state.get('http_services', [])}
    findings = {}

    def add(entry):
        if entry.get('finding_type') == 'broken_object_level_authorization':
            key = ('idor', endpoint_key(entry.get('target', '')),
                   entry.get('owner_identity'), entry.get('other_identity'))
        else:
            key = ('candidate', entry.get('template_id'), endpoint_key(entry.get('target', '')))
        previous = findings.get(key)
        if previous and previous.get('verification_evidence') and not entry.get('verification_evidence'):
            return
        findings[key] = entry

    for idx, candidate in enumerate(state.get('candidates', []), start=1):
        observation = http_by_url.get(endpoint_key(candidate.get('url', '')))
        proof, record = _proof_for(candidate, state.get('verification_evidence', []), state.get('run_id'))
        private = _private_object_evidence(record)
        idor_claim = candidate.get('finding_type') == 'broken_object_level_authorization'
        entry = {
            'evidence_id': f'EV-{idx:03d}', 'source_tool': candidate.get('source_tool', 'nuclei'),
            'target': candidate.get('url', ''), 'timestamp': int(time.time()),
            'template_id': candidate.get('template_id', ''),
            'severity': candidate.get('severity', 'info'),
            'actual_observation': ({'status_code': observation.get('status_code'),
                                    'title': observation.get('title', '')} if observation else None),
            'verification_evidence': proof, 'confidence': 'unconfirmed',
        }
        if candidate.get('finding_type') == 'service_reachability' or candidate.get('template_id') == 'adaptix-http-baseline':
            entry.update(verification_status='rejected', reason='reachability baseline is not a vulnerability')
        elif proof and proof['result'] == 'confirmed' and idor_claim and private is None:
            # An authorization claim cannot be verified by a review label alone; it
            # needs two distinct identities and a decisive ownership response.
            entry.update(verification_status='inconclusive', confidence='unconfirmed',
                         reason='Authorization claim lacks two-identity ownership evidence; a review label alone cannot verify it')
        elif proof and proof['result'] == 'confirmed':
            entry.update(verification_status='verified', confidence='supported',
                         reason='vulnerability-specific replay/review evidence provided')
        elif proof and proof['result'] == 'refuted':
            entry.update(verification_status='rejected', reason='vulnerability-specific check refuted candidate')
        else:
            entry.update(verification_status='inconclusive',
                         reason='HTTP status/severity do not prove or disprove a vulnerability; independent check needed')
        if private:
            entry.update(finding_type='broken_object_level_authorization', **private)
        add(entry)

    for finding in state.get('idor_findings', []):
        if not isinstance(finding, dict):
            continue
        candidate = {'template_id': finding.get('template_id'), 'url': finding.get('target', '')}
        proof = finding.get('verification_evidence')
        proof, record = _proof_for(candidate, [proof] if isinstance(proof, dict) else [], state.get('run_id'))
        entry = {**(record or finding), 'source_tool': 'idor_test',
                 'target': finding.get('target', ''),
                 'finding_type': 'broken_object_level_authorization',
                 'verification_evidence': proof, 'severity': finding.get('severity', 'unknown')}
        if record:
            entry.update(target=record['url'], evidence_ref=proof['evidence_ref'],
                         raw_evidence_ref=finding.get('evidence_ref'),
                         verification_status='verified' if proof['result'] == 'confirmed' else 'rejected',
                         confidence='supported')
        else:
            entry.update(verification_status='inconclusive', confidence='unconfirmed')
            if finding.get('verification_status') != 'inconclusive':
                entry['reason'] = 'IDOR proof missing, invalid or from another run; rerun the two-identity check'
        add(entry)

    web_findings = build_findings(state)
    for index, finding in enumerate(web_findings, start=1):
        status = finding['verification_status']
        entry = {
            'evidence_id': f'EV-WEB-{index:03d}', 'source_tool': 'http_request',
            'target': finding.get('target'), 'timestamp': int(time.time()),
            'template_id': 'adaptix-' + str(finding.get('category')), 'severity': finding.get('severity'),
            'finding_type': finding.get('category'), 'category': finding.get('category'),
            'actual_observation': {'observations': finding.get('observations', []),
                                   'method': finding.get('method'), 'parameter': finding.get('parameter')},
            'verification_evidence': finding.get('reproduction'),
            'confidence': 'supported' if status == 'confirmed' else 'unconfirmed',
            'reason': finding.get('severity_rationale'), 'report_status': REPORT_STATUS.get(status, status.upper()),
            'web_finding': finding,
            'verification_status': {'confirmed': 'verified', 'false_positive': 'rejected'}.get(status, 'inconclusive'),
        }
        add(entry)

    result = {name: [entry for entry in findings.values() if entry['verification_status'] == status]
              for name, status in (('verified_findings', 'verified'), ('rejected_findings', 'rejected'),
                                   ('inconclusive_findings', 'inconclusive'))}
    result['findings'] = web_findings
    return result


def reflection_verification(state):
    from src.adaptix.agents.hypotheses import update_hypotheses
    from src.adaptix.agents.progress import stagnation_report
    groups = collect_findings(state)
    verified, rejected, inconclusive = (groups[name] for name in
                                        ('verified_findings', 'rejected_findings', 'inconclusive_findings'))
    stagnation = stagnation_report(state)
    consecutive = stagnation['consecutive_no_gain']
    blocked = [{'tool': row.get('tool'), 'target': row.get('target'),
                'code': row.get('code', ''), 'kind': row.get('kind', ''),
                'missing': row.get('missing', [])[:3]}
               for row in state.get('rejected_actions', [])[-6:]]
    completed = [{'tool': row.get('tool'), 'target': row.get('target')}
                 for row in state.get('attempted_actions', [])[-6:]]
    unfinished = [row.get('target') for row in inconclusive]
    if consecutive >= 2:
        guidance = ('Repeated actions added no measured progress (' + str(consecutive) +
                    ' in a row). Change what the next action is evidence about - a different endpoint, a different '
                    'question, or a different hypothesis - or stop with the recorded limitation.')
    elif consecutive == 1:
        guidance = ('The last action added no measured progress; an identical or parameter-only repeat of it will '
                    'not either. Change the evidence source or the question.')
    elif blocked:
        guidance = ('Some actions were not executed. Each blocked action records which prerequisite was missing; '
                    'choose an action whose prerequisites the run already satisfies instead of repeating one.')
    else:
        guidance = 'Choose the next action from current evidence; verify uncertainty or stop with limitations.'
    return {
        'hypotheses': update_hypotheses(state),
        'hypothesis_diagnostics': state.get('planner_metrics', {}).get('hypothesis_diagnostics', {}),
        'reflection': {'progress': len(state.get('attempted_actions', [])),
                       'uncertainty': unfinished,
                       'errors': state.get('errors', [])[-8:],
                       'last_action': state.get('attempted_actions', [])[-1:],
                       'last_outcome': stagnation['recent'][-1:],
                       'consecutive_no_gain': consecutive,
                       'policy_feedback': state.get('policy_feedback', []),
                       'blocked_actions': blocked,
                       'completed_actions': completed,
                       'guidance': guidance},
        **groups,
        'events': log(state, f'Reflection: {len(verified)} verified, {len(rejected)} non-findings/refuted, '
                             f'{len(inconclusive)} inconclusive'),
    }
