"""Evidence triage; server reachability never confirms a vulnerability."""
import time
from src.adaptix.security.scope import endpoint_key
from src.adaptix.workflow.events import log
from src.adaptix.evidence.verification import load_valid_proof

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
        elif proof and proof['result'] == 'confirmed':
            entry.update(verification_status='verified', confidence='supported',
                         reason='vulnerability-specific replay/review evidence provided')
        elif proof and proof['result'] == 'refuted':
            entry.update(verification_status='rejected', reason='vulnerability-specific check refuted candidate')
        else:
            entry.update(verification_status='inconclusive',
                         reason='HTTP status/severity do not prove or disprove a vulnerability; independent check needed')
        if record and record.get('verification_basis') == 'private_object_access':
            entry.update(finding_type='broken_object_level_authorization',
                         owner_identity=record['requests'][0]['identity'],
                         other_identity=record['requests'][1]['identity'])
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

    return {name: [entry for entry in findings.values() if entry['verification_status'] == status]
            for name, status in (('verified_findings', 'verified'), ('rejected_findings', 'rejected'),
                                 ('inconclusive_findings', 'inconclusive'))}


def reflection_verification(state):
    groups = collect_findings(state)
    verified, rejected, inconclusive = (groups[name] for name in
        ('verified_findings', 'rejected_findings', 'inconclusive_findings'))
    return {
        'reflection': {'progress': len(state.get('attempted_actions', [])),
                       'uncertainty': [x['target'] for x in inconclusive],
                       'errors': state.get('errors', [])[-8:],
                       'last_action': state.get('attempted_actions', [])[-1:],
                       'policy_feedback': state.get('policy_feedback', []),
                       'guidance': 'Choose next action from current evidence; verify uncertainty or stop with limitations.'},
        **groups,
        'events': log(state, f'Reflection: {len(verified)} verified, {len(rejected)} non-findings/refuted, '
                             f'{len(inconclusive)} inconclusive'),
    }
