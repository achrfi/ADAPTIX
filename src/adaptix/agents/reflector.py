"""Evidence triage; server reachability never confirms a vulnerability."""
import time
from src.adaptix.security.scope import endpoint_key
from src.adaptix.workflow.events import log

# External (future) vulnerability-specific verifier may supply explicit replay results.
# Untrusted Nuclei severity and HTTP status never promote a candidate by themselves.


def _proof_for(candidate, proofs):
    for proof in proofs:
        if (proof.get('template_id') == candidate.get('template_id')
                and endpoint_key(proof.get('url', '')) == endpoint_key(candidate.get('url', ''))
                and proof.get('verification_method') in ('deterministic_replay', 'manual_review')
                and proof.get('evidence_ref')
                and proof.get('result') in ('confirmed', 'refuted')):
            return proof
    return None


def reflection_verification(state):
    http_by_url = {endpoint_key(item.get('url', '')): item for item in state.get('http_services', [])}
    verified, rejected, inconclusive = [], [], []
    for idx, candidate in enumerate(state.get('candidates', []), start=1):
        observation = http_by_url.get(endpoint_key(candidate.get('url', '')))
        proof = _proof_for(candidate, state.get('verification_evidence', []))
        entry = {
            'evidence_id': f'EV-{idx:03d}', 'source_tool': 'nuclei',
            'target': candidate.get('url', ''), 'timestamp': int(time.time()),
            'template_id': candidate.get('template_id', ''),
            'severity': candidate.get('severity', 'info'),
            'actual_observation': ({'status_code': observation.get('status_code'),
                                    'title': observation.get('title', '')} if observation else None),
            'verification_evidence': proof, 'confidence': 'unconfirmed',
        }
        if candidate.get('finding_type') == 'service_reachability' or candidate.get('template_id') == 'adaptix-http-baseline':
            entry.update(verification_status='rejected', reason='reachability baseline is not a vulnerability')
            rejected.append(entry)
        elif proof and proof['result'] == 'confirmed':
            entry.update(verification_status='verified', confidence='supported',
                         reason='vulnerability-specific replay/review evidence provided')
            verified.append(entry)
        elif proof and proof['result'] == 'refuted':
            entry.update(verification_status='rejected', reason='vulnerability-specific check refuted candidate')
            rejected.append(entry)
        else:
            entry.update(verification_status='inconclusive',
                         reason='HTTP status/severity do not prove or disprove a vulnerability; independent check needed')
            inconclusive.append(entry)
    return {
        'verified_findings': verified, 'rejected_findings': rejected,
        'inconclusive_findings': inconclusive,
        'events': log(state, f'Reflection: {len(verified)} verified, {len(rejected)} non-findings/refuted, '
                             f'{len(inconclusive)} inconclusive'),
    }
