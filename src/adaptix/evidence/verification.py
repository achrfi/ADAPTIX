"""Validate provenance and minimum proof, not a scanner's severity label."""
import hashlib
import hmac
import json
import time
import re
from pathlib import Path
from src.adaptix.config import ROOT
from src.adaptix.security.authorization import _key, _payload_bytes
from src.adaptix.security.scope import endpoint_key
from src.adaptix.evidence.storage import artifact_path, save_text
from src.adaptix.evidence.sanitize import sanitize, scenario_secrets


def replay_result(record):
    """The current automated verifier supports private-object authorization only."""
    if record.get('verification_basis') != 'private_object_access':
        return None
    truth = record.get('ground_truth', {})
    requests, responses = record.get('requests', []), record.get('responses', [])
    if not (len(requests) == len(responses) == 2 and truth.get('private') is True
            and truth.get('identities_valid') is True and truth.get('owner') == requests[0].get('identity')
            and str(truth.get('object_id')) == str(record.get('object_id'))
            and requests[0].get('identity') and requests[1].get('identity')
            and requests[0]['identity'] != requests[1]['identity']
            and all(r.get('method') == 'GET' and endpoint_key(r.get('url', '')) == endpoint_key(record.get('url', '')) for r in requests)):
        return None
    owner, other = responses
    if not 200 <= owner['status_code'] < 300:
        return None
    if other['status_code'] in (401, 403, 404):
        return 'refuted'
    if owner['status_code'] == other['status_code'] and owner['body_sha256'] == other['body_sha256']:
        return 'confirmed'
    return None


def complete_trace(record):
    requests, responses = record.get('requests', []), record.get('responses', [])
    return (bool(requests) and len(requests) == len(responses)
            and all(r.get('method') and endpoint_key(r.get('url', '')) for r in requests)
            and all(isinstance(r.get('status_code'), int) and 100 <= r['status_code'] <= 599
                    and re.fullmatch('[0-9a-f]{64}', r.get('body_sha256', ''))
                    and isinstance(r.get('headers'), dict) and isinstance(r.get('body_excerpt'), str) for r in responses))


def write_verification_record(state, record):
    """Worker-local verifier/reviewer interface, never a model-selected result label."""
    record = sanitize({**record, 'run_id': state['run_id'], 'timestamp': int(time.time())}, scenario_secrets(state))
    if not complete_trace(record) or not all(record.get(k) for k in ('steps', 'expected_behavior', 'actual_behavior')):
        raise ValueError('Verification needs complete request/response trace and expected/actual behavior')
    if record.get('verification_method') == 'deterministic_replay':
        result = replay_result(record)
        if result is None:
            raise ValueError('No supported vulnerability-specific replay proof; use signed human review')
        record['result'] = result
    elif (record.get('verification_method') != 'manual_review' or not record.get('reviewer')
          or not record.get('reason') or record.get('result') not in ('confirmed', 'refuted')):
        raise ValueError('Manual review needs reviewer attribution')
    payload = {'record': record, 'signature': hmac.new(_key(), _payload_bytes(record), hashlib.sha256).hexdigest()}
    path = artifact_path(state, 'verification', record['url'] + '#' + record['template_id'], 'json')
    save_text(path, json.dumps(payload, ensure_ascii=False, indent=2))
    return {'template_id': record['template_id'], 'url': record['url'],
            'verification_method': record['verification_method'], 'result': record['result'],
            'run_id': record['run_id'], 'timestamp': record['timestamp'],
            'evidence_ref': str(path), 'evidence_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def load_valid_proof(candidate, proof, run_id=None):
    """Return the authenticated record, so reporting uses its trace and identities."""
    try:
        path = Path(proof['evidence_ref']).resolve()
        if not path.is_relative_to((ROOT / 'artifacts' / 'scans').resolve()):
            return None
        raw = path.read_bytes()
        if len(raw) > 1_000_000 or hashlib.sha256(raw).hexdigest() != proof.get('evidence_sha256'):
            return None
        envelope = json.loads(raw)
        record = envelope['record']
        signature = hmac.new(_key(), _payload_bytes(record), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, envelope['signature']):
            return None
        if not (record.get('template_id') == candidate.get('template_id')
                and endpoint_key(record.get('url', '')) == endpoint_key(candidate.get('url', ''))
                and record.get('result') == proof.get('result') in ('confirmed', 'refuted')
                and record.get('verification_method') == proof.get('verification_method')
                and record.get('run_id') == proof.get('run_id') and record.get('timestamp') == proof.get('timestamp')
                and (run_id is None or record.get('run_id') == run_id)
                and complete_trace(record) and record.get('steps')
                and record.get('expected_behavior') and record.get('actual_behavior') and record.get('timestamp')):
            return None
        if record['verification_method'] == 'manual_review':
            return record if record.get('reviewer') and record.get('reason') else None
        if record['verification_method'] != 'deterministic_replay':
            return None
        return record if replay_result(record) == record['result'] else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def valid_proof(candidate, proof, run_id=None):
    return load_valid_proof(candidate, proof, run_id) is not None
