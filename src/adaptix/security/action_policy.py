"""An exact, signed human approval for state-changing capabilities, separate from scope."""
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from src.adaptix.security.authorization import _key, _payload_bytes
from src.adaptix.config import ROOT


def issue_action_approval(run_id, principal, tool, target, change_limit, ttl_seconds=300, destination=None, manifest_sha256=None):
    """Local human operator interface. Never exposed as a graph node or remote API."""
    if not all(isinstance(x, str) and x.strip() for x in (run_id, principal, tool, target, change_limit)):
        raise ValueError('Approval needs run, principal, action and a concrete change limit')
    if not 0 < ttl_seconds <= 3600:
        raise ValueError('Approval TTL must be within one hour')
    now = int(time.time())
    payload = {'kind': 'state_change_approval', 'approval_id': secrets.token_hex(12),
               'run_id': run_id, 'principal': principal, 'tool': tool, 'target': target,
               'change_limit': change_limit, 'issued_at': now, 'expires_at': now + ttl_seconds}
    record = {'payload': payload, 'signature': hmac.new(_key(), _payload_bytes(payload), hashlib.sha256).hexdigest()}
    if manifest_sha256 is not None:
        import re
        if not re.fullmatch('[0-9a-f]{64}', manifest_sha256):
            raise ValueError('Manifest SHA256 must be a complete hex digest')
        payload['manifest_sha256'] = manifest_sha256
        record['signature'] = hmac.new(_key(), _payload_bytes(payload), hashlib.sha256).hexdigest()
    path = Path(destination or ROOT / 'artifacts' / 'approvals' / (payload['approval_id'] + '.json'))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(record, stream, indent=2)
    return path


def approval_for(state, action, specification):
    """Risk comes from the trusted registry, never from the planner's claim."""
    if specification.get('risk', 'observe') != 'state_change':
        return {'required': False, 'result': 'allowed', 'operation': specification.get('operation', 'observe')}
    for path in state.get('action_approvals', []):
        try:
            record = json.loads(Path(path).read_text(encoding='utf-8'))
            p = record['payload']
            expected = hmac.new(_key(), _payload_bytes(p), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, record['signature']):
                continue
            if specification.get('manifest_sha256') and p.get('manifest_sha256') != specification['manifest_sha256']:
                continue
            if specification.get('manifest_sha256') and p.get('change_limit') != 'execute_manifest_once':
                continue
            if (p.get('kind') == 'state_change_approval' and p.get('run_id') == state.get('run_id')
                    and p.get('principal') == state.get('principal')
                    and p.get('tool') == action['tool'] and p.get('target') == action['target']
                    and p.get('issued_at', float('inf')) <= time.time() < p.get('expires_at', 0)
                    and p.get('change_limit')):
                return {'required': True, 'result': 'allowed', 'approval_id': p['approval_id'],
                        'change_limit': p['change_limit'], 'expires_at': p['expires_at']}
        except (OSError, ValueError, TypeError, KeyError):
            continue
    return {'required': True, 'result': 'denied', 'reason': 'No valid human approval for this run/action'}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Local human approval issuer; never an agent capability')
    for name in ('run-id', 'principal', 'tool', 'target', 'change-limit'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--ttl-seconds', type=int, default=300)
    parser.add_argument('--manifest-sha256', help='Required for approval of the exact Nuclei template manifest')
    args = parser.parse_args()
    _key(create=True)
    print(issue_action_approval(args.run_id, args.principal, args.tool, args.target, args.change_limit, args.ttl_seconds, manifest_sha256=args.manifest_sha256))
