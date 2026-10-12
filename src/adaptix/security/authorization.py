"""Local-admin issued HMAC capability for an authorized scan session.

Operator MUST verify target ownership/permission outside this prototype.
The key belongs only on the scanner worker, never a dashboard/client.
"""
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import time

from src.adaptix.config import ROOT, config
from src.adaptix.security.scope import expand_targets, normalize_requests

KEY_PATH = ROOT / 'config' / '.adaptix_scope_signing_key'


def _payload_bytes(payload):
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def _key(create=False):
    if create:
        KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(KEY_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(secrets.token_bytes(32))
        except FileExistsError:
            pass
    if not KEY_PATH.is_file():
        raise ValueError('Signing key belum dibuat. Admin jalankan: python -m src.adaptix.security.authorization init')
    if KEY_PATH.stat().st_mode & 0o077:
        raise ValueError('Signing key permissions terlalu terbuka; gunakan chmod 600 config/.adaptix_scope_signing_key')
    return KEY_PATH.read_bytes()


def issue_grant(targets, principal, hours=24, destination=None):
    """Local operator action, NOT callable by an unauthenticated remote client."""
    if not principal or any(x.isspace() for x in principal) or len(principal) > 80:
        raise ValueError('Principal wajib berupa identifier tanpa spasi, max 80 chars')
    if not (0 < hours <= 168):
        raise ValueError('Lama izin maksimal 168 jam')
    policy = config('scope.yaml')
    requested = normalize_requests(targets)
    hosts = expand_targets(requested, policy, require_allowlist=False)
    now = int(time.time())
    payload = {'version': 1, 'grant_id': secrets.token_hex(12), 'principal': principal,
               'targets': requested, 'hosts': hosts, 'issued_at': now, 'expires_at': now + int(hours * 3600)}
    signature = hmac.new(_key(), _payload_bytes(payload), hashlib.sha256).hexdigest()
    record = {'payload': payload, 'signature': signature}
    if destination is None:
        destination = ROOT / 'artifacts' / 'authorizations' / f'{payload["grant_id"]}.json'
    path = Path(destination).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as file:
        json.dump(record, file, indent=2)
    return path, payload


def verify_grant(path, requested, principal, policy):
    """Check signer, principal, expiry, exact targets, and pinned resolved IPs."""
    if not principal:
        raise ValueError('principal wajib disediakan')
    try:
        record = json.loads(Path(path).read_text(encoding='utf-8'))
        payload = record['payload']
        signature = record['signature']
        provided_signature = bytes.fromhex(signature)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError('Grant tidak valid / tidak terbaca') from exc
    expected = hmac.new(_key(), _payload_bytes(payload), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, provided_signature):
        raise ValueError('Grant signature tidak valid')
    now = int(time.time())
    if payload.get('version') != 1 or payload.get('expires_at', 0) <= now or payload.get('issued_at', now+1) > now:
        raise ValueError('Grant sudah kadaluarsa atau waktu tidak valid')
    if payload.get('principal') != principal:
        raise ValueError('Grant principal tidak sesuai')
    canonical = normalize_requests(requested)
    if not set(canonical).issubset(set(payload['targets'])):
        raise ValueError('Ada target di luar grant')
    # DNS re-resolution must match exactly; prevents changed/rebound destinations.
    # Scanners receive the *pinned IPs*, never a domain for resolution again.
    resolved = expand_targets(canonical, policy, require_allowlist=False)
    if not set(resolved).issubset(set(payload['hosts'])):
        raise ValueError('DNS atau IP target berubah dari saat grant diterbitkan; minta grant baru')
    return resolved, payload['grant_id']


def main():
    parser = argparse.ArgumentParser(description='ADAPTIX local operator authorization (not a public endpoint)')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('init', help='Buat signing key lokal dengan permission 0600')
    issue = sub.add_parser('issue', help='Terbitkan grant untuk scope yang SUDAH diverifikasi oleh operator')
    issue.add_argument('--target', action='append', required=True)
    issue.add_argument('--principal', required=True)
    issue.add_argument('--hours', type=float, default=24)
    issue.add_argument('--output')
    args = parser.parse_args()
    if args.command == 'init':
        _key(create=True)
        print('Signing key initialized:', KEY_PATH)
    elif args.command == 'issue':
        path, payload = issue_grant(args.target, args.principal, args.hours, args.output)
        print(json.dumps({'grant_file': str(path), 'principal': payload['principal'], 'targets': payload['targets'],
                          'pinned_hosts': payload['hosts'], 'expires_at_epoch': payload['expires_at']}, indent=2))


if __name__ == '__main__':
    main()
