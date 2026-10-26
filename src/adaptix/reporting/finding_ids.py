"""Stable identifiers for findings shared by the report and the live view."""
import hashlib


def finding_ref(row):
    row = row or {}
    value = row.get('finding_id') or row.get('evidence_id') or row.get('id')
    if value:
        return str(value)
    identity = '|'.join(str(row.get(key) or '') for key in (
        'target', 'url', 'parameter', 'class', 'finding_type', 'category'))
    return 'F-' + hashlib.sha256(identity.encode()).hexdigest()[:12]
