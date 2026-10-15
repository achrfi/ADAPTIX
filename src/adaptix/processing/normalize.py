"""Stable source-specific keys; never conflate different objects or identities."""
import json
from src.adaptix.security.scope import endpoint_key


def record_key(kind, row):
    if kind == 'services':
        return (row.get('host'), row.get('protocol'), row.get('port'))
    if kind == 'recon_inventory':
        return (row.get('host'),)
    if kind == 'candidates':
        return (row.get('template_id'), endpoint_key(row.get('url', '')))
    if kind in ('http_services', 'browser_evidence'):
        return endpoint_key(row.get('url', ''))
    if kind == 'idor_findings':
        return (row.get('scenario'), tuple(row.get('endpoint_key') or []),
                row.get('owner_identity'), row.get('other_identity'))
    return json.dumps(row, sort_keys=True, default=str)


def deduplicate(kind, rows):
    """Keep newest observation at each stable key, including within a single batch."""
    unique = {}
    for row in rows:
        if isinstance(row, dict):
            unique[record_key(kind, row)] = row
    return list(unique.values())
