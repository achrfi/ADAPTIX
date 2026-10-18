"""Bounded evidence suitable for sharing; originals remain worker-local."""
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE = re.compile(r'(?i)(authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|token|access[-_]?token|refresh[-_]?token|api[-_]?key|session[-_]?id)')


def clean_url(value):
    try:
        u = urlsplit(value)
        if not u.scheme or not u.netloc:
            return value
        host = u.netloc.rsplit('@', 1)[-1]
        query = urlencode([(k, '[REDACTED]' if SENSITIVE.fullmatch(k) else v)
                           for k, v in parse_qsl(u.query, keep_blank_values=True)])
        return urlunsplit((u.scheme, host, u.path, query, u.fragment))
    except ValueError:
        return '[invalid URL]'


def sanitize(value, secrets=()):
    if isinstance(value, dict):
        return {str(k): '[REDACTED]' if SENSITIVE.fullmatch(str(k)) and not
                (str(k) == 'authorization' and isinstance(v, dict) and 'type' in v) else sanitize(v, secrets)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(v, secrets) for v in value]
    if isinstance(value, str):
        for secret in sorted({s for s in secrets if isinstance(s, str) and len(s) >= 4}, key=len, reverse=True):
            value = value.replace(secret, '[REDACTED]')
        value = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+', 'Bearer [REDACTED]', value)
        value = re.sub(r'(?i)\b(password|api_key|access_token|refresh_token)\s*=\s*[^\s&]+', r'\1=[REDACTED]', value)
        if value.startswith(('http://', 'https://')):
            return clean_url(value)
    return value


def response_record(response, secrets=()):
    import hashlib
    import json
    try:
        text = response.text
    except Exception:
        # Defensive: a stale content-encoding must not lose an otherwise recorded response.
        text = response.content.decode('utf-8', 'replace')
    try:
        body = json.dumps(sanitize(json.loads(text), secrets), ensure_ascii=False)
    except (ValueError, TypeError):
        body = sanitize(text, secrets)
    return {'status_code': response.status_code,
            'headers': sanitize(dict(getattr(response, 'headers', {})), secrets),
            'body_excerpt': body[:4096], 'body_truncated': len(body) > 4096,
            'body_sha256': hashlib.sha256(text.encode()).hexdigest()}


def scenario_secrets(state):
    return [v for identity in state.get('identity_context', {}).get('identities', []) for v in identity.get('headers', {}).values()] + [v for sc in state.get('idor_scenarios', [])
            for role in ('owner_identity', 'other_identity')
            for v in sc.get(role, {}).get('headers', {}).values()]
