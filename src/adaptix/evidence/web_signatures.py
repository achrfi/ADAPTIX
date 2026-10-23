"""Deterministic web response signatures and general vulnerability finding synthesis.

The rules here never promote an LLM hypothesis or a scanner severity label into a
confirmed finding. A finding is only ``confirmed`` when the stored, reproducible
response trace itself contains objective evidence and, for differential classes,
a matching control observation on the same path proves the input caused it.
"""
import re

CATEGORY_TITLES = {
    'sql_injection': 'SQL injection indicator',
    'nosql_injection': 'NoSQL injection indicator',
    'cross_site_scripting': 'Cross-site scripting indicator',
    'path_traversal': 'Path traversal indicator',
    'sensitive_information_exposure': 'Sensitive information exposure',
    'security_misconfiguration': 'Security misconfiguration indicator',
    'broken_access_control': 'Broken access control indicator',
    'idor_bola': 'Broken object level authorization indicator',
    'authentication': 'Authentication weakness indicator',
    'authorization': 'Authorization weakness indicator',
    'file_upload': 'File upload weakness indicator',
    'server_side_request_forgery': 'Server-side request forgery indicator',
    'jwt_weakness': 'JWT weakness indicator',
}

SEVERITY = {
    'sql_injection': 'high',
    'nosql_injection': 'high',
    'cross_site_scripting': 'high',
    'path_traversal': 'high',
    'sensitive_information_exposure': 'high',
    'server_side_request_forgery': 'high',
    'broken_access_control': 'high',
    'idor_bola': 'high',
    'authentication': 'high',
    'authorization': 'high',
    'file_upload': 'high',
    'security_misconfiguration': 'medium',
    'jwt_weakness': 'medium',
}

SEVERITY_RATIONALE = {
    'sql_injection': 'Database error behaviour was reproduced by attacker-controlled input; impact depends on data reachable by the application account.',
    'nosql_injection': 'NoSQL engine error behaviour correlates with attacker-controlled input.',
    'cross_site_scripting': 'Attacker-controlled markup is reflected into an HTML response without output encoding.',
    'path_traversal': 'A traversal payload returned the contents of a sensitive file outside the web root.',
    'sensitive_information_exposure': 'The response body contains credential-like material that should not be disclosed.',
    'security_misconfiguration': 'The response exposes configuration or error detail that aids further attack.',
}

CONFIRMED = 'confirmed'
POTENTIAL = 'potential'
INCONCLUSIVE = 'inconclusive'
FALSE_POSITIVE = 'false_positive'

REPORT_STATUS = {CONFIRMED: 'CONFIRMED', POTENTIAL: 'POTENTIAL',
                 INCONCLUSIVE: 'INCONCLUSIVE', FALSE_POSITIVE: 'FALSE_POSITIVE'}

_PROBE_CHARS = set("<>'\"`;()=$|{}")
_PROBE_TOKENS = ('../', '..\\', '%2e%2e', '..%2f', '%00', 'union ', 'select ', ' sleep(',
                 ' or 1=1', 'or 1=1', '{{', '${', 'onerror', 'onload', '<script',
                 'javascript:', 'etc/passwd', 'boot.ini', '$ne', '{{', '||', '&&')

_SCRIPT_TOKENS = ('<script', 'onerror=', 'onload=', 'javascript:', '<svg', '<img', '<iframe')
_INJECTION_CHARS = ("'", '"', '`', ';', '--')
_TRAVERSAL_TOKENS = ('../', '..\\', '%2e%2e', '..%2f', 'etc/passwd', 'boot.ini')

SQL_ERROR_RULES = [
    ('mysql_syntax', re.compile(r'(?i)you have an error in your sql syntax')),
    ('mysql_warning', re.compile(r'(?i)warning:\s*mysql')),
    ('mssql_unclosed_quote', re.compile(r'(?i)unclosed quotation mark after the character string')),
    ('mssql_odbc', re.compile(r'(?i)(?:microsoft ole db provider for sql server|odbc sql server driver)')),
    ('postgres_syntax', re.compile(r'(?i)(?:pg_query\(|pg_exec\(|postgresql.{0,40}error|syntax error at or near)')),
    ('sqlite_error', re.compile(r'(?i)(?:sqlite3?\.operationalerror|sqlite error|unrecognized token)')),
    ('oracle_error', re.compile(r'(?i)\bora-\d{5}\b')),
    ('generic_sqlstate', re.compile(r'(?i)sqlstate\[\w+\]')),
]

NOSQL_ERROR_RULES = [
    ('mongo_error', re.compile(r'(?i)(?:MongoError|MongoServerError|E11000 duplicate key|unknown operator)')),
    ('couch_error', re.compile(r'(?i)(?:couchdb|elasticsearch).{0,40}error')),
]

TRAVERSAL_MARKERS = ('root:x:0:0:', 'daemon:x:', 'nobody:x:', '[boot loader]', '[extensions]',
                     'BEGIN OPENSSH PRIVATE KEY', '; for 16-bit app support')

# Deterministic client-framework markers observed in served HTML/JS. These are
# only technology fingerprints (Wappalyzer-style rules applied to evidence the
# target itself emitted); they never become vulnerability findings and never
# name a product the response did not evidence. Mapped further into Nuclei
# template tags only where the configured product map knows the marker.
FRAMEWORK_RULES = (
    ('angular', re.compile(r'(?i)(?:\bng-app=|ngcontroller|\bapp-root\b|angular(?:\.min)?\.js|zone\.js)')),
    ('react', re.compile(r'(?i)(?:__NEXT_DATA__|data-reactroot|\breact(?:-dom)?(?:\.min)?\.js|_reactListening)')),
    ('vue', re.compile(r'(?i)(?:\bid="app"[^>]*data-v-|\bvue(?:\.min)?\.js|v-if=")')),
    ('jquery', re.compile(r'(?i)jquery[-.]?(?:\d|core|\.min)?\.?js')),
    ('bootstrap', re.compile(r'(?i)bootstrap(?:\.min)?\.(?:js|css)')),
    ('wordpress', re.compile(r'(?i)(?:wp-content|wp-includes|/wp-json)')),
    ('django', re.compile(r'(?i)csrfmiddlewaretoken')),
    ('express', re.compile(r'(?i)connect\.sid')),
)

# Header names whose values name real products or runtime stacks. Only the
# target's own response headers produce labels here - nothing is synthesized.
HEADER_PRODUCT_FIELDS = ('server', 'x-powered-by', 'x-aspnet-version', 'x-drupal-cache', 'x-generator')

# Credential-shaped values that documentation itself publishes as examples. They
# match the detection rules but are sample text, never evidence of a real leak.
PLACEHOLDER_MATERIAL = ('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')

SENSITIVE_RULES = [
    ('private_key', re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----')),
    ('aws_access_key', re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ('json_web_token', re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b')),
    ('slack_token', re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b')),
]


def is_probe_value(value):
    """True when a parameter value looks like a deliberately crafted test payload."""
    if not isinstance(value, str) or not value:
        return False
    if any(char in value for char in _PROBE_CHARS):
        return True
    lowered = value.lower()
    return any(token in lowered for token in _PROBE_TOKENS)


def _encoded(value):
    return (value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            .replace('"', '&quot;').replace("'", '&#x27;'))


def detect(text, content_type, payloads):
    """Return deduplicated deterministic signatures found in a single response body."""
    text = text or ''
    content_type = (content_type or '').lower()
    detections = []
    for value in payloads:
        if not is_probe_value(value):
            continue
        raw = value in text
        lowered = value.lower()
        if any(token in lowered for token in _SCRIPT_TOKENS):
            if raw and 'html' in content_type:
                detections.append({'category': 'cross_site_scripting', 'signature': 'reflected_html_markup'})
            elif raw:
                detections.append({'category': 'cross_site_scripting', 'signature': 'reflected_non_html'})
            elif _encoded(value) in text:
                detections.append({'category': 'cross_site_scripting', 'signature': 'html_encoded_reflection'})
        if any(char in value for char in _INJECTION_CHARS):
            for name, rule in SQL_ERROR_RULES:
                if rule.search(text):
                    detections.append({'category': 'sql_injection', 'signature': name})
            for name, rule in NOSQL_ERROR_RULES:
                if rule.search(text):
                    detections.append({'category': 'nosql_injection', 'signature': name})
        if any(token in lowered for token in _TRAVERSAL_TOKENS):
            for marker in TRAVERSAL_MARKERS:
                if marker in text:
                    detections.append({'category': 'path_traversal', 'signature': marker})
    for name, rule in SENSITIVE_RULES:
        if rule.search(text):
            detections.append({'category': 'sensitive_information_exposure', 'signature': name})
    seen, unique = set(), []
    for item in detections:
        key = (item['category'], item['signature'])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def control_detections(text):
    """Differential signatures present in a control response's own body.

    ``detect`` evaluates the SQL/NoSQL/traversal rules only for crafted payload
    values, so a control trace's own ``detected`` list can never contain them:
    a control that emits a database error or a traversal marker by itself would
    otherwise always look clean. This applies the same rule families to the
    control's stored body excerpt so endpoint-inherent behaviour is not lost.
    """
    text = text or ''
    detections = []
    for name, rule in SQL_ERROR_RULES:
        if rule.search(text):
            detections.append({'category': 'sql_injection', 'signature': name})
    for name, rule in NOSQL_ERROR_RULES:
        if rule.search(text):
            detections.append({'category': 'nosql_injection', 'signature': name})
    for marker in TRAVERSAL_MARKERS:
        if marker in text:
            detections.append({'category': 'path_traversal', 'signature': marker})
    seen, unique = set(), []
    for item in detections:
        key = (item['category'], item['signature'])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def detect_technologies(text, headers):
    """Technology fingerprints from evidence the target itself emitted.

    Returns (raw_labels, marker_source_pairs). Raw labels are verbatim response
    header product strings (e.g. ``nginx/1.26.2``, ``Express``) - never invented
    and never normalized here. Markers are generic framework fingerprints from
    RESPONSE_MARKERS(rules) matched against the served HTML/JS. A response that
    lacks any signature yields empty results: absence is never a claim.
    """
    raw, markers = {}, []
    for field in HEADER_PRODUCT_FIELDS:
        value = (headers.get(field) or '').strip()
        if value:
            raw[field] = value
    text = text or ''
    for name, rule in FRAMEWORK_RULES:
        if rule.search(text):
            markers.append(name)
    return raw, markers


def _controls(group):
    return [trace for trace in group if trace.get('control')]


def _control_clean(category, group):
    controls = _controls(group)
    return bool(controls) and not any(
        trace.get('excerpt_truncated')  # a truncated control cannot prove absence
        or detection['category'] == category
        for trace in controls
        for detection in list(trace.get('detected', [])) + control_detections(trace.get('body_excerpt', '')))


def _status_for(category, group):
    signatures = {detection['signature'] for trace in group for detection in trace.get('detected', [])
                  if detection['category'] == category}
    if category == 'cross_site_scripting':
        if 'reflected_html_markup' in signatures:
            return CONFIRMED
        if 'reflected_non_html' in signatures:
            return POTENTIAL
        if 'html_encoded_reflection' in signatures:
            return FALSE_POSITIVE
        return POTENTIAL
    if category in ('sql_injection', 'nosql_injection'):
        return CONFIRMED if _control_clean(category, group) else POTENTIAL
    if category == 'path_traversal':
        return CONFIRMED if _control_clean(category, group) else POTENTIAL
    if category == 'sensitive_information_exposure':
        # Unambiguous secret material is confirmed; ambiguous tokens may be legitimate,
        # and values documentation itself publishes are sample text, never proof.
        if not signatures & {'private_key', 'aws_access_key'}:
            return POTENTIAL
        text = ' '.join(trace.get('body_excerpt', '') for trace in group)
        return POTENTIAL if any(marker in text for marker in PLACEHOLDER_MATERIAL) else CONFIRMED
    return POTENTIAL


def build_findings(state):
    """Synthesize Phase-8 findings from stored probe traces, never from model text."""
    traces = [trace for trace in state.get('probe_traces', []) if isinstance(trace, dict)]
    by_path = {}
    for trace in traces:
        by_path.setdefault(trace.get('path_key'), []).append(trace)
    findings = []
    for path_key, path_traces in by_path.items():
        categories = {detection['category'] for trace in path_traces
                      for detection in trace.get('detected', []) if detection.get('category')}
        for category in sorted(categories):
            status = _status_for(category, path_traces)
            group = [trace for trace in path_traces if not trace.get('control')]
            representative = next((trace for trace in group
                                   if any(d['category'] == category for d in trace.get('detected', []))),
                                  group[0] if group else path_traces[0])
            controls = _controls(path_traces)
            evidence_refs = sorted({trace.get('evidence_ref') for trace in path_traces if trace.get('evidence_ref')})
            observations = sorted({f"{detection['category']}:{detection['signature']}"
                                   for trace in path_traces for detection in trace.get('detected', [])
                                   if detection['category'] == category})
            findings.append({
                'finding_id': f'WEB-{len(findings) + 1:03d}',
                'category': category,
                'title': CATEGORY_TITLES.get(category, category),
                'target': representative.get('url'),
                'path_key': path_key,
                'method': representative.get('method'),
                'parameter': representative.get('parameter'),
                'observations': observations,
                'verification_status': status,
                'confidence': {CONFIRMED: 'high', POTENTIAL: 'medium',
                               INCONCLUSIVE: 'low', FALSE_POSITIVE: 'high'}[status],
                'severity': SEVERITY.get(category, 'medium'),
                'severity_rationale': SEVERITY_RATIONALE.get(
                    category, 'Impact depends on what the application exposes at this endpoint.'),
                'reproduction': {
                    'method': representative.get('method'),
                    'url': representative.get('url'),
                    'parameter': representative.get('parameter'),
                    'payload': representative.get('payload'),
                    'control_url': controls[0].get('url') if controls else None,
                },
                'tools_used': ['http_request'],
                'token_usage': int(state.get('planner_metrics', {}).get('tokens_used', 0)),
                'execution_time': representative.get('seconds'),
                'evidence_refs': evidence_refs,
            })
    return findings
