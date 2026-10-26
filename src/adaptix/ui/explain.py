"""Class labels for findings; narrative explanations come from the report model."""

EXPLAIN = {
    'sql_injection': {'title': 'SQL injection', 'cwe': 'CWE-89'},
    'cross_site_scripting': {'title': 'Cross-site scripting (XSS)', 'cwe': 'CWE-79'},
    'broken_object_level_authorization': {'title': 'Broken object level authorization (BOLA/IDOR)', 'cwe': 'CWE-639'},
    'union_data_extraction': {'title': 'SQL injection dengan ekstraksi data (UNION)', 'cwe': 'CWE-89'},
    'os_command_injection': {'title': 'OS command injection', 'cwe': 'CWE-78'},
    'template_injection': {'title': 'Server-side template injection', 'cwe': 'CWE-1336'},
    'path_traversal': {'title': 'Path traversal', 'cwe': 'CWE-22'},
    'ssrf': {'title': 'Server-side request forgery', 'cwe': 'CWE-918'},
    'server_side_request_forgery': {'title': 'Server-side request forgery', 'cwe': 'CWE-918'},
    'xxe': {'title': 'XML external entity', 'cwe': 'CWE-611'},
    'security_misconfiguration': {'title': 'Security misconfiguration', 'cwe': 'CWE-16'},
    'information_disclosure': {'title': 'Information disclosure', 'cwe': 'CWE-200'},
    'sensitive_information_exposure': {'title': 'Sensitive information exposure', 'cwe': 'CWE-200'},
    'authentication_bypass': {'title': 'Authentication bypass', 'cwe': 'CWE-287'},
    'authentication': {'title': 'Authentication weakness', 'cwe': 'CWE-287'},
    'authorization': {'title': 'Authorization weakness', 'cwe': 'CWE-285'},
    'file_upload': {'title': 'Unrestricted file upload', 'cwe': 'CWE-434'},
    'jwt_weakness': {'title': 'JWT weakness', 'cwe': 'CWE-347'},
    'rate_limit': {'title': 'Missing rate limiting', 'cwe': 'CWE-770'},
    'csrf': {'title': 'Cross-site request forgery', 'cwe': 'CWE-352'},
    'open_redirect': {'title': 'Open redirect', 'cwe': 'CWE-601'},
    'insecure_deserialization': {'title': 'Insecure deserialization', 'cwe': 'CWE-502'},
    'potential_vulnerability': {'title': 'Indikasi scanner', 'cwe': ''},
}


def explain(finding):
    finding = finding or {}
    key = str(finding.get('class') or finding.get('finding_type')
              or finding.get('category') or '').strip().lower()
    entry = EXPLAIN.get(key)
    if entry is None and finding.get('impact'):
        entry = EXPLAIN.get(str(finding.get('impact')).strip().lower())
    if entry is None and finding.get('impact_proven'):
        entry = EXPLAIN['union_data_extraction']
    if entry is None:
        entry = {'title': key.replace('_', ' ') or 'temuan belum diklasifikasi', 'cwe': ''}
    return {**entry, 'cause': '', 'mitigation': ''}
