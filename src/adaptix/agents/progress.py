"""Evidence-grounded progress, distinct from the model's estimated benefit."""
import re
from src.adaptix.security.scope import endpoint_key


def objective_kind(state):
    explicit = state.get('objective_kind')
    if explicit in ('authorization', 'navigation', 'service_observation', 'security_assessment'):
        return explicit
    text = state.get('user_prompt', '').lower()
    if state.get('idor_scenarios') or re.search(r'idor|bola|dua identitas|kontrol akses|authorization|objek privat', text):
        return 'authorization'
    if re.search(r'tautan|link|halaman detail|navigate|navigation', text):
        return 'navigation'
    if re.search(r'status.http|http.status|judul|title|reachability', text):
        return 'service_observation'
    return 'security_assessment'


def progress_assessment(state, result):
    from src.adaptix.agents.reflector import collect_findings
    kind = objective_kind(state)
    merged = {**state, **result}
    before = collect_findings(state)
    after = collect_findings(merged)
    key = lambda item: (item.get('template_id'), item.get('target'), item.get('owner_identity'), item.get('other_identity'))
    verified = len({key(x) for x in after['verified_findings']} - {key(x) for x in before['verified_findings']})
    refuted = len({key(x) for x in after['rejected_findings'] if x.get('verification_evidence')}
                  - {key(x) for x in before['rejected_findings'] if x.get('verification_evidence')})
    inconclusive = len({key(x) for x in after['inconclusive_findings']} - {key(x) for x in before['inconclusive_findings']})
    if verified or (refuted and kind == 'authorization'):
        return {'objective_kind': kind, 'goal_progress': 1.0, 'verification_gain': verified + refuted,
                'reason': 'Authenticated vulnerability proof or decisive authorization control result'}
    old_http = {(endpoint_key(x.get('url')), x.get('status_code'), x.get('title')) for x in state.get('http_services', [])}
    fresh_http = [x for x in result.get('http_services', []) if (endpoint_key(x.get('url')), x.get('status_code'), x.get('title')) not in old_http]
    old_browser = {(x.get('url'), x.get('title')) for x in state.get('browser_evidence', [])}
    fresh_browser = [x for x in result.get('browser_evidence', []) if (x.get('url'), x.get('title')) not in old_browser]
    previous_links = {u for row in state.get('browser_evidence', []) for u in row.get('links', []) if u != row.get('url')}
    navigation = any(row.get('url') in previous_links and row.get('title') for row in fresh_browser)
    if kind == 'navigation' and navigation:
        value, reason = 1.0, 'Followed a previously discovered link and observed the destination title'
    elif kind == 'navigation' and any(row.get('links') for row in fresh_browser):
        value, reason = .6, 'Discovered in-scope navigation evidence'
    elif kind == 'service_observation' and any(isinstance(row.get('status_code'), int) for row in fresh_http + fresh_browser):
        title_needed = bool(re.search(r'judul|title', state.get('user_prompt', ''), re.I))
        complete = not title_needed or any(row.get('title') for row in fresh_http + fresh_browser)
        value, reason = (1.0 if complete else .5), 'Observed requested status/title facts'
    elif kind == 'authorization' and result.get('idor_scenarios') != state.get('idor_scenarios') and result.get('idor_scenarios'):
        value, reason = .8, 'Constructed a scenario with observed provenance and validated sessions/private ownership'
    elif kind == 'authorization' and (result.get('scenario_candidates') or result.get('api_operations')):
        value, reason = .5, 'Discovered documented API routes or owned-object candidates'
    elif kind == 'authorization' and inconclusive:
        value, reason = .1, 'Authorization remains uncertain; another record is not a confirmed result'
    elif any(row.get('tech') for row in fresh_http):
        value, reason = .4, 'New technology evidence can narrow subsequent tests'
    elif fresh_http or fresh_browser:
        value, reason = .15, 'New observation; objective impact remains unverified'
    elif result.get('services') and result.get('services') != state.get('services'):
        value, reason = .3, 'New service inventory'
    elif result.get('candidates') and result.get('candidates') != state.get('candidates'):
        value, reason = .3, 'New unverified hypothesis; independent verification still needed'
    else:
        value, reason = 0.0, 'No new evidence of progress toward the objective'
    if len(result.get('errors', [])) > len(state.get('errors', [])):
        value = min(value, .1)
    return {'objective_kind': kind, 'goal_progress': value, 'verification_gain': verified + refuted, 'reason': reason}
