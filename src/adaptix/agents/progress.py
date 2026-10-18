"""Evidence-grounded progress, distinct from the model's estimated benefit."""
import re
from urllib.parse import parse_qsl, urlsplit
from src.adaptix.security.scope import endpoint_key


def _path_key(url):
    parsed = urlsplit(str(url or ''))
    return f'{parsed.scheme}://{parsed.netloc}{parsed.path}'


def _parameter_names(url):
    return tuple(sorted({name for name, _ in parse_qsl(urlsplit(str(url or '')).query, keep_blank_values=True) if name}))


def stagnation_report(state, limit=5):
    """Measured information gain of recent actions; never the model's self-report.

    ``goal_progress`` comes from deterministic evidence comparison: a repeated
    value variation that returns the same response is recorded as zero gain even
    though a new request was audited.
    """
    outcomes = [o for o in state.get('action_outcomes', []) if isinstance(o, dict)]
    recent = [{'tool': (o.get('action') or {}).get('tool'),
               'target': (o.get('action') or {}).get('target'),
               'goal_progress': round(float(o.get('goal_progress') or 0), 3),
               'new_evidence': len(o.get('new_evidence_keys') or []),
               'reason': str(o.get('reason') or '')[:140]}
              for o in outcomes[-limit:]]
    streak, zero_gain = 0, 0
    for outcome in reversed(outcomes):
        if float(outcome.get('goal_progress') or 0) <= 0:
            streak += 1
        else:
            break
    zero_gain = sum(1 for o in outcomes if float(o.get('goal_progress') or 0) <= 0)
    return {'recent': recent, 'consecutive_no_gain': streak, 'no_gain_actions': zero_gain,
            'actions_measured': len(outcomes)}


def parameter_variation_no_gain(state, action):
    """True when an action only varies values of a parameter that already proved insensitive.

    Two or more distinct requests on the same path and parameter set, all with the
    same status and response body and no detected signature, are measured evidence
    that changing this parameter's value yields no new information.
    """
    if action.get('tool') != 'http_request':
        return False
    if str(action.get('method') or 'GET').upper() not in ('GET', 'HEAD'):
        return False
    proposed = _parameter_names(action.get('target', ''))
    if not proposed:
        return False
    key = _path_key(action.get('target', ''))
    method = str(action.get('method') or 'GET').upper()
    group = [row for row in state.get('probe_traces', []) if isinstance(row, dict)
             and row.get('path_key') == key and str(row.get('method') or '').upper() == method
             and tuple(sorted(name for name in str(row.get('parameter') or '').split(',') if name)) == proposed]
    fingerprints = {row.get('request_fingerprint') or row.get('url') for row in group}
    if len(fingerprints) < 2 or any(row.get('detected') for row in group):
        return False
    return len({(row.get('status_code'), row.get('body_sha256')) for row in group}) == 1


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
    web_key = lambda f: (f.get('category'), f.get('path_key'))
    new_web = len({web_key(f) for f in after.get('findings', [])} - {web_key(f) for f in before.get('findings', [])})
    trace_key = lambda t: (t.get('path_key'), t.get('method'), t.get('body_sha256'))
    route_key = lambda r: (endpoint_key(r.get('url', '')), r.get('method'), r.get('kind'))
    new_trace_keys = {trace_key(t) for t in result.get('probe_traces', [])} - {trace_key(t) for t in state.get('probe_traces', [])}
    new_route_keys = {route_key(r) for r in result.get('web_routes', [])} - {route_key(r) for r in state.get('web_routes', [])}
    new_traces = len(new_trace_keys)
    app_routes = {key for key in new_route_keys
                  if not next((r.get('static_asset') for r in result.get('web_routes', [])
                               if route_key(r) == key), False)}
    new_routes = len(new_route_keys)
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
    elif new_web:
        value, reason = .5, 'Deterministic signature recorded; differential proof still required for confirmation'
    elif new_traces:
        value, reason = .3, 'Bounded request returned a comparable response trace'
    elif app_routes:
        value, reason = .3, 'Discovered in-scope application routes'
    elif new_routes:
        value, reason = .1, 'Discovered static asset references only; application routes still needed'
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
