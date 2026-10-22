"""ADAPTIX unified module. Migrated from tested running code."""
from urllib.parse import urlsplit
from src.adaptix.config import config, ROOT
from src.adaptix.tools.registry import tool_registry
from src.adaptix.security.scope import allowed_url
from src.adaptix.security.transport import browser_resolver_rules, bind_url
from src.adaptix.evidence.storage import artifact_path, save_text
from src.adaptix.workflow.events import log
from src.adaptix.workflow.budget import tool_budget_available, record_tool_call, tool_timeout, remaining_seconds
from src.adaptix.security.scope import endpoint_key


def _in_scope(state, url, permitted_ports):
    return allowed_url(url, state.get('hosts', []), permitted_ports,
                       state.get('scope_aliases'), state.get('scope_networks'))


def normalize_observed_url(request_url):
    """Reduce an observed XHR/fetch URL to a routable endpoint (parameter names only).

    Runtime values such as session ids and cache-busters are dropped so repeated
    polling calls collapse to one discovered route.
    """
    from src.adaptix.tools.web import normalize_script_path
    parsed = urlsplit(request_url)
    path_and_query = parsed.path + (('?' + parsed.query) if parsed.query else '')
    endpoint = normalize_script_path(path_and_query) or parsed.path
    return f'{parsed.scheme}://{parsed.netloc}{endpoint}'


def browser_observe(state):
    actions = state.get('planned_actions', [])
    cursor = int(state.get('action_cursor', 0))
    intended = ([actions[cursor]['target']] if actions and cursor < len(actions) and actions[cursor]['tool'] == 'playwright'
                else [x['url'] for x in state.get('http_services', [])] if not actions else [])
    urls = intended
    if not tool_budget_available(state):
        return {'events': log(state, 'Playwright: skipped, tool-call budget exhausted')}
    if not urls:
        return {'events': log(state, 'Playwright: skipped; no live endpoints')}
    registry = tool_registry()
    if not registry['playwright']['enabled']:
        return {'events': log(state, 'Playwright: disabled in config')}
    if not registry['playwright']['path']:
        return {'errors': list(state.get('errors', [])) + ['Playwright package missing'],
                'events': log(state, 'Playwright: missing')}
    for url in urls:
        bind_url(url, state)
    from playwright.sync_api import sync_playwright
    from src.adaptix.tools.web import route_row
    cfg = config('scope.yaml')['limits']
    permitted_ports = {urlsplit(url).port or (443 if url.startswith('https:') else 80) for url in urls}
    evidence = list(state.get('browser_evidence', []))
    routes = list(state.get('web_routes', []))
    execution_metrics = dict(state.get('execution_metrics', {}))
    errors = list(state.get('errors', []))
    raw_bytes = int(state.get('raw_bytes', 0))
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, timeout=int(tool_timeout(state, 30)*1000), args=['--host-resolver-rules=' + browser_resolver_rules(state), '--no-proxy-server'])
            try:
                for url in urls:
                    if not tool_budget_available({**state, 'execution_metrics': execution_metrics}):
                        break
                    execution_metrics = record_tool_call({**state, 'execution_metrics': execution_metrics}, 'playwright')
                    context = browser.new_context(ignore_https_errors=True)
                    try:
                        page = context.new_page()
                        blocked_requests = []
                        # Real application routes are the XHR/fetch calls the SPA
                        # makes at runtime; observe only read-only in-scope traffic.
                        observed_requests = {}

                        def route_request(route):
                            request = route.request
                            if (request.method in ('GET', 'HEAD') and remaining_seconds(state) > 0
                                    and _in_scope(state, request.url, permitted_ports)):
                                observed_requests[request.url] = request.resource_type
                                route.continue_()
                            else:
                                blocked_requests.append({'url': request.url, 'method': request.method,
                                                         'reason': 'read-only browser operation/scope policy'})
                                route.abort()

                        page.route('**/*', route_request)
                        response = page.goto(url, wait_until='domcontentloaded', timeout=int(tool_timeout(state, 8)*1000))
                        # Abort external redirects/subresources; do not click or submit forms.
                        if not _in_scope(state, page.url, permitted_ports):
                            raise ValueError('Out-of-scope browser navigation blocked')
                        # Give the SPA a bounded window to finish its initial API calls.
                        try:
                            page.wait_for_load_state('networkidle', timeout=int(tool_timeout(state, 6)*1000))
                        except Exception:
                            page.wait_for_timeout(500)
                        img = artifact_path(state, 'playwright', url, 'png')
                        raw_html = page.content()
                        raw_path = artifact_path(state, 'playwright-source', url, 'html')
                        save_text(raw_path, raw_html)
                        raw_bytes += len(raw_html.encode('utf-8'))
                        page.screenshot(path=str(img), full_page=False, timeout=int(tool_timeout(state, 5)*1000))
                        img.chmod(0o600)
                        links = [link for link in page.locator('a[href]').evaluate_all('(nodes) => nodes.slice(0, 64).map(n => n.href)')
                                 if _in_scope(state, link, permitted_ports)]
                        api_endpoints = []
                        for request_url, resource_type in observed_requests.items():
                            if resource_type not in ('xhr', 'fetch'):
                                continue
                            # Keep parameter names but drop runtime values (session ids,
                            # cache-busters) so one endpoint is recorded once.
                            target = normalize_observed_url(request_url)
                            row = route_row(state, target, 'GET', 'xhr' if resource_type == 'xhr' else 'fetch', str(raw_path))
                            if not row or row['static_asset']:
                                continue
                            routes.append(row)
                            api_endpoints.append({'url': row['url'], 'kind': row['kind'], 'api_like': row.get('api_like', False)})
                        evidence.append({'url': url, 'title': page.title()[:160],
                                         'status_code': response.status if response else None,
                                         'text_excerpt': page.locator('body').inner_text(timeout=int(tool_timeout(state, 3)*1000))[:2000],
                                         'links': list(dict.fromkeys(links)),
                                         'api_endpoints': api_endpoints[:64],
                                         'blocked_requests': blocked_requests,
                                         'raw_ref': str(raw_path),
                                         'screenshot': str(img.relative_to(ROOT))})
                    except Exception as exc:
                        errors.append(f'Playwright {url}: {str(exc)[:150]}')
                    finally:
                        context.close()
            finally:
                browser.close()
    except Exception as exc:
        errors.append('Playwright startup: ' + str(exc)[:180])
    routes = list({(endpoint_key(row['url']), row['method'], row['kind']): row for row in routes}.values())
    return {'browser_evidence': evidence, 'web_routes': routes,
            'execution_metrics': execution_metrics, 'raw_bytes': raw_bytes, 'errors': errors,
            'events': log(state, f'Playwright: {len(evidence)} pages, {len(routes)} routes observed')}


def browser_test(state):
    """One read-only browser session proving real script execution of an URL payload.

    The action carries a marker (6-64 chars [A-Za-z0-9_.-]) that appears inside
    the navigated in-scope URL. The tool navigates the URL once, capturing and
    dismissing every browser dialog (payload navigation), then navigates the same
    URL with the marker removed (control navigation). A deterministic replay
    record signs the outcome: a marker dialog on the payload navigation and none
    on the control is script execution; a marker dialog on the control refutes
    injection. Nothing is clicked or submitted and only in-scope GET/HEAD traffic
    proceeds, exactly like browser_observe. The tool reports honestly when no
    dialog ever fires: the record never signs and the result stays inconclusive.
    """
    import hashlib
    import re as re_module
    from src.adaptix.evidence.verification import CONTRACT_REQUIREMENTS, replay_result, write_verification_record

    action = next((a for a in state.get('planned_actions', []) if a.get('tool') == 'browser_test'), {})
    url = action.get('target', '')
    marker = str(action.get('marker') or '')
    registry = tool_registry()
    if not registry['playwright']['enabled'] or not registry['playwright']['path']:
        return {'errors': list(state.get('errors', [])) + ['Browser Test: playwright package disabled or missing'],
                'events': log(state, 'Browser Test: playwright unavailable; recorded as a limitation')}
    if not re_module.fullmatch(r'[A-Za-z0-9_.-]{6,64}', marker):
        return {'errors': list(state.get('errors', [])) + ['Browser Test: action needs a 6-64 char marker ([A-Za-z0-9_.-])'],
                'events': log(state, 'Browser Test: refused invalid marker')}
    if marker not in url:
        return {'errors': list(state.get('errors', [])) + ['Browser Test: marker must appear in the navigated URL (round-trip proof)']}
    parsed = urlsplit(url)
    if not allowed_url(url, state.get('hosts', []), {parsed.port or (443 if parsed.scheme == 'https' else 80)},
                       state.get('scope_aliases'), state.get('scope_networks')):
        return {'errors': list(state.get('errors', [])) + ['Browser Test: endpoint outside pinned scope'],
                'events': log(state, 'Browser Test: rejected out-of-scope navigation')}
    if not tool_budget_available(state):
        return {'events': log(state, 'Browser Test: skipped, tool-call budget exhausted')}
    control_url = url.replace(marker, '')
    if control_url == url:
        return {'errors': list(state.get('errors', [])) + ['Browser Test: removing the marker produced the same URL; a control decision is impossible for a marker at this injection point'],
                'events': log(state, 'Browser Test: marker is not an addressable value')}
    from playwright.sync_api import sync_playwright
    permitted_ports = {parsed.port or (443 if parsed.scheme == 'https' else 80)}
    execution_metrics = record_tool_call(state, 'browser_test')
    raw_bytes = int(state.get('raw_bytes', 0))
    payload_dialogs, control_dialogs, pages = [], [], {}

    def navigate(page, target, dialogs):
        def on_dialog(dialog):
            dialogs.append({'message': str(dialog.message)[:300], 'type': str(dialog.type)})
            try:
                dialog.dismiss()
            except Exception:
                pass

        page.on('dialog', on_dialog)
        page.route('**/*', lambda route: (
            route.continue_() if route.request.method in ('GET', 'HEAD')
            and remaining_seconds(state) > 0 and _in_scope(state, route.request.url, permitted_ports)
            else route.abort()))
        try:
            response = page.goto(target, wait_until='domcontentloaded', timeout=int(tool_timeout(state, 8) * 1000))
            if not _in_scope(state, page.url, permitted_ports):
                raise ValueError('Out-of-scope browser navigation blocked')
            try:
                page.wait_for_load_state('networkidle', timeout=int(tool_timeout(state, 4) * 1000))
            except Exception:
                page.wait_for_timeout(400)
            return response.status if response else None, page.content()
        finally:
            page.remove_listener('dialog', on_dialog)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, timeout=int(tool_timeout(state, 30) * 1000),
                                        args=['--host-resolver-rules=' + browser_resolver_rules(state),
                                              '--no-proxy-server'])
            try:
                context = browser.new_context(ignore_https_errors=True)
                try:
                    page = context.new_page()
                    payload_status, payload_html = navigate(page, url, payload_dialogs)
                    raw_bytes += len(payload_html.encode('utf-8'))
                    control_status, control_html = navigate(page, control_url, control_dialogs)
                    raw_bytes += len(control_html.encode('utf-8'))
                finally:
                    context.close()
            finally:
                browser.close()
    except Exception as exc:
        return {'execution_metrics': execution_metrics, 'raw_bytes': raw_bytes,
                'payload_dialogs': payload_dialogs, 'control_dialogs': control_dialogs,
                'errors': list(state.get('errors', [])) + ['Browser Test: ' + str(exc)[:150]],
                'events': log(state, 'Browser Test: failed before executable evidence was captured')}
    marker_lower = marker.casefold()
    marker_payload = [row['message'] for row in payload_dialogs if marker_lower in row['message'].casefold()]
    marker_control = [row['message'] for row in control_dialogs if marker_lower in row['message'].casefold()]
    record = {
        'template_id': 'browser-' + marker[:32], 'url': url, 'method': 'GET',
        'verification_method': 'deterministic_replay', 'verification_basis': 'browser_execution',
        'requests': [{'method': 'GET', 'url': url, 'identity': None},
                     {'method': 'GET', 'url': control_url, 'identity': None}],
        'responses': [
            {'status_code': payload_status or 200, 'headers': {},
             'body_sha256': hashlib.sha256(payload_html.encode()).hexdigest(),
             'body_excerpt': payload_html[:1500], 'body_truncated': len(payload_html) > 1500},
            {'status_code': control_status or 200, 'headers': {},
             'body_sha256': hashlib.sha256(control_html.encode()).hexdigest(),
             'body_excerpt': control_html[:1500], 'body_truncated': len(control_html) > 1500}],
        'browser': {'marker': marker, 'dialog_messages': [row['message'] for row in payload_dialogs],
                    'control_dialog_messages': [row['message'] for row in control_dialogs],
                    'control_url': control_url,
                    'captured_dialogs': len(payload_dialogs) + len(control_dialogs)},
        'controls': [{'url': control_url, 'status_code': control_status or 200, 'control': True,
                      'detected': [], 'body_excerpt': control_html[:2048],
                      'excerpt_truncated': len(control_html) > 2048, 'kind': 'marker_removed'}],
        'steps': ['Navigate the recorded URL (payload navigation) in a headless in-scope browser session; capture and dismiss all dialogs',
                  'Navigate the same URL with the marker removed (control navigation); capture and dismiss dialogs',
                  'Let the browser_execution contract decide from the stored navigation observations alone',
                  'Requirement: ' + CONTRACT_REQUIREMENTS['browser_execution']],
        'expected_behavior': 'No attacker-controlled script executes in the browser context',
        'actual_behavior': (f'{len(marker_payload)} marker dialog(s) on the payload navigation, '
                            f'{len(marker_control)} on the control navigation'),
    }
    verification = list(state.get('verification_evidence', []))
    result = replay_result(record)
    if result is not None:
        verification.append(write_verification_record(state, record))
    events_tail = (f'Browser Test: {len(payload_dialogs) + len(control_dialogs)} dialog(s); '
                   + ('execution recorded: ' + result if result else 'no execution observed; inconclusive'))
    return {'candidates': list(state.get('candidates', [])) + [{
                'template_id': 'browser-' + marker[:32], 'url': url, 'source_tool': 'browser',
                'finding_type': 'cross_site_scripting', 'severity': 'high',
                'status': 'candidate_unverified', 'evidence': [{'marker': marker}]},
            ] if result is not None else [],
            'verification_evidence': verification,
            'execution_metrics': execution_metrics, 'raw_bytes': raw_bytes,
            'payload_dialogs': payload_dialogs, 'control_dialogs': control_dialogs,
            'errors': list(state.get('errors', [])),
            'events': log(state, events_tail)}
