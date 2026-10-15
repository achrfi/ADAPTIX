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
    cfg = config('scope.yaml')['limits']
    permitted_ports = {urlsplit(url).port or (443 if url.startswith('https:') else 80) for url in urls}
    evidence = list(state.get('browser_evidence', []))
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
                        def route_request(route):
                            request = route.request
                            if (request.method in ('GET', 'HEAD') and remaining_seconds(state) > 0
                                    and allowed_url(request.url, state['hosts'], permitted_ports, state.get('scope_aliases'), state.get('scope_networks'))):
                                route.continue_()
                            else:
                                blocked_requests.append({'url': request.url, 'method': request.method,
                                                         'reason': 'read-only browser operation/scope policy'})
                                route.abort()
                        page.route('**/*', route_request)
                        response = page.goto(url, wait_until='domcontentloaded', timeout=int(tool_timeout(state, 8)*1000))
                        # Abort external redirects/subresources; do not click or submit forms.
                        if not allowed_url(page.url, state['hosts'], permitted_ports, state.get('scope_aliases'), state.get('scope_networks')):
                            raise ValueError('Out-of-scope browser navigation blocked')
                        img = artifact_path(state, 'playwright', url, 'png')
                        raw_html = page.content()
                        raw_path = artifact_path(state, 'playwright-source', url, 'html')
                        save_text(raw_path, raw_html)
                        raw_bytes += len(raw_html.encode('utf-8'))
                        page.screenshot(path=str(img), full_page=False, timeout=int(tool_timeout(state, 5)*1000))
                        img.chmod(0o600)
                        links = [link for link in page.locator('a[href]').evaluate_all('(nodes) => nodes.slice(0, 64).map(n => n.href)')
                                 if allowed_url(link, state['hosts'], permitted_ports, state.get('scope_aliases'), state.get('scope_networks'))]
                        evidence.append({'url': url, 'title': page.title()[:160],
                                         'status_code': response.status if response else None,
                                         'text_excerpt': page.locator('body').inner_text(timeout=int(tool_timeout(state, 3)*1000))[:2000],
                                         'links': list(dict.fromkeys(links)),
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
    return {'browser_evidence': evidence, 'execution_metrics': execution_metrics, 'raw_bytes': raw_bytes, 'errors': errors,
            'events': log(state, f'Playwright: {len(evidence)} screenshots')}
