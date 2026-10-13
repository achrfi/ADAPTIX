"""ADAPTIX unified module. Migrated from tested running code."""
from urllib.parse import urlsplit
from src.adaptix.config import config, ROOT
from src.adaptix.tools.registry import tool_registry
from src.adaptix.security.scope import allowed_url
from src.adaptix.evidence.storage import artifact_path
from src.adaptix.workflow.events import log
from src.adaptix.workflow.budget import tool_budget_available, record_tool_call
from src.adaptix.security.scope import endpoint_key


def browser_observe(state):
    actions = state.get('planned_actions', [])
    cursor = int(state.get('action_cursor', 0))
    intended = ([actions[cursor]['target']] if actions and cursor < len(actions) and actions[cursor]['tool'] == 'playwright'
                else [x['url'] for x in state.get('http_services', [])] if not actions else [])
    observed = {endpoint_key(x['url']) for x in state.get('http_services', [])}
    urls = [url for url in intended if endpoint_key(url) in observed]
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
    from playwright.sync_api import sync_playwright
    cfg = config('scope.yaml')['limits']
    permitted_ports = {urlsplit(url).port or (443 if url.startswith('https:') else 80) for url in urls}
    evidence = list(state.get('browser_evidence', []))
    execution_metrics = dict(state.get('execution_metrics', {}))
    errors = list(state.get('errors', []))
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                for url in urls:
                    if not tool_budget_available({**state, 'execution_metrics': execution_metrics}):
                        break
                    execution_metrics = record_tool_call({**state, 'execution_metrics': execution_metrics}, 'playwright')
                    context = browser.new_context(ignore_https_errors=True)
                    try:
                        page = context.new_page()
                        page.route('**/*', lambda route: route.continue_() if allowed_url(route.request.url, state['hosts'], permitted_ports) else route.abort())
                        page.goto(url, wait_until='domcontentloaded', timeout=8000)
                        # Abort external redirects/subresources; do not click or submit forms.
                        if not allowed_url(page.url, state['hosts'], permitted_ports):
                            raise ValueError('Out-of-scope browser navigation blocked')
                        img = artifact_path(state, 'playwright', url, 'png')
                        page.screenshot(path=str(img), full_page=False, timeout=5000)
                        img.chmod(0o600)
                        evidence.append({'url': url, 'title': page.title()[:160],
                                         'screenshot': str(img.relative_to(ROOT))})
                    except Exception as exc:
                        errors.append(f'Playwright {url}: {str(exc)[:150]}')
                    finally:
                        context.close()
            finally:
                browser.close()
    except Exception as exc:
        errors.append('Playwright startup: ' + str(exc)[:180])
    return {'browser_evidence': evidence, 'execution_metrics': execution_metrics, 'errors': errors,
            'events': log(state, f'Playwright: {len(evidence)} screenshots')}
