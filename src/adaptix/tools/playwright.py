"""ADAPTIX unified module. Migrated from tested running code."""
from urllib.parse import urlsplit
from src.adaptix.config import config, ROOT
from src.adaptix.tools.registry import tool_registry
from src.adaptix.security.scope import allowed_url
from src.adaptix.evidence.storage import artifact_path
from src.adaptix.workflow.events import log


def browser_observe(state):
    urls = [x['url'] for x in state.get('http_services', [])]
    if not urls:
        return {'browser_evidence': [], 'events': log(state, 'Playwright: skipped; no live endpoints')}
    registry = tool_registry()
    if not registry['playwright']['enabled']:
        return {'browser_evidence': [], 'events': log(state, 'Playwright: disabled in config')}
    if not registry['playwright']['path']:
        return {'browser_evidence': [], 'errors': list(state.get('errors', [])) + ['Playwright package missing'],
                'events': log(state, 'Playwright: missing')}
    from playwright.sync_api import sync_playwright
    cfg = config('scope.yaml')['limits']
    permitted_ports = {urlsplit(url).port or (443 if url.startswith('https:') else 80) for url in urls}
    evidence = []
    errors = list(state.get('errors', []))
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                for url in urls:
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
    return {'browser_evidence': evidence, 'errors': errors,
            'events': log(state, f'Playwright: {len(evidence)} screenshots')}
