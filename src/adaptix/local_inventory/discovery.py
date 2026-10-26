"""Bounded, read-only discovery for local labs."""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlsplit, urlunsplit

import httpx
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from .scope import LocalScope
from .wordlists import load_wordlist

WORDS = ('admin', 'api', 'health', 'login', 'missing', 'redirect', 'robots.txt', 'status')


def local_url(value: str, origin: str, base: str | None = None) -> str | None:
    """Return a same-origin endpoint; query values and fragments are omitted."""
    try:
        url = urlsplit(urljoin(base or origin + "/", value))
        expected = urlsplit(origin)
        if (
            url.scheme != expected.scheme or url.netloc != expected.netloc
            or url.username or url.password
        ):
            return None
        return urlunsplit((url.scheme, url.netloc, url.path or "/", "", ""))
    except ValueError:
        return None


def navigable(url: str) -> bool:
    """Record file links as references; reserve navigation for web documents."""
    suffix = Path(urlsplit(url).path.rstrip("/")).suffix.lower()
    return not suffix or suffix in {".html", ".htm", ".php", ".asp", ".aspx", ".jsp"}


def find_ffuf() -> str | None:
    name = "ffuf.exe" if os.name == "nt" else "ffuf"
    bundled = Path.cwd() / ".tools" / name
    return str(bundled.resolve()) if bundled.is_file() else shutil.which("ffuf")


def ffuf_progress(stderr: bytes) -> dict:
    matches = re.findall(
        rb"Progress: \[(\d+)/(\d+)\].*?Errors: (\d+)", stderr,
    )
    if not matches:
        return {"complete": False, "completed": None, "total": None, "errors": None}
    completed, total, errors = map(int, matches[-1])
    return {"complete": completed == total and errors == 0,
            "completed": completed, "total": total, "errors": errors}


def ffuf_discover(
    scope: LocalScope, output: Path, *, fixture=False, wordlist: Path | None = None,
) -> dict:
    if fixture:
        words, provenance = WORDS, {"project": "bundled_fixture", "entries": len(WORDS)}
    else:
        words, provenance = load_wordlist(wordlist)
    rate, seconds = (5, 15) if fixture else (25, 300)
    (output / "wordlist.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    executable = find_ffuf()
    if not executable:
        raise RuntimeError("ffuf_missing")
    # Keep runtime files under this run, with explicit config and no secret/proxy inheritance.
    runtime = output / 'ffuf-runtime'
    runtime.mkdir()
    input_path = runtime / "paths.txt"
    input_path.write_text("\n".join(words) + "\n", encoding="utf-8")
    config = runtime / "ffufrc"
    config.write_text("", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k.upper() in {
        "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
    }}
    env['XDG_CONFIG_HOME'] = str(runtime)
    env['XDG_CONFIG_DIRS'] = str(runtime)
    raw_path = output / "ffuf.json"
    command = [
        executable, "-config", str(config), "-u", scope.connection_origin + "/FUZZ",
        "-H", "Host: " + urlsplit(scope.origin).netloc,
        "-w", str(input_path), "-of", "json", "-o", str(raw_path),
        "-mc", "200,204,301,302,307,308,401,403", "-t", "1", "-rate", str(rate),
        "-timeout", "3", "-maxtime", str(seconds), "-noninteractive",
    ]
    if not fixture:
        command.append("-ac")
    (output / 'ffuf-command.json').write_text(json.dumps(command, indent=2), encoding='utf-8')
    result = subprocess.run(
        command, cwd=runtime, env=env, capture_output=True, timeout=seconds + 10,
        shell=False, check=False,
    )
    (output / 'ffuf-progress.log').write_bytes(result.stderr)
    if result.returncode != 0:
        raise RuntimeError("ffuf_exit_nonzero")
    raw = json.loads(raw_path.read_text(encoding="utf-8-sig"))
    progress = ffuf_progress(result.stderr)
    progress['complete'] = progress['complete'] and progress['total'] == len(words)
    records = []
    for row in raw["results"]:
        url = local_url(scope.logical_url(row["url"]), scope.origin)
        if url and urlsplit(url).path.lstrip("/") in words:
            records.append({
                "url": url, "method": "GET", "status": int(row["status"]), "source": "ffuf",
                "content_type": row.get("content-type", ""),
            })
    if fixture and not records:
        raise RuntimeError("ffuf_empty_results")
    # Keep only reproducible evidence, not temp paths or ffuf's full commandline/config.
    raw_path.write_text(json.dumps({"results": records, "progress": progress,
                                    'config': {'method': 'GET'}}, indent=2),
                        encoding="utf-8")
    return {"records": records, "candidates": len(words), "rate_per_second": rate,
            "max_seconds": seconds, "wordlist": provenance, "progress": progress,
            "status": "success" if progress["complete"] else "partial",
            "auto_calibration": not fixture}


def browser_discover(
    scope: LocalScope, output: Path, seeds: list[str], channel: str | None = None,
    *, fixture=False,
) -> dict:
    origin = scope.origin
    request_limit = 40 if fixture else 240
    page_limit = 8 if fixture else 24
    records, pages, forms, blocked, errors, client_routes = [], [], [], [], [], []
    queue = list(dict.fromkeys([origin + "/"] + [
        url for url in seeds if local_url(url, origin) == url
    ]))
    visited = set()
    request_count = 0
    with httpx.Client(trust_env=False, follow_redirects=False, timeout=5) as transport, \
            sync_playwright() as p:
        options = {"headless": True, "args": scope.browser_args()}
        if channel:
            options["channel"] = channel
        browser = p.chromium.launch(**options)
        context = browser.new_context(
            service_workers="block", accept_downloads=False,
            viewport={"width": 1200, "height": 800},
        )
        context.set_default_timeout(5000)

        def gate(route):
            nonlocal request_count
            request = route.request
            reason = None
            if not local_url(request.url, origin):
                reason = "outside_lab"
            elif request.method not in {"GET", "HEAD"}:
                reason = "non_read_method"
            elif any(value in {"polling", "websocket"} for value in
                     parse_qs(urlsplit(request.url).query).get("transport", [])):
                reason = "realtime_disabled"
            elif request_count >= request_limit:
                reason = "request_limit"
            if reason:
                # Record just origin/path, never request headers or body.
                parsed = urlsplit(request.url)
                blocked.append({
                    "method": request.method,
                    "url": urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")),
                    "reason": reason,
                })
                route.abort()
            else:
                request_count += 1
                try:
                    headers = {k: v for k, v in request.headers.items() if k.lower() not in {
                        "host", "connection", "content-length", "accept-encoding",
                    }}
                    headers["Host"] = urlsplit(origin).netloc
                    with transport.stream(request.method, scope.connection_url(request.url),
                                          headers=headers) as received:
                        data = bytearray()
                        for chunk in received.iter_bytes(chunk_size=65536):
                            data.extend(chunk)
                            if len(data) > 16_000_000:
                                raise ValueError('response_size_limit')
                        decoded_headers = {key: value for key, value in received.headers.items()
                                           if key.lower() not in ('content-encoding', 'content-length', 'transfer-encoding')}
                        response = httpx.Response(received.status_code, headers=decoded_headers,
                                                  content=bytes(data))
                    headers = dict(response.headers)
                    # Let the browser receive decoded bytes without stale encoding/length.
                    for header in ["content-encoding", "content-length", "transfer-encoding"]:
                        headers.pop(header, None)
                    if response.is_redirect and "location" in headers:
                        destination = local_url(headers.pop("location"), origin, request.url)
                        if destination:
                            records.append({"url": destination, "method": "GET",
                                            "source": "redirect_reference"})
                            if destination not in visited and destination not in queue:
                                queue.append(destination)
                        else:
                            blocked.append({"method": "GET", "url": request.url,
                                            "reason": "outside_lab"})
                        # Redirects become explicit queue entries; the browser never
                        # follows an un-intercepted HTTP redirect chain itself.
                    route.fulfill(status=response.status_code, headers=headers, body=response.content)
                except Exception:
                    errors.append({"url": local_url(request.url, origin),
                                   "code": "request_transport_failed"})
                    route.abort()

        context.route("**/*", gate)
        # A routed socket without connect_to_server() never opens an upstream connection.
        # Avoid close() in this sync callback: it can wait on its own event dispatch.
        def block_socket(ws):
            parsed = urlsplit(ws.url)
            blocked.append({"method": "WEBSOCKET", "reason": "websocket_disabled",
                            "url": urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))})

        context.route_web_socket("**/*", block_socket)
        page = context.new_page()
        context.on("page", lambda popup: popup.close())

        def response_seen(response):
            url = local_url(response.url, origin)
            if url:
                records.append({
                    "url": url, "method": response.request.method,
                    "status": response.status, "source": "playwright_network",
                })

        page.on("response", response_seen)
        try:
            while queue and len(visited) < page_limit:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                operation = "navigate"
                try:
                    response = page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    if not response:
                        errors.append({"url": url, "code": "page_no_response"})
                        continue
                    render_wait = "networkidle"
                    operation = "render_wait"
                    try:
                        page.wait_for_load_state("networkidle", timeout=3000)
                    except PlaywrightTimeoutError:
                        render_wait = "bounded_wait_expired"
                    if response.status >= 400:
                        pages.append({"url": url, "title": page.title(), "status": response.status,
                                      "render_wait": render_wait})
                        continue
                    if url == origin + "/":
                        operation = "root_ready"
                        if fixture:
                            page.locator("html[data-recon-ready='true']").wait_for(timeout=5000)
                        else:
                            # SPA content can be visible while the body itself has no layout box.
                            page.locator("body").wait_for(state="attached")
                        operation = "screenshot"
                        page.screenshot(path=str(output / "homepage.png"))
                    operation = "read_dom"
                    title = page.title()
                    pages.append({"url": url, "title": title, "status": response.status,
                                  "render_wait": render_wait})
                    for href in page.locator("a[href]").evaluate_all(
                        "nodes => nodes.map(n => n.getAttribute('href'))"
                    ):
                        child = local_url(href, origin, page.url)
                        if child:
                            fragment = urlsplit(urljoin(page.url, href)).fragment
                            if fragment.startswith("/"):
                                client_route = child + "#" + fragment.split("?", 1)[0]
                                if client_route not in client_routes:
                                    client_routes.append(client_route)
                            records.append({
                                "url": child, "method": "GET", "source": "playwright_link",
                            })
                            if navigable(child) and child not in visited and child not in queue:
                                queue.append(child)
                    for form in page.locator("form").evaluate_all("""nodes => nodes.map(n => ({
                        action: n.getAttribute('action') || '',
                        method: (n.getAttribute('method') || 'GET').toUpperCase(),
                        fields: Array.from(n.elements).map(e => e.name).filter(Boolean)
                    }))"""):
                        action = local_url(form["action"], origin, page.url)
                        if action:
                            forms.append({**form, "action": action, "submitted": False})
                            records.append({
                                "url": action, "method": form["method"],
                                "source": "playwright_form",
                            })
                except Exception as exc:
                    errors.append({"url": url, "code": "page_operation_failed",
                                   "operation": operation, "error_type": type(exc).__name__})
        finally:
            context.close()
            browser.close()
    if queue:
        errors.append({"code": "page_limit"})
    if any(row["reason"] == "request_limit" for row in blocked):
        errors.append({"code": "request_limit"})
    evidence = {
        "records": records, "pages": pages, "forms": forms,
        "blocked": blocked, "errors": errors, "requests_sent": request_count,
        "client_routes": sorted(client_routes),
        "remaining_pages": len(queue),
        "limits": {"pages": page_limit, "requests": request_limit},
    }
    (output / "browser.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    if errors:
        return {**evidence, "status": "partial"}
    return {**evidence, "status": "success"}


def merge_records(records: list[dict]) -> list[dict]:
    merged = {}
    for row in records:
        key = (row["method"], row["url"])
        item = merged.setdefault(key, {
            "method": key[0], "url": key[1], "sources": [], "statuses": [], "observed": False,
        })
        if row["source"] not in item["sources"]:
            item["sources"].append(row["source"])
        if row.get("status") is not None:
            item["observed"] = True
            if row["status"] not in item["statuses"]:
                item["statuses"].append(row["status"])
    for item in merged.values():
        item["sources"].sort()
        item["statuses"].sort()
    return [merged[key] for key in sorted(merged)]
