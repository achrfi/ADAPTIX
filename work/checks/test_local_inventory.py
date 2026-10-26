"""Live-run inventory contracts copied from the reference, with local-only fixtures."""
from contextlib import contextmanager
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import runpy
import sys
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.adaptix.local_inventory import discovery, workflow
from src.adaptix.local_inventory.scope import LocalScope, ScopeError
from src.adaptix.local_inventory.wordlists import load_wordlist


@pytest.mark.parametrize('target', [
    '', 'http://0.0.0.0:3000', 'http://192.0.2.1', 'http://public.invalid',
    'http://127.0.0.1:3000/admin', 'http://127.0.0.1:3000/#/login',
    'http://user:secret@localhost:3000', 'http://localhost:0',
])
def test_only_explicit_loopback_origins_are_accepted(target):
    with pytest.raises(ScopeError):
        LocalScope.from_target(target)


def test_localhost_resolution_must_be_entirely_loopback(monkeypatch):
    from src.adaptix.local_inventory import scope
    monkeypatch.setattr(scope.socket, 'getaddrinfo', lambda *a, **kw: [
        (None, None, None, None, ('127.0.0.1', 3000)),
        (None, None, None, None, ('192.0.2.2', 3000))])
    with pytest.raises(ScopeError):
        LocalScope.from_target('http://localhost:3000')


def test_url_inventory_drops_query_values_and_stays_on_one_origin():
    origin = 'http://127.0.0.1:3000'
    assert discovery.local_url('/next?token=secret#/client', origin) == origin + '/next'
    assert discovery.local_url('http://127.0.0.1:3001/next', origin) is None
    assert discovery.local_url('https://127.0.0.1:3000/next', origin) is None


@pytest.mark.parametrize('completed,total,errors,expected', [
    (4750, 4750, 0, 'success'), (4749, 4750, 0, 'partial'),
    (4750, 4750, 1, 'partial'), (0, 0, 0, 'partial'),
])
def test_ffuf_uses_full_list_reference_flags_and_honest_progress(
        tmp_path, monkeypatch, completed, total, errors, expected):
    words, meta = load_wordlist()
    assert len(words) == meta['entries'] == 4750
    monkeypatch.setattr(discovery, 'find_ffuf', lambda: '/usr/bin/ffuf')
    monkeypatch.setenv('OPENAI_API_KEY', 'SYNTHETIC_SECRET')
    monkeypatch.setenv('HTTP_PROXY', 'http://outside.invalid:8080')

    def run(argv, **kwargs):
        assert argv[argv.index('-t') + 1] == '1'
        assert argv[argv.index('-rate') + 1] == '25'
        assert argv[argv.index('-maxtime') + 1] == '300'
        assert argv[argv.index('-timeout') + 1] == '3'
        assert '-ac' in argv and '-r' not in argv and '-recursion' not in argv
        assert len(Path(argv[argv.index('-w') + 1]).read_text().splitlines()) == 4750
        assert 'OPENAI_API_KEY' not in kwargs['env'] and 'HTTP_PROXY' not in kwargs['env']
        assert 'HOME' not in kwargs['env']
        Path(argv[argv.index('-o') + 1]).write_text(json.dumps({'results': [
            {'url': 'http://127.0.0.1:3000/robots.txt', 'status': 200,
             'content-type': 'text/plain'}]}))
        return SimpleNamespace(returncode=0, stderr=(
            f'Progress: [{completed}/{total}] :: Errors: {errors}\n').encode())
    monkeypatch.setattr(discovery.subprocess, 'run', run)
    result = discovery.ffuf_discover(LocalScope.from_target('http://127.0.0.1:3000'), tmp_path)
    assert result['status'] == expected
    assert result['candidates'] == 4750
    saved = json.loads((tmp_path / 'ffuf.json').read_text())
    assert saved['config']['method'] == 'GET'
    assert 'commandline' not in saved


def test_reference_only_records_are_not_marked_as_observed():
    rows = discovery.merge_records([
        {'url': 'http://127.0.0.1:3000/contact', 'method': 'GET', 'status': 200, 'source': 'ffuf'},
        {'url': 'http://127.0.0.1:3000/contact', 'method': 'POST', 'source': 'playwright_form'}])
    assert rows[0]['observed'] is True
    assert rows[1]['observed'] is False and rows[1]['statuses'] == []


@contextmanager
def local_server(root_factory=None, redirect=None):
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            hits.append(('POST', self.path))
            self.send_response(204)
            self.end_headers()

        def do_GET(self):
            hits.append(('GET', self.path))
            if self.path == '/jump' and redirect:
                self.send_response(302)
                self.send_header('Location', redirect)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            content = (root_factory(self.server.server_port) if self.path == '/' and root_factory
                       else '<html><title>Next</title><body>local fixture</body></html>')
            encoded = gzip.compress(content.encode())
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Encoding', 'gzip')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', hits
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def test_real_browser_records_dom_and_network_without_writes_or_escape(tmp_path):
    with local_server() as (trap, outside_hits):
        def root(port):
            return f'''<html data-recon-ready="true"><title>Live fixture</title><body>
                <a href="/next">Next</a><a href="/jump">Jump</a>
                <a href="/archive.zip">File reference</a>
                <form action="/write" method="POST"><input name="record" value="private"></form>
                <img src="{trap}/must-not-load?token=SECRET">
                <script>fetch('/api/info?token=SECRET');
                fetch('/write', {{method:'POST', body:'private'}}).catch(() => {{}});
                new WebSocket('ws://127.0.0.1:{port}/socket');</script></body></html>'''
        with local_server(root, trap + '/must-not-follow') as (origin, hits):
            result = discovery.browser_discover(LocalScope.from_target(origin), tmp_path, [], fixture=True)
    assert outside_hits == []
    assert not any(method == 'POST' for method, path in hits)
    assert not any(path.startswith('/socket') or path == '/archive.zip' for method, path in hits)
    assert any(row['reason'] == 'non_read_method' for row in result['blocked'])
    assert any(row['reason'] == 'outside_lab' for row in result['blocked'])
    assert any(row['reason'] == 'websocket_disabled' for row in result['blocked'])
    assert any(row['url'].endswith('/api/info') for row in result['records'])
    assert result['forms'][0]['submitted'] is False
    assert (tmp_path / 'homepage.png').stat().st_size > 0
    assert 'SECRET' not in json.dumps(result)
    assert result['status'] == 'success'


@pytest.mark.parametrize('ffuf_status,ai_error,expected', [
    ('success', False, 'success'), ('partial', False, 'partial'), ('success', True, 'partial'),
])
@pytest.mark.parametrize('browser_root_observed', [True, False])
def test_pipeline_preserves_results_and_never_calls_partial_success(
        tmp_path, monkeypatch, ffuf_status, ai_error, expected, browser_root_observed):
    origin = 'http://127.0.0.1:3000'
    row = {'url': origin + '/', 'method': 'GET', 'status': 200, 'source': 'ffuf'}
    monkeypatch.setattr(workflow, 'ffuf_discover', lambda *a, **kw: {
        'records': [row], 'status': ffuf_status, 'progress': {'complete': ffuf_status == 'success'},
        'candidates': 4750, 'auto_calibration': True})
    monkeypatch.setattr(workflow, 'browser_discover', lambda *a, **kw: {
        'records': [{**row, 'source': 'playwright_network'}] if browser_root_observed else [],
        'pages': [{}], 'status': 'success', 'requests_sent': 1,
        'errors': [], 'remaining_pages': 0, 'forms': [], 'blocked': [], 'client_routes': []})
    monkeypatch.setattr(workflow, 'summarize', lambda *a: (_ for _ in ()).throw(RuntimeError('SECRET')))
    result = workflow.build_graph(LocalScope.from_target(origin), tmp_path, ai=ai_error).invoke({})
    assert result['report']['status'] == (expected if browser_root_observed else 'partial')
    assert result['report']['endpoints'][0]['observed'] is True
    assert 'SECRET' not in json.dumps(result['report'])


def test_module_recon_command_dispatches_to_local_inventory(monkeypatch):
    from src.adaptix.local_inventory import cli
    main = MagicMock(return_value=0)
    monkeypatch.setattr(cli, 'main', main)
    monkeypatch.setattr(sys, 'argv', ['adaptix', 'recon', '--target', 'http://127.0.0.1:3000'])
    with pytest.raises(SystemExit) as result:
        runpy.run_module('src.adaptix', run_name='__main__')
    assert result.value.code == 0
    main.assert_called_once_with(['--target', 'http://127.0.0.1:3000'])
