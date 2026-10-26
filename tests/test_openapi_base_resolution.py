"""An OpenAPI document must resolve its routes against its own origin.

Measured on a real lab: VAmPI serves `servers: [{"url": ""}]`. `urljoin('/openapi.json', '')`
returns '/openapi.json' itself, so every documented route was appended to the spec
path - `http://127.0.0.1:18080/openapi.json/users/v1` - and no observation could ever
match a documented collection/detail pair. The result was zero scenario candidates
on an application with an obvious BOLA, which reads exactly like "nothing found".
"""
import httpx
import pytest

from src.adaptix.tools import discovery


class _Response:
    def __init__(self, payload, url):
        self._payload = payload
        self.url = url
        self.status_code = 200
        self.headers = {'content-type': 'application/json'}
        self.content = b'{}'
        self.text = '{}'

    def json(self):
        return self._payload

    def is_success(self):
        return True


def _state(url):
    # The spec URL must already be a known/eligible target: api_discover refuses an
    # endpoint the run has not observed or probed.
    state = {'hosts': ['127.0.0.1'], 'scope_ports': [18080], 'scope_aliases': {},
             'scope_networks': [], 'api_observations': [], 'api_operations': [],
             'identity_context': {'identities': [{'name': 'a'}, {'name': 'b'}]},
             'planned_actions': [{'tool': 'api_discover', 'target': url}],
             'execution_metrics': {}, 'tool_call_budget': 20, 'raw_bytes': 0,
             'http_services': [{'url': url, 'validated': True}]}
    return state


@pytest.mark.parametrize('servers', [[{'url': ''}], [], [{}], None])
def test_empty_server_url_resolves_to_origin(monkeypatch, tmp_path, servers):
    doc = {'openapi': '3.0.1', 'paths': {'/books/v1': {'get': {}},
                                          '/books/v1/{book_title}': {'get': {'security': [{'bearerAuth': []}]}}}}
    if servers is not None:
        doc['servers'] = servers
    url = 'http://127.0.0.1:18080/openapi.json'
    monkeypatch.setattr(discovery, 'read_get', lambda *a, **k: _Response(doc, url))
    monkeypatch.setattr(discovery, 'artifact_path', lambda *a, **k: str(tmp_path / 'x.json'))
    monkeypatch.setattr(discovery, 'save_text', lambda *a, **k: None)
    out = discovery.api_discover(_state(url))
    urls = {o['url'] for o in out.get('api_operations', [])}
    assert 'http://127.0.0.1:18080/books/v1' in urls, urls
    assert 'http://127.0.0.1:18080/books/v1/{book_title}' in urls, urls
    assert not any('/openapi.json/' in u for u in urls), 'routes must not hang off the spec path'


def test_declared_server_url_is_still_honoured(monkeypatch, tmp_path):
    doc = {'openapi': '3.0.1', 'servers': [{'url': '/api/v2'}],
           'paths': {'/books': {'get': {}}}}
    url = 'http://127.0.0.1:18080/openapi.json'
    monkeypatch.setattr(discovery, 'read_get', lambda *a, **k: _Response(doc, url))
    monkeypatch.setattr(discovery, 'artifact_path', lambda *a, **k: str(tmp_path / 'x.json'))
    monkeypatch.setattr(discovery, 'save_text', lambda *a, **k: None)
    out = discovery.api_discover(_state(url))
    urls = {o['url'] for o in out.get('api_operations', [])}
    assert 'http://127.0.0.1:18080/api/v2/books' in urls, urls
