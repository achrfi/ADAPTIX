import json
from src.adaptix.tools import discovery


class FakeResponse:
    def __init__(self, status_code, json_body):
        self.status_code = status_code
        self._json = json_body
        self.content = json.dumps(json_body).encode()
        self.is_success = 200 <= status_code < 300
        self.headers = {}
        self.text = ""

    def json(self):
        return self._json


def test_openapi_without_servers_resolves_to_origin_not_spec_path(monkeypatch):
    state = {
        "run_id": "p0a-repro",
        "hosts": ["127.0.0.1"],
        "target": ["127.0.0.1"],
        "services": [{"host": "127.0.0.1", "port": 18080, "service": "http"}],
        "planned_actions": [
            {"tool": "api_discover", "target": "http://127.0.0.1:18080/openapi.json"}
        ],
    }
    spec = {
        "openapi": "3.0.0",
        "paths": {"/users/v1/_debug": {"get": {"summary": "debug"}}},
    }

    def fake_read_get(working_state, url, headers=None):
        return FakeResponse(200, spec)

    monkeypatch.setattr(discovery, "read_get", fake_read_get)

    update = discovery.api_discover(state)
    urls = {op["url"] for op in update.get("api_operations", [])}
    print("OPERATIONS FOUND:", urls)

    assert "http://127.0.0.1:18080/users/v1/_debug" in urls
    assert not any("/openapi.json/" in u for u in urls)
def test_openapi_with_relative_servers_uses_that_base(monkeypatch):
    state = {
        "run_id": "p0a-relative",
        "hosts": ["127.0.0.1"],
        "target": ["127.0.0.1"],
        "services": [{"host": "127.0.0.1", "port": 18080, "service": "http"}],
        "planned_actions": [
            {"tool": "api_discover", "target": "http://127.0.0.1:18080/openapi.json"}
        ],
    }
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "/api"}],
        "paths": {"/users/v1/_debug": {"get": {"summary": "debug"}}},
    }

    def fake_read_get(working_state, url, headers=None):
        return FakeResponse(200, spec)

    monkeypatch.setattr(discovery, "read_get", fake_read_get)

    update = discovery.api_discover(state)
    urls = {op["url"] for op in update.get("api_operations", [])}
    print("RELATIVE SERVERS OPERATIONS:", urls)

    assert "http://127.0.0.1:18080/api/users/v1/_debug" in urls


def test_openapi_with_out_of_scope_absolute_server_is_not_used(monkeypatch):
    state = {
        "run_id": "p0a-outofscope",
        "hosts": ["127.0.0.1"],
        "target": ["127.0.0.1"],
        "services": [{"host": "127.0.0.1", "port": 18080, "service": "http"}],
        "planned_actions": [
            {"tool": "api_discover", "target": "http://127.0.0.1:18080/openapi.json"}
        ],
    }
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "http://evil.example.com/api"}],
        "paths": {"/users/v1/_debug": {"get": {"summary": "debug"}}},
    }

    def fake_read_get(working_state, url, headers=None):
        return FakeResponse(200, spec)

    monkeypatch.setattr(discovery, "read_get", fake_read_get)

    update = discovery.api_discover(state)
    urls = {op["url"] for op in update.get("api_operations", [])}
    print("OUT-OF-SCOPE SERVER OPERATIONS:", urls)

    assert not any("evil.example.com" in u for u in urls)
