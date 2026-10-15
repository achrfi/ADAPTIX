"""Versioned, resettable two-account fixture with protected, vulnerable and public controls."""
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = 'adaptix-idor-fixture-v1'
ACCOUNTS = {'owner': 'Bearer lab-owner-only', 'other': 'Bearer lab-other-only'}
OBJECT = {'id': '42', 'owner': 'owner', 'private': True, 'content': 'Disposable lab record'}


class FixtureLab:
    def __init__(self):
        self.hits = []
        self.reset()
        lab = self
        class Handler(BaseHTTPRequestHandler):
            def handle(self):
                try:
                    super().handle()
                except (ConnectionResetError, BrokenPipeError):
                    pass  # Version probes may close connections before a response.
            def do_GET(self):
                identity = next((name for name, credential in ACCOUNTS.items()
                                 if self.headers.get('Authorization') == credential), None)
                lab.hits.append({'method': 'GET', 'path': self.path, 'identity': identity})
                if self.path == '/':
                    body = b'<html><title>ADAPTIX I1-I6 Lab</title><body>Resettable read-only lab</body></html>'
                    self.send_response(200); self.send_header('Content-Type', 'text/html'); self.end_headers(); self.wfile.write(body)
                    return
                if self.path == '/readonly-policy-check':
                    body = b'<html><title>Read-only policy check</title><body><script>fetch("/should-not-write", {method:"POST"}).catch(()=>{});</script></body></html>'
                    self.send_response(200); self.send_header('Content-Type', 'text/html'); self.end_headers(); self.wfile.write(body)
                    return
                if self.path == '/whoami':
                    status, data = (200, {'identity': identity}) if identity else (401, {'error': 'authentication required'})
                elif self.path == '/public/orders/42':
                    status, data = 200, {'id': '42', 'public': True}
                elif self.path in ('/vulnerable/orders/42', '/protected/orders/42'):
                    if not identity: status, data = 401, {'error': 'authentication required'}
                    elif self.path.startswith('/protected/') and identity != 'owner': status, data = 403, {'error': 'forbidden'}
                    else: status, data = 200, lab.object
                else:
                    status, data = 404, {'error': 'unknown lab path'}
                self.send_response(status); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self.wfile.write(json.dumps(data, sort_keys=True).encode())
            def do_POST(self):
                lab.hits.append({'method': 'POST', 'path': self.path})
                self.send_response(405); self.end_headers()
            def log_message(self, *args):
                pass
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}'

    def reset(self):
        self.object = dict(OBJECT)

    def manifest(self):
        return {'version': VERSION, 'snapshot_sha256': hashlib.sha256(json.dumps(OBJECT, sort_keys=True).encode()).hexdigest(),
                'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'scope': self.url, 'reset': 'FixtureLab.reset()',
                'accounts': list(ACCOUNTS), 'ground_truth': {'vulnerable': 'IDOR', 'protected': 'access correctly denied', 'public': 'not IDOR'},
                'lateral_movement': False, 'operations': ['GET']}

    def scenario(self, mode):
        return {'name': mode + '-order', 'base_url': self.url,
                'path_template': '/' + mode + '/orders/{object_id}', 'object_id': '42', 'method': 'GET',
                'owner_identity': {'name': 'owner', 'headers': {'Authorization': ACCOUNTS['owner']}},
                'other_identity': {'name': 'other', 'headers': {'Authorization': ACCOUNTS['other']}},
                'ground_truth': {'owner': 'owner', 'object_id': '42', 'private': mode != 'public', 'identities_valid': True}}

    def __enter__(self):
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.reset()
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=3)
