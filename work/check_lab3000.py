"""Operator-run ffuf smoke check of the fixed local lab; no planner integration."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.parse import urlsplit
import uuid

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.recon_local import inspect_with_model, load_words

TARGET = 'http://127.0.0.1:3000'


def read_response(client, path):
    time.sleep(0.5)
    with client.stream('GET', TARGET + path) as response:
        data = bytearray()
        for chunk in response.iter_bytes(chunk_size=16384):
            data.extend(chunk)
            if len(data) > 1_000_000:
                raise ValueError('Lab response exceeds the one-megabyte evidence limit')
        return {'path': path, 'status': response.status_code, 'bytes': len(data),
                'body_sha256': hashlib.sha256(data).hexdigest(),
                'content_type': response.headers.get('content-type', '')}


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    words = load_words()
    name = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:6]
    output = ROOT / 'work/lab3000-runs' / name
    output.mkdir(parents=True, mode=0o700)
    summary = {'status': 'failed', 'target': TARGET, 'autonomous_graph_integration': False}
    try:
        with httpx.Client(trust_env=False, timeout=5, follow_redirects=False) as client:
            root = read_response(client, '/')
            if root['status'] != 200:
                raise ValueError('Expected the specified lab root to respond with HTTP 200')
            baseline = read_response(client, '/adaptix-missing-' + uuid.uuid4().hex)
            wordlist = output / 'wordlist.txt'
            wordlist.write_text('\n'.join(words) + '\n')
            ffufrc = output / 'ffufrc'
            ffufrc.write_text('[http]\nfollowredirects = false\n[general]\nrecursion = false\n')
            config_directory = output / 'config'
            config_directory.mkdir()
            binary = shutil.which('ffuf')
            if not binary:
                raise RuntimeError('ffuf is not installed')
            command = [binary, '-config', str(ffufrc), '-u', TARGET + '/FUZZ',
                       '-w', str(wordlist), '-X', 'GET', '-t', '1', '-rate', '2',
                       '-timeout', '3', '-maxtime', '20', '-mc', '200-399,401,403',
                       '-noninteractive', '-s', '-of', 'json', '-o', str(output / 'ffuf.json')]
            environment = {key: value for key, value in os.environ.items()
                           if key.lower() not in ('http_proxy', 'https_proxy', 'all_proxy', 'ffuf_config')}
            environment.update({'NO_PROXY': '127.0.0.1', 'XDG_CONFIG_HOME': str(config_directory)})
            result = subprocess.run(command, cwd=output, env=environment, stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=30, check=False)
            (output / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
            (output / 'ffuf.log').write_text(result.stdout + '\n' + result.stderr)
            if result.returncode:
                raise RuntimeError(f'ffuf exited with status {result.returncode}')
            rows = json.loads((output / 'ffuf.json').read_text())['results']
            if len(rows) > len(words):
                raise ValueError('ffuf returned more results than the bounded input')
            observations, verification = [], []
            for row in rows:
                url = urlsplit(row['url'])
                if (url.scheme, url.netloc) != ('http', '127.0.0.1:3000'):
                    raise ValueError('Result outside the fixed lab origin')
                if url.path not in {'/' + word for word in words} or url.query or url.fragment:
                    raise ValueError('Result outside the fixed path list')
                response = read_response(client, url.path)
                if response['status'] != row['status']:
                    raise ValueError('Independent status verification disagrees with ffuf')
                response['matches_missing_path_response'] = (
                    response['status'] == baseline['status']
                    and response['body_sha256'] == baseline['body_sha256'])
                verification.append(response)
                observations.append({'path': url.path, 'status': row['status']})
            if len({row['path'] for row in observations}) != len(observations):
                raise ValueError('Duplicate result paths')
            observations.sort(key=lambda row: row['path'])
            (output / 'evidence.json').write_text(json.dumps({
                'root': root, 'missing_path_control': baseline,
                'observations': observations, 'independent_checks': verification}, indent=2) + '\n')
        print('ffuf completed; statuses independently checked; invoking real local model', flush=True)
        model = inspect_with_model(observations, output)
        summary.update({'status': 'passed', 'mode': 'operator-run-fixed-local-lab',
                        'wordlist_entries': len(words), 'http_observations': len(observations),
                        'matching_missing_path_responses': sum(
                            row['matches_missing_path_response'] for row in verification),
                        'route_existence_verified': False,
                        'scope': 'HTTP response discovery/classification only; no vulnerability testing', **model})
    except Exception as exc:
        summary.update({'error_type': type(exc).__name__, 'error': str(exc)})
        raise
    finally:
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps({'status': summary['status'], 'results': str(output.relative_to(ROOT))}), flush=True)


if __name__ == '__main__':
    main()
