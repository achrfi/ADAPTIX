"""Live LangGraph node progress for the terminal dashboard."""
import json
import os
import time

from src.adaptix.evidence.storage import artifact_path


def progress_path(state):
    if not state or not state.get('run_id'):
        return None
    return artifact_path(state, 'progress', 'workflow', 'json')


def write_progress(state, node, phase, started_at=None, duration=None, event=''):
    path = progress_path(state)
    if path is None:
        return None
    started = float(started_at or time.time())
    payload = {
        'run_id': state.get('run_id'),
        'node': node,
        'phase': phase,
        'status': state.get('status') or phase,
        'stop_reason': state.get('stop_reason'),
        'iteration': int(state.get('iterations', 0) or 0),
        'run_started_at': state.get('run_started_at'),
        'node_started_at': started,
        'node_seconds': None if duration is None else round(float(duration), 3),
        'updated_at': time.time(),
        'event': str(event or '')[:400],
    }
    temporary = path.with_name(f'{path.name}.{os.getpid()}.tmp')
    try:
        temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding='utf-8')
        temporary.chmod(0o600)
        os.replace(temporary, path)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    return path
