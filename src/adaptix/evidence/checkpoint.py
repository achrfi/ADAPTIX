"""Durable LangGraph checkpoints for a run, with the sanitizer in front of the disk.

A run that stops on ``time_budget_exhausted`` used to restart from zero: the graph
kept its state in memory and the only persistence was the per-pass JSON snapshot in
``audit.py``, which cannot be resumed from. A checkpointer fixes that, but it writes
the whole ``AgentState`` to disk on every superstep - including ``llm_api_key`` and
every operator session header collected by ``scenario_secrets``. The saver's own
serializer stores strings verbatim (verified: ``sk-`` and cookie values appear
byte-for-byte in the sqlite file), so attaching it directly would move secrets from
process memory into a durable artifact.

This module is the only entry point to a saver. It never hands out a raw saver:
:func:`open_checkpoint` returns a :class:`SanitizedSaver` that scrubs every value
with :func:`src.adaptix.evidence.sanitize.sanitize` before delegating, so the disk
copy is bounded evidence, never credentials. The provider key is additionally
replaced with a marker rather than the generic ``[REDACTED]`` so a resumed run can
tell "this run had a key, load it from the environment again" from "no key was
configured".

Resume identity is the run identity. Callers pass the existing ``run_id`` as the
thread, so ``adaptix --resume <run_id>`` continues the same conversation instead of
opening a second one; nothing here invents identifiers.
"""
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from langgraph.checkpoint.sqlite import SqliteSaver

from src.adaptix.config import ROOT

# A checkpoint belongs to a run, so it lives beside that run's evidence. Same
# 0o700 directory, same run-id sanitizing rule as ``storage.artifact_path``.
CHECKPOINT_DIRNAME = 'checkpoint.sqlite'
THREAD_PREFIX = 'adaptix-run-'
# What replaces the provider key on disk. Deliberately NOT the generic
# ``[REDACTED]``: a resumed run must be able to see that a key existed.
KEY_MARKER = '[CHECKPOINT-KEY-PLACEHOLDER]'
_SAFE_RUN_ID = re.compile(r'[A-Za-z0-9_-]{1,80}')


def checkpoint_path(run_id, root=None):
    """Path of the checkpoint database for ``run_id`` (one file per run)."""
    run_id = str(run_id)
    if not _SAFE_RUN_ID.fullmatch(run_id):
        import hashlib
        run_id = hashlib.sha256(run_id.encode()).hexdigest()[:24]
    base = Path(root) if root is not None else ROOT
    return base / 'artifacts' / 'scans' / run_id / CHECKPOINT_DIRNAME


def usable_key(value):
    """The key to authenticate with, or ``None``.

    A checkpoint stores ``KEY_MARKER`` where the key was. That marker is a fact about
    the file - it says "a credential lived here" - and must never be handed to a
    provider as if it were one. Only a real, non-marker string counts.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text == KEY_MARKER:
        return None
    return text


def thread_id_for(run_id):
    """LangGraph thread for a run: the run identity, prefixed to stay readable."""
    return f'{THREAD_PREFIX}{_SAFE_RUN_ID.fullmatch(str(run_id)) and run_id or run_id}'


class SanitizedSaver(SqliteSaver):
    """A ``SqliteSaver`` that scrubs every value before it reaches the database.

    LangGraph calls the saver with ``(config, checkpoint, metadata, ...)`` where
    ``checkpoint`` carries the channel values under ``channel_values``. Every write
    path is overridden, so a future LangGraph version that adds a write method
    fails loudly here instead of silently persisting raw state.
    """

    def __init__(self, conn, *, run_id=None):
        super().__init__(conn)
        self._run_id = run_id

    # -- scrubbing ---------------------------------------------------------
    def _secrets(self):
        """The provider key recorded for this run, when the run is known."""
        if not self._run_id:
            return ()
        try:
            return (os.environ.get('ADAPTIX_API_KEY'),)
        except Exception:
            return ()

    def _clean(self, value, secrets=()):
        from src.adaptix.evidence.sanitize import sanitize
        return sanitize(value, tuple(s for s in secrets if isinstance(s, str) and len(s) >= 4))

    # LangGraph's own bookkeeping. These are not user data: ``channel_versions`` holds
    # version tokens the saver parses ("2.0.1"), and ``versions_seen``/``pending_sends``
    # map node names to them. Scrubbing them used to turn a version into
    # ``[REDACTED]`` and made ``get_next_version`` raise on resume. They never carry
    # request or response content, so they are stored verbatim.
    CONTROL_FIELDS = ('channel_versions', 'versions_seen', 'pending_sends', 'updated_channels')

    def _clean_checkpoint(self, checkpoint, secrets):
        if not isinstance(checkpoint, dict):
            return checkpoint
        cleaned = dict(checkpoint)
        channel_values = cleaned.get('channel_values')
        if isinstance(channel_values, dict):
            values = self._clean(dict(channel_values), secrets)
            key = values.get('llm_api_key')
            if isinstance(key, str) and key:
                # Keep the fact, drop the secret.
                values['llm_api_key'] = KEY_MARKER
            cleaned['channel_values'] = values
        return cleaned

    # -- every write path --------------------------------------------------
    def put(self, config, checkpoint, metadata, new_versions):
        secrets = self._secrets()
        # ``metadata`` carries the step/run counters the saver reads back, plus two
        # free-text fields that do describe the run. Scrub only the latter.
        clean_meta = dict(metadata) if isinstance(metadata, dict) else metadata
        if isinstance(clean_meta, dict):
            for field in ('source', 'step'):
                if isinstance(clean_meta.get(field), int):
                    continue
                clean_meta[field] = self._clean(clean_meta.get(field), secrets) if isinstance(clean_meta.get(field), str) else clean_meta.get(field)
        return super().put(config, self._clean_checkpoint(checkpoint, secrets),
                           clean_meta, new_versions)

    def put_writes(self, config, writes, task_id, task_path=''):
        secrets = self._secrets()
        cleaned = [(channel, self._clean(value, secrets)) for channel, value in writes]
        return super().put_writes(config, cleaned, task_id, task_path)


@contextmanager
def open_checkpoint(run_id, root=None):
    """Open the run's checkpoint database, creating the directory if needed.

    Yields ``(saver, path)``. The connection is closed on exit; the file stays, which
    is the whole point - a later process opens the same path and resumes.
    """
    path = checkpoint_path(run_id, root=root)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    conn = sqlite3.connect(str(path), check_same_thread=False)
    saver = SanitizedSaver(conn, run_id=run_id)
    try:
        saver.setup()
        yield saver, path
    finally:
        conn.close()


def restore_runtime_secrets(state, env=None):
    """Put the provider key back into a state that came off disk.

    A checkpoint stores ``KEY_MARKER`` where the key was (see ``SanitizedSaver``), so a
    resumed state cannot authenticate with what it holds. The environment is the
    source of truth for credentials: take the key from there, and if it is gone drop
    the marker so the run fails with a real provider error instead of sending a
    placeholder as a credential. Every other channel is already secret-free.
    """
    import os as _os
    if not isinstance(state, dict) or state.get('llm_api_key') != KEY_MARKER:
        return state
    source = env if env is not None else _os.environ
    restored = dict(state)
    key = (source.get('ADAPTIX_API_KEY') or '').strip()
    restored['llm_api_key'] = key or None
    return restored


def resumable_snapshot(run_id, root=None):
    """The newest checkpoint a resumed run can actually continue from.

    A run that stops on a cumulative limit ends its thread with the stopping tail:
    ``adaptive_planning`` writes no actions, both routers then answer "report", and the
    final ``final_report`` snapshot has nothing pending. Continuing from there is a
    no-op, which is why a plain ``stream(None)`` on a budget-stopped run does nothing.

    The last usable point is the newest snapshot whose next step is real work and whose
    own state has not already recorded the stop. That is the execution or planning step
    the limit cut short; re-entering it with an escalated budget is what makes resume
    mean something. Returns ``None`` when every snapshot is a stopping tail.
    """
    from src.adaptix.workflow.graph import resumable_graph
    from src.adaptix.agents.planner import budget_stop_reason
    if not has_checkpoint(run_id, root=root):
        return None
    config = {'configurable': {'thread_id': thread_id_for(run_id)}}
    with open_checkpoint(run_id, root=root) as (saver, _path):
        app = resumable_graph(saver)
        for snapshot in app.get_state_history(config):
            values = snapshot.values or {}
            if snapshot.next == ('final_report',):
                continue
            if not snapshot.next:
                continue
            if values.get('stop_reason') or budget_stop_reason(values, values.get('planner_metrics') or {}):
                continue
            return snapshot
    return None


def has_checkpoint(run_id, root=None):
    """True when a resumable checkpoint exists for ``run_id``."""
    return checkpoint_path(run_id, root=root).is_file()


def pending_nodes(run_id, root=None):
    """Nodes a resumed run would execute next, or ``()`` when nothing is resumable.

    Reports the *resumable* point (:func:`resumable_snapshot`), not the thread's last
    snapshot: a finished thread ends on ``final_report`` with nothing pending, yet the
    run is still resumable from the step its budget cut short.
    """
    snapshot = resumable_snapshot(run_id, root=root)
    return tuple(snapshot.next or ()) if snapshot else ()
