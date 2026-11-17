# Day 2 — Durable runs (checkpointer + resume)

A run that stops on a budget no longer throws its work away. It writes a checkpoint as it
goes, and `--resume` continues it in a new process instead of starting over.

## What was added

- `src/adaptix/evidence/checkpoint.py` — `open_checkpoint()`, `thread_id_for()`,
  `resumable_snapshot()`, `restore_runtime_secrets()`, and a `SanitizedSaver` that routes
  every write through `evidence/sanitize.py`.
- `--resume RUN_ID` on the CLI. A resume with no checkpoint is refused; a resume of a
  finished run is refused with "already finished; nothing to resume".
- `src/adaptix/workflow/graph.py` — `resumable_graph(checkpointer)`, which compiles a bound
  engine for a run. `graph` itself stays the plain, unbound object.
- `tests/test_resume_checkpoint.py` — 6 tests that lock the behaviour below.

## Defects found and fixed while building it

1. **A checkpoint marker was accepted as a credential.** The saver stores `KEY_MARKER`
   where the API key was, so nothing secret reaches disk. On resume the state was loaded
   as-is and the marker was truthy, so `api_key = state_key or env_key` sent the marker to
   the provider — every resumed run failed with `AuthenticationError`. Fixed: the marker is
   never a credential; the environment is the only source of a key.
2. **A pinned `checkpoint_id` made every read return the pre-write snapshot.** `update_state`
   wrote the new budget, but `get_state(fork)` re-read the pinned checkpoint and reported
   the old value, so a resume silently replayed the stopped run. Fixed: write with the
   pinned id, then read and stream from the newest snapshot.
3. **`sanitize()` redacted LangGraph's own bookkeeping.** Scrubbing `channel_version`
   counters left the saver unable to compute a next version. Fixed: control data is not
   secret-bearing and is never scrubbed.
4. **The report writer was handed the token ledger as model input.** The ledger's request
   block holds the real key, so the prompt path could leak it. Fixed: the prompt path
   excludes secret-bearing keys by name.
5. **A bound engine and the module `graph` had diverged.** A run streamed a look-alike
   object while callers instrumented `graph`; the two quietly stopped being the same graph,
   and a checkpoint was written with no resumable thread (20,480 bytes, empty). Fixed: every
   run streams the engine bound to its own checkpoint, and the CLI tests capture at the
   `run_stream` boundary rather than by patching `graph.stream`.

## Proof

- `--resume` with no checkpoint        -> refused
- fresh run `d2real1`                  -> `checkpoint.sqlite` written
- resume of a finished run             -> "already finished; nothing to resume"
- API key verbatim on disk             -> False (sanitized)
- halted run `acc1`, resumed           -> banner "continuing at execute_action",
                                          **0** auth errors, budget 40 with **13** tool
                                          calls used, 74 routes discovered
- full suite                           -> **775 passed, 0 failed** (12:58)

## End-to-end against OWASP Juice Shop

Both target classes were found and independently verified:

| class | category | severity | verification | impact |
|---|---|---|---|---|
| SQLi (UNION) | `sql_injection` | critical | `deterministic_replay` / `differential_injection` | `impact_proven=true`, 10 rows extracted, real password hash `fe01ce2a7fbac8fafaed7c982a04e229` |
| XSS | `cross_site_scripting` | medium | `deterministic_replay` / `browser_execution` | JS dialog round trip reproduced |

## Known limits

- A resume continues from the last **progress** point. A run stopped by
  `planning_stagnation` resumes into the same planner state and will not become smarter;
  the checkpoint preserves work, it does not change the policy.
- `pending_nodes()` is empty for a thread whose stop condition sits in its own state; the
  resumable point is therefore chosen from the snapshot graph, not from `next`.
