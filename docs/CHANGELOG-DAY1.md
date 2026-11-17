# Day 1 — Integrity fixes

Two defects in the project's strongest layer, both closed and pinned by regression
tests. No evidence-layer architecture was changed; `verification.py` is untouched.

Baseline before: **761 passed**. After: **769 passed**, exit 0.

---

## Fix 1 — the suite only ran on the machine that wrote it

### What was wrong

Three independent hardcodes, all of which made `pytest` depend on the process cwd and
on the absolute path `/root/projects/adaptix`:

| Location | Defect |
|---|---|
| `tests/test_idor_severity.py:10` | `pathlib.Path('src/adaptix/agents/reflector.py')` — cwd-relative |
| 11 test modules | `sys.path.insert(0, '/root/projects/adaptix')` — absolute |
| 6 references in 4 modules | `pathlib.Path('/root/projects/adaptix/src/...').read_text()` — absolute |

Plus one structural gap: `tests/` had no `__init__.py`, so `from tests.test_adaptix_
planning_recovery import ...` could not resolve outside the project root.

Measured symptom: `pytest tests/` from `/tmp` produced **3 collection errors**; a fresh
checkout on any other host or path could not run at all.

### What changed

- `tests/test_idor_severity.py` — resolves from `Path(__file__).resolve().parents[1]`.
- `tests/__init__.py` — new. Registers both the repo root and `tests/` on `sys.path`,
  because the suite mixes `from tests.x import` and `from test_x import` styles.
- 11 modules — the literal path insert removed; the root comes from `pyproject.toml`.
- 4 modules — absolute reads replaced with `ROOT / 'src/...'`.
- `pyproject.toml` — `pythonpath = ["."]` under `[tool.pytest.ini_options]`.
- `conftest.py` — new, root-level.

### Proof

```
cwd=/tmp      -> 769 tests collected
cwd=/          -> 769 tests collected
cwd=/usr/lib   -> 769 tests collected
cwd=/mnt/c     -> 769 tests collected
```

The three modules that originally failed now pass from a foreign cwd: **37 passed**.

### Pinned by

`tests/test_suite_portability.py` — fails if any test file reintroduces an absolute
path or a cwd-relative read, and proves collection succeeds from a `tmp_path` with
more than 500 tests collected (so a fix that silently collects nothing cannot pass).

Note on one transient: a single collection error appeared once under `/usr/lib` and
did not reproduce in 9 subsequent runs (3 sequential, 3 concurrent, 3 in the exact
original loop). Cause was confirmed as stale `__pycache__` — two generations of `.pyc`
for the same module with timestamps 26 minutes apart, one written while another pytest
process was importing it. Purging bytecode removed it. Not a design defect.

---

## Fix 2 — a class reported as `tested` that no check had exercised

### What was wrong

`TOOL_CLASSES['injection_probe']` mapped to **both** `sql_injection` and
`nosql_injection`:

```python
'injection_probe': ('sql_injection', 'nosql_injection'),
```

But `injection_probe` sends only boolean SQL predicates (`OR 1=1` / `AND 1=2`). There
is **no** NoSQL operator payload anywhere in `src/adaptix/tools/` — no `$ne`, `$gt`,
`$regex`, or `$where`. A run that executed one SQLi probe therefore reported:

```
nosql_injection: tested
```

That is a false statement about a class nothing had exercised. A false `tested` is the
single failure mode `coverage.py` exists to prevent, and it was sitting in the file
that defines the honesty contract.

### What changed

`src/adaptix/reporting/coverage.py`

1. `'injection_probe': ('sql_injection',)` — NoSQL claim removed, with a comment
   stating why it is absent rather than merely dropping it.
2. New branch, evaluated before the generic "nothing ran" case:

```python
elif not class_tools:
    status = NOT_TESTED
    reason = ('no probe reports this class: the tool can record the signal and '
              'escalate it, but it holds no deterministic check for it, so this '
              'run makes no statement about whether the class is present')
```

The branch order matters. Previously a run that executed *other* actions answered
`nosql_injection` with *"no action was planned and executed in this run"* — which
implies the class was skipped by circumstance rather than by the tool having no probe
for it. Verified as a real failure during implementation: the first version of the
regression test caught exactly that.

### Result

```
sql_injection      status=tested       reason=1 action(s) for this class executed this run
nosql_injection    status=not_tested   reason=no probe reports this class: the tool can
                                             record the signal and escalate it, but it
                                             holds no deterministic check for it, ...
```

`nosql_injection` can still be *recorded* when a candidate or signature suggests it —
it is simply no longer claimed as tested.

### Pinned by

`tests/test_coverage_no_overclaim.py` — five tests:

1. `injection_probe` claims SQL and not NoSQL.
2. Guard rail: no tool may claim `nosql_injection` while no operator payload exists in
   `tools/`. If a real probe is added later, the assertion in (1) must be revisited
   deliberately rather than silently satisfied.
3. A SQL-only run reports SQL as `tested` and NoSQL as `not_tested`.
4. The `not_tested` reason must not say "executed no action".
5. The fix must not over-correct into under-reporting SQL.

---

## Final state

```
769 passed in 606.30s (0:06:06)   EXIT=0
```

Files changed: 16 modified, 4 added (`conftest.py`, `tests/__init__.py`,
`tests/test_coverage_no_overclaim.py`, `tests/test_suite_portability.py`).

Not touched: `evidence/verification.py`, `workflow/budget.py`, `static_discovery.py`.
