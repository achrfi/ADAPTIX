# Audit: why runs reported no vulnerabilities, and what was fixed

Scope: source-level audit of the adaptive pentest pipeline plus one bounded
reproduction per defect. Baseline suite before changes: **517 passed**. After:
**532 passed** (15 new tests for the discovery adapter).

Target used for reproduction: the local lab on `127.0.0.1:3000` (OWASP Juice
Shop), authorized for this workstation.

---

## Defect 1 - provider configuration was silently dropped by the state schema

`workflow/graph.py` declares the graph state as a `TypedDict`. LangGraph only
carries keys that the schema declares. `llm_api_base`, `llm_api_key` and
`llm_native_json` were passed into `graph.invoke()` by `main.py` but were **not
declared**, so every node received a state without them - from the very first
node onward.

Verified with a minimal LangGraph reproduction:

```
node saw keys: ['a']
invoke out:    {'a': 1}
DROPPED?       True
```

Consequence: any run against a hosted provider or a non-default `--api-base`
lost its base URL / key / structured-output mode at the graph boundary. The
planner would fall back to provider defaults and either fail or emit prose the
parser then discarded - one route to "0 findings".

Fix: the three keys are declared in `AgentState`.

## Defect 2 - the scope grant expired in the middle of a run

`authorize_cli_targets()` issued every grant with a hard-coded **1 hour** life,
while `--time-budget` defaults to **1800s** and is commonly raised to several
hours. A run longer than the grant died with `authorization_invalid` while
evidence was still being collected: every later action was refused, and the
report showed no findings.

Fix: `authorize_cli_targets(..., hours=None)` now accepts an explicit lifespan,
and `main.py` derives it from the time budget
(`ceil(budget / 3600) + 1`, capped at 168h) so the grant outlives the run.

Verified: budget 1800s -> 2h grant; 7200s -> 3h; 14400s -> 5h.

## Defect 3 - the wordlist profile was ignored

The adapter accepted a `profile` and advertised five of them, but the resolver
ignored the argument and always loaded `common.txt`. Every sweep therefore ran
the same generic list, and the API / backup profiles the planner could request
did nothing.

Fix: the resolver takes the profile, and each profile maps to its own file.

```
profile api             -> api-endpoints.txt
profile backup          -> backup-files.txt
profile common          -> common.txt
profile quick           -> quick.txt
profile raft-small-dirs -> raft-small-directories.txt
```

## Defect 4 (root cause) - no content discovery, and discovery output was fake

Two separate problems combined into the observed "no vulnerabilities":

**(a) There was no way to find unlinked paths.** `web_discover` reads links a
served document already references; `api_discover` reads a document the
application already advertises. Nothing could answer "which paths exist that
this application never links to?" - the directory layer where admin panels,
backups, API prefixes and `.git` live. Every run was confined to routes the
crawl already reached.

**(b) A naive sweep made it worse, not better.** ffuf's built-in `-ac` only
learns from the wordlist it is given. This lab answers unknown API paths with
**500 + "Error: Unexpected path: ..."** and unknown pages with the **200 SPA
shell**. Run uncalibrated, a 269-word API list produced **192 "live routes"**,
of which roughly **189 did not exist**. The planner then spent its whole budget
probing them and the run reported nothing.

Fix, in three parts:

1. **Per-prefix calibration.** Before sweeping, the adapter fetches one
   guaranteed-nonexistent path per parent prefix. Error templates here are a
   fixed skeleton wrapped around the requested path, so body length is exactly
   `base + echoes * len(path)`; the adapter records `base` and `echoes` and
   rejects any later row that satisfies the same arithmetic. Constant-length
   soft-404s are rejected by equal length.
2. **Post-filtering, not just ffuf filters.** Filtering happens in Python after
   the sweep, so it applies to every row regardless of how ffuf was invoked.
3. **A real pipeline stage.** The sweep runs inside the deterministic baseline
   for every authorized origin, and is also available to the planner as a
   first-class capability with its own prerequisites, contract and
   once-per-profile guard.

Measured on the lab:

| profile | tested | real matches | soft-404 filtered | wall clock |
|---------|--------|--------------|-------------------|-----------|
| api     | 269    | **3**        | **189**           | 135s      |
| quick   | 585    | **11**       | **196**           | 293s      |
| common  | 4750   | 1            | 0                 | (slow)    |

The three real API routes found (`/api-docs`, `/api/users/current`,
`/api/users/login`) are exactly the endpoints the crawl never linked to, and the
ones worth testing.

---

## Supporting changes

- **Wordlists** live in `work/wordlists/discovery/` with a `manifest.json`
  recording upstream path, SHA-256 and entry count for each file (SecLists,
  preinstalled package, copied verbatim - no network fetch).
- **Rate honesty.** A sweep can only test what the configured rate permits
  inside the time cap. Sending 4,750 words at 2 req/s into 180s returns the
  first ~360 and looks like full coverage. The adapter trims to what is
  affordable and records `trimmed_by_rate_cap`.
- **Reachability preflight.** An unreachable origin is recorded as a
  limitation, not an error, and never burns the wall-clock budget in connection
  timeouts.
- **Test hermeticity.** The sweep is a real subprocess against a live origin.
  `tests/conftest.py` now disables it suite-wide, with
  `tests/test_adaptix_static_discovery.py` opting back in. Before this, an
  unrelated baseline test took 187s and made ~5,000 real HTTP requests.
- **Scope.** Every sweep re-checks the origin through the same `permitted()`
  predicate as every other adapter, runs with `shell=False`, drops
  credential-shaped environment variables, and refuses a wordlist outside the
  project tree.

## Defect 5 - the sweep was scheduled after the phase exhausted its budget

Adding the sweep was not enough: it ran *last* in `_discover_origin`, after the
crawl and the document probes. The baseline's phase cap is 8 tool calls, and
observation processing is one of them, so on a real target the sweep never
executed at all. Verified in run `audit-e2e-193419`:

```
steps: [('web_discover', None), ('api_discover', None)]
static_swept: []          <- never ran
```

Fix: the sweep runs **first** on the origin, and the crawl then operates over
the union of what it finds and what the sweep discovered.

Verified in run `audit-e2e2-202923`:

```
steps: [('static_discovery', 'quick', 11, None), ('web_discover', None, 74, None)]
```

## Defect 6 - a provider timeout was misclassified as an over-large envelope

`request_decision` collapsed two unrelated failures into one branch:

```python
if is_timeout_error(...) or finish_reason == 'length':
    envelope_too_large = True     # and retry with a smaller cap
```

A `finish_reason == 'length'` response really does mean the output envelope was
too big. A **timeout** does not: it means the provider did not finish in the
window. Retrying 520 output tokens at 500 changes nothing about that, and it
burns the run's clock. In run `audit-e2e-193419` the ledger shows exactly this:

| attempt | max_tokens | seconds | result |
|---------|-----------|---------|--------|
| 1 | 520 | 180.1 | failed, `envelope: too_large` |
| 2 | 500 | 180.1 | failed, `envelope: too_large` |
| 1 (next pass) | 520 | 87.1 (clamped) | failed |

Three timeouts, 447s of a 1200s budget, and every one recorded as an output
problem. The planner then reported `llm_error` on every pass, produced 0 actions,
and the run ended with **zero findings** - which is the symptom the audit set out
to explain.

Fix: a timeout is classified `provider_timeout`, the retry keeps the same
envelope, and the planner's recompaction path resizes the *prompt* instead of the
output cap. Verified in run `audit-e2e2-202923`: `provider_timeout: 2`, and
planning still returned `mode: llm` with executed actions.

## Defect 7 - the planner sized output from a window already consumed by the prompt

With `--model-context-tokens 8192`, a 7857-token prompt left 335 tokens of
headroom for a decision that needs ~520. The planner dutifully sized to the
headroom, so every call was structurally doomed: the model could not finish, and
the timeout hid the cause.

This is an operator configuration trap, not a code bug, so the fix is a guard
rather than a rewrite: the timeout path now recompacts the prompt to half the
window, which both halves the prefill and gives the decision real room.

---

## End-to-end state after the fixes

| | before | after |
|---|---|---|
| content discovery | never ran | 11 real paths per origin, first in the phase |
| fake routes from a sweep | 192 of 269 (73%) | 189 filtered, 3 kept |
| planner mode | `llm_error` on every pass | `llm`, actions executed |
| timeouts | recorded as `envelope: too_large` | `provider_timeout`, prompt resized |
| tests | 517 passed | **532 passed** |

**Remaining limitation, stated plainly: the local model is the bottleneck.** At
`adaptix-qwen35-8k` with ~2-5 output tok/s on this hardware, a 1500s budget is
consumed by two 420s provider calls before any vulnerability class is exercised.
Run `audit-e2e2-202923` executed 2 `http_request` actions and stopped at
`time_budget_exhausted`, correctly reporting `not_tested` for every vuln class
rather than claiming safety. That is honest behaviour; it is not a code defect.
To get findings out of this lab, raise `--time-budget` (3600s+), lower
`--model-context-tokens` to 8192 with a smaller prompt, or point `--model` at a
faster provider - the pipeline no longer has to be fixed for that to matter.

### Third run: the pipeline is healthy, the model is the limit

`audit-final-211347` used `--llm-timeout 600 --model-context-tokens 12288
--time-budget 3000 --planner-retries 0`:

| signal | result |
|--------|--------|
| provider timeouts | **0** across all 5 planning passes |
| planner mode | `llm` on every pass (one `policy_recovery`, recovered) |
| executed actions | `api_discover x1, http_request x4` |
| repeated-action guard | fired correctly (`already_completed`, `kind: repeat`) |
| stop reason | `time_budget_exhausted` |
| findings | 0, reported as `not_tested` per class |

Every defect from this audit is now absent: the sweep runs first and returns 11
real paths, the planner never degrades to `llm_error`, duplicate actions are
rejected with a concrete alternative, and the report states what was *not* tested
instead of implying the target is clean.

The residual zero is a model-quality limit: all four `http_request` actions were
unauthenticated GETs answered with **401**, so no object-level check was ever
reached. The planner knew it needed a session (it proposed
`/api/users/login` for that reason) but the 8k-context local model could not
construct a valid login body+token flow within the remaining budget. That needs a
stronger model or operator-supplied session credentials (`--identity-context`),
not another code change.

The distinction that matters: before this audit the pipeline could not have
produced a finding even with a perfect model, because the sweep never ran, the
planner was in `llm_error`, and fake routes consumed the budget. Now it can - the
probes reach real endpoints and the guards behave. Attribution for the next zero
should start at model capability, not at the code.

---

## Deliberate non-goals

No recursive brute force by default, no credential attack, no
parameter/value fuzzing in this adapter. Parameter and value fuzzing belongs in
`http_request`, where each probe produces a comparable, signed trace. A
discovered route is evidence that a path answered - never a finding.

---

# Round 2 — end-to-end run against a hosted gateway (base URL + API key)

The first round fixed the pipeline so a plan could be produced at all. This round
ran the product end to end against a real OpenAI-compatible gateway to answer one
question: does an operator who fills in `.env` get a working assessment?

## Defects found and fixed

### Defect 6 — `.env` was never loaded
The project shipped `.env.example` and accepted `.env`, but no code read it. A key
placed there was ignored silently and had to be exported by hand per shell.
Fixed in `config.load_dotenv()`, called before the argument parser is built. Real
environment variables still win, so per-command overrides remain safe.

### Defect 7 — planner knobs were dropped by the graph state schema
LangGraph validates the run state against `AgentState` (a `TypedDict`) and silently
drops keys it does not declare. `llm_api_base`, `llm_api_key` and later
`llm_reasoning_effort` were all written into the state and never reached the
planner. The symptom was a hosted provider running with no base URL, then a
reasoning model that ignored the reasoning setting — both while the same checkpoint
replayed outside the graph succeeded.

`tests/test_planner_knobs_reach_the_graph.py` now asserts every knob `main.py`
writes is declared. This class of bug had already cost two debugging rounds.

### Defect 8 — a gateway that accepts `json_schema` then ignores it
`openai/` was listed as natively schema-capable, so every OpenAI-compatible gateway
was probed with strict `json_schema`. The gateway accepted it and enforced nothing,
leaving the model free to write decisions that violated the schema. Because the
request succeeded, no fallback ever armed.

Gateways are now detected separately from the vendor API, and the transport is
`json_object` whenever a custom `api_base` is in use. An operator override
(`--native-json on|off`) still exists for a gateway that does enforce it.

### Defect 9 — the prompt taught the model the wrong types
The skeleton embedded in the system prompt is the model's idea of "reply with
exactly this shape". It shipped `"headers":"<headers>"` and
`"evidence_refs":"<evidence_refs>"` — placeholder strings where the schema requires
an object and an array. The model wrote strings; validation rejected the pass.

Sample values now carry the right JSON type, and a test asserts the prompt's own
example validates against the schema.

### Defect 10 — reasoning models starve the output budget
Measured on `glm-5.3`: 4284 characters of `reasoning_content` and **zero**
`content`, `finish_reason=length`, at every `max_tokens`. The gateway also ignored
`max_tokens` entirely (asked 16-4096, always returned ~2048). Neither is a wrong
decision, so neither should lose a planning pass.

Two fixes: `--reasoning-effort` / `ADAPTIX_REASONING_EFFORT=none` suppresses hidden
reasoning, and an empty-content-with-reasoning response is classified as
`ProviderStarvation` and retried from a small fixed allowance that does not consume
the operator's retry budget or shrink the envelope.

Starvation is intermittent at the gateway (measured: empty, empty, valid, valid on
an identical request), so retrying is correct. It is not free — each attempt is
metered at the full reservation.

### Defect 11 — truncation discarded work that had already survived
A hard-capped gateway cuts the JSON off mid-string. Both planning passes were lost
and the run ended with zero actions, even though every action the model had finished
writing was valid and pointed at real routes.

`salvage_truncated_json()` keeps the completed `actions` entries and closes the
document. It only fires for *truncated* JSON: a complete document that fails
validation takes the normal reject/retry path, so safety rules (a nonempty
reflection, for example) cannot be bypassed by recovery.

### Defect 12 — shape drift in descriptive fields cost whole passes
On a transport that cannot enforce the schema, the model wrote `review.uncertainty`
as a list on one pass and a string on the next, `headers` as `""` instead of `{}`,
and `marker` as `""` where a 6-character minimum applies. Each rejected the entire
decision.

Descriptive fields are now normalised at the validation boundary. Fields that carry
meaning — tool eligibility handled by the registry, priority bounds, `goal_status`
literal, `extra=forbid` — still reject.

### Defect 13 — an unsupported optional parameter failed the request
`reasoning_effort` sent to a model that does not accept it raises
`UnsupportedParamsError` and loses the whole call (`openai/gpt-4.1-mini`). The
parameter is an optimisation, never a requirement: it is now dropped once and
retried, and the fallback is recorded in metrics.

## Model selection at the gateway

The gateway exposes 175 model ids and `autoapp/*` routes through an aggregator that
picks a backend per request, so behaviour varies between calls. Measured over 8
identical planner calls with the real 36 KB prompt:

| model | valid | empty (starvation) | invalid | avg latency |
|---|---|---|---|---|
| `autoapp/minimax-m3` | 5/8 | 2 | 1 | 16.5 s |
| `autoapp/glm-5.2` | 1/8 | 7 | 0 | 12.5 s |
| `autoapp/glm-5.3` | 1/4 | 3 | 0 | 11.6 s |
| `autoapp/kimi-k2.6` | 1/4 | 3 | 0 | 10.5 s |
| `autoapp/deepseek-v4-pro` | 0/4 | 3 | 1 | 12.3 s |

Model ids also need LiteLLM's provider prefix: `autoapp/glm-5.3` is
`openai/autoapp/glm-5.3` when the base URL is a gateway. Without the prefix the id
cannot be resolved at all.

## Verified end-to-end

Run `e2e-final-025737`, `openai/autoapp/minimax-m3`, context 32768, 2100 s budget:

- `mode: llm` on every planning pass — no `llm_error` for the duration of the run
- 19 provider calls, 11 valid decisions, 6 starvation retries and 4 truncations all
  recovered; `errors: []`
- 9 actions executed (`http_request` 8, `httpx` 1), tool-call budget 18/50
- stop reason `budget_exhausted`, status `completed_partial` — a clean stop, not a
  crash
- findings 0, every class reported `not_tested` with the reason
  "this run executed no action for this class; absence of findings here is missing
  coverage, not an application-security result"

## What is still true (not a code defect)

1. **Token budget is the binding constraint, not time.** The run stopped with
   1317 s of 2100 s unused because 607 557 of 600 000 tokens were consumed. The
   planning prompt is 28 K tokens per call, and a starvation retry is metered at the
   full 30 K reservation. Raising `ADAPTIX_TOKEN_BUDGET` buys more passes; shrinking
   the observation payload buys them more cheaply.
2. **The lab target answers 401/500 without a session.** `--identity-context` is
   still required before access-control classes can be tested at all. Zero findings
   on an unauthenticated surface is `not_tested`, and the report says so.
3. **A gateway may not honour `max_tokens`.** Treat the output cap as a hint.
   `--check-model` warns when the measured completion exceeds the request, and the
   salvage path protects against the truncation that follows.

---

## Round 3 — object-level authorization (access-control class)

### Objective

Find a real access-control defect, not a simulated one: two valid identities, one
privately-owned object, and a documented detail endpoint. The operator supplied the
identities through `--identity-context`; the tool had to derive, fetch, and prove the
defect by itself.

### Result — verified finding, produced by the pipeline

```
run           : bola-final-091721
objective     : achieved
severity      : high
cwe           : CWE-639
owasp         : A01:2021 Broken Access Control
target        : http://127.0.0.1:18080/books/v1/adaptix-secret-01
owner         : adaptix_owner   GET -> 200
other         : adaptix_other   GET -> 200
owner_sha256  : 1e33399e4a450244627e0f394494abb9ec2a0243a72b29d90612a09a59b4c402
other_sha256  : 1e33399e4a450244627e0f394494abb9ec2a0243a72b29d90612a09a59b4c402
```

Identical response hashes for two different identities is the proof: `adaptix_other`
received the owner's private field content. The report carries it in
`verified_findings` and `independently_verified_findings`, and
`assessment_coverage.classes.broken_object_level_authorization.status` is `tested`
with `independently_verified_findings: 1` — not the `not_tested` placeholder that
earlier rounds produced.

### Five defects fixed to get there

1. **OpenAPI base URL resolution.** `servers: [{"url": ""}]` plus
   `urljoin('/openapi.json', '')` produced `/openapi.json/books/v1` for every
   operation, so no documented route was ever requestable. Resolution now falls back
   to the spec's own origin when the declared server URL is empty.
2. **`at_path()` iterated a string per character.** `identity_json_path` is a dotted
   string (`data.username`); iterating it walked `'d'`, `'a'`, `'t'` … which never
   matches a key, so **every** session failed validation with "Session identity not
   validated" and the run reported `scenario_candidates: 0`. Dotted strings are now
   split into segments; lists are still accepted.
3. **Candidate derivation depended on the planner's luck.** Deriving candidates
   requires a 200 observation of the collection, but nothing scheduled one — whole
   runs ended with `scenario_candidates: 0` while the collection was one in-scope,
   read-only GET away. `collection_index()` now selects those collections
   deterministically and the baseline fetches them.
4. **Baseline ordering starved the probes.** The static sweep (585 names at 2 req/s,
   ~293s) ran first against a 120s phase budget, so document probes never executed
   and `api_operations` stayed empty. Documents and collections now run first; the
   sweep runs last with a reserved slot.
5. **$RID carried `severity: unknown`.** `idor_findings` rows have no severity field,
   so a verified IDOR was untriageable. Verified object-level findings now report
   `high` (CWE-639 / A01:2021), or `medium` when no proof record was attached, and an
   explicit severity is never overwritten.

### Test coverage added

| File | Tests | Guards against |
|---|---|---|
| `test_openapi_base_resolution.py` | 5 | empty `servers[].url` breaking every route |
| `test_identity_json_path.py` | 7 | per-character path walking |
| `test_collection_index.py` | 8 | collections never requested |
| `test_idor_severity.py` | 5 | untriageable verified IDOR |

Suite: **611 passed, 0 failed** (was 586 before this round).

### Still open

- Coverage is one class deep: `cross_site_scripting`, `sql_injection` and the other
  classes remain `not_tested` on this run, honestly labelled as missing coverage.
- `autoapp/*` gateway routes remain load-balanced across backends; starvation is
  mitigated by retry, not eliminated.
- The gateway still ignores `max_tokens`; the planner envelope relies on salvage and
  retry rather than on a respected cap.


---

# Round 5 — Planner survival on a large prompt, and finding-driven escalation

Round 4 proved three vulnerabilities on a 74-route single-page target, but the planner
never participated: `planner mode: llm_error`, 2 passes, 0 actions. The findings came
from deterministic baseline probes, so "adaptive" was a claim without a demonstration.
This round makes the planner survive that prompt and act on what it finds. Every defect
below was measured against the real gateway before the code was changed.

## Defects found and fixed

### 1. The largest output envelope could not hold a real decision

`OUTPUT_ENVELOPES` topped out at 1216 tokens and `PLANNER_OUTPUT_TOKENS` was a literal
1216. Measured on the 74-route prompt: a complete decision used **1.8–2.4k** completion
tokens, so every pass ended `finish_reason=length` with the object cut mid-string. Zero
passes could validate. The top rung is now 3072 and the cap is derived from the tuple
(`PLANNER_OUTPUT_TOKENS = OUTPUT_ENVELOPES[0]['tokens']`), so the two cannot drift.

Rungs must also have distinct shapes. Two of them shared `(actions=1, hypotheses=1)`,
which made a schema-to-cost lookup ambiguous: a retry was capped at 640 while its paired
schema resolved to the 1024 rung. The smallest rung is now tied to `MIN_VIABLE_OUTPUT`
(500) rather than 520, so `500 / 4.8 = 104s` fits the 120s floor.

### 2. A valid decision was discarded for prose length

Every validation error in the first diagnosis was `string_too_long`. The decision was
complete and well shaped; a rationale had run past a presentation cap. The prompt also
demanded 130/90 characters while the validator enforced 400/240, so a model obeying
neither was refused for a limit it was never told. `prose_fit.fit_prose` now trims only
prose paths to the cap **read from the model metadata** — never a hardcoded copy — and
leaves every structured field byte-identical. `review` is declared `ReflectionReview |
None`, so the cap lookup unwraps the union and resolves item models (`Action.reason`)
as well as root fields.

### 3. Params wrapped in `args`, and a fenced JSON rejected

Measured across samples: without an explicit shape rule the model wrapped action
parameters in an `args` object (`extra_forbidden`); with the rule it produced 3/3 valid
decisions at the same cap. With `json_object` requested and "no prose" in the prompt, the
model also still wrapped decisions in ```` ```json ```` fences on some attempts — a
complete object discarded for presentation. `strip_code_fence` unwraps the body before
any parse attempt.

### 4. `reflection` rejected when returned as a list or object

`reflection` arrived as a list of sentences on one attempt, failing the `str` check
before the validator ran (`string_type`). Coercion is now `mode='before'`, the same
`_as_text` the nested review fields already use; an empty value is still refused.

### 5. Evaluation-only mode capped output at 512 tokens

After the objective was met, the review-only branch used a hardcoded 512-token ceiling.
Measured: that review writes **2.0–2.9k** tokens, so every attempt truncated and a run
that had *already achieved its objective* ended `completed_with_errors`. The ceiling is
now selected from the same measured envelopes as a decision, and the prompt states the
prose bound the branch was missing.

## The escalation path

Round 4's planner payload carried `idor_findings` only. A verified SQL injection or DOM
XSS **never entered the prompt**, so "SQL is indicated, try a higher-impact payload" was
structurally unreachable — the model could not see the SQL finding at all.

`finding_context.py` now adds a bounded, cited view of every verified finding plus
concrete escalation options per class, and `verified_findings` /
`finding_escalation_policy` are in `ESSENTIAL_FIELDS` so compaction can never strip the
trigger. Two further defects surfaced while proving it:

- SQLi and XSS rows reached the planner with an **empty `evidence_ref`** although the run
  held sealed records for them; the ref lives in the run-level `verification_evidence`
  keyed by URL. The model read the blank field as "no proof" and refused to escalate. The
  rows now join the sealed index by URL (exact, then path-only; a record for another
  endpoint is never borrowed).
- `grounded_review` then called those same sealed paths *"evidence not present"* — the
  run stopped on its own best proof. Sealed paths are now citable.

The policy was also too soft: it discouraged repetition but never required action, and
the model answered a verified finding with `actions=[]`. It now states that an
un-escalated verified class requires one more `http_request` on the same parameter, and
names the only conditions under which stopping is correct.

## Measured results

| Check | Before | After |
|---|---|---|
| Valid decisions at 74 routes | 0 | yes, at 26.5k prompt |
| Planner mode (`js-final-142639`) | `llm_error`, 0 actions | `llm`, decision valid without fitting |
| Objective status (`js-final-141...`) | `not_assessed` | `achieved` |
| Truncated review (evaluation-only) | every attempt | none |
| Suite | 618 passed | **655 passed, 0 failed** |

Escalation proof, against the real gateway with one verified SQL injection and an
objective asking for impact:

```
TOOL   : http_request
TARGET : /rest/products/search?q=' UNION SELECT id,email,password,1,1,1,1,1,1 FROM Users--
REASON : Escalate verified SQLi on q via UNION extraction: 9-column Products projection
```

Same parameter, higher-impact payload, chosen from the listed option. That is the
behaviour the request asked for, and it is now pinned by
`tests/test_escalation_trigger.py`.

A control run confirms the model is not merely compliant: with an objective demanding
three *distinct* classes, it returned `actions=[]` and `goal_status: blocked`, explaining
that further SQL injection could not satisfy the remaining two. Both behaviours are
correct for their objective.

## What remains

- `ProviderStarvation` still appears first on some passes (empty `content`, all output
  spent on reasoning). Retry recovers it; the gateway ignoring `reasoning_effort=none` is
  the cause and is not fixable from this side.
- The gateway still hard-caps ~2048 tokens and ignores `max_tokens`; decisions fit there
  now, but a longer review can still truncate.
- `objective_status` is still written only by the review path. It is correct here, but a
  run whose planner fails before review keeps `not_assessed` despite sealed evidence.
- `nosql_injection` is still reported `tested` although only SQL predicates are sent.

## One reporting path for every proven class (Round 6)

The report carried one finding out of five. `result['findings']` was assigned
`build_findings(state)`, and that function synthesizes only from `probe_traces`. Two
classes never write a probe trace: BOLA (`authorization_probe`) and browser XSS
(`script_probe` uses its own `httpx.Client`). UNION extractions were in the same
position. So the deliverable described one class while the run had proved four.

Measured on `js-tool-194124`: `verified_findings` = 5, `findings` = 1.

The fix merges three sources - `build_findings`, `verified_findings`,
`scanner_matched_findings` - through `_merge_report_findings`, keyed by
`_report_identity`. Identity is **(path, parameter, class)**. It is deliberately not the
payload: the same injection on the same parameter with three different payloads is one
vulnerability, and keying on payload produced three UNION rows for one hole. It is
also not `endpoint_key`, which carries the query string and therefore split by payload
as well.

Only proven statuses (`confirmed`, `verified`, `scanner_matched`) reach `findings`. An
`inconclusive` record stays in its own bucket. Without that gate a bare signature
(`/metrics` prometheus-metrics, inconclusive) appeared as a finding row.

Measured after the fix, same checkpoint: `findings` = 4 - SQLi (confirmed), BOLA
(verified, CWE-639), browser XSS (verified, browser_execution), scanner match.

Pinned by `tests/test_report_merge.py`, including a regression test that reads that
checkpoint and asserts all three classes are present.

## Status describes the assessment, not the gateway (Round 6)

`report.py` set `completed_with_errors` whenever `state['errors']` was non-empty, and
`planner.py:1588` writes every starved planning pass into that list. A run that had
already sealed five verified findings therefore reported an error because two later
passes returned empty provider content.

Two surfaces now: `errors` (outcome - security, policy, storage) and `transport_notes`
(provider faults). They are split by `_outcome_errors` / `_transport_notes`.

The status rule is deliberately asymmetric. `planner_unavailable` is fatal **unless**
the run still holds something it proved and the only fault on record is transport -
that is the case where the evidence predates the starvation and is intact. A run with
nothing proved stays `completed_with_errors`, because no assessment happened and
silence would hide a real failure. A policy rejection or a non-transport error stays
fatal regardless.

Measured: `js-tool-194124` moved from `completed_with_errors` to `completed_partial`
with `errors: []` and 4 transport notes preserved. `js-tool-183552` stayed
`completed_with_errors` - correctly, because it holds a real
`Tool failed: TypeError` on record from before the coercion fix.

Pinned by `tests/test_report_status.py`, which asserts both directions: excused when
evidence exists, fatal when it does not.
