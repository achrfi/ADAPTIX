"""Exact-input decision cache and bounded retries, with a provider token ledger."""
import hashlib
import json
import os
import time
import litellm
from pydantic import ValidationError
from src.adaptix.agents.schema import PlannerDecision
from src.adaptix.workflow.budget import remaining_seconds, remaining_tokens, STORE_CACHE_BOUND


TIMEOUT_ERRORS = ('Timeout', 'ReadTimeout', 'ConnectTimeout')
# A local provider call needs roughly a minute; do not start one that cannot finish.
MIN_PROVIDER_SECONDS = 75
# Fallback per-call provider window when the run does not configure one.
DEFAULT_PROVIDER_SECONDS = 180.0
# Measured output throughput for one full-size planning decision on the local provider.
PLANNING_OUTPUT_RATE = 4.8
# A call that timed out or was cut off at the output limit proves the response envelope
# did not fit the window. Repeating an identical call would time out again, so the next
# attempt must ask for strictly less output.
MIN_RETRY_OUTPUT = 160
# Fallback shrink for callers that supply no tighter envelope of their own.
ENVELOPE_SHRINK = 0.5
# The smallest decision the strict native JSON schema has ever needed. A retry
# with less room than this is misclassifying exhaustion as an output constraint;
# refusing it prevents a doomed truncated call and preserves budget.
MIN_VIABLE_OUTPUT = 500


def context_limited(state, attempt_prompt_cost):
    """True when this prompt cannot fit any honest decision in the model context."""
    try:
        measure = int(state.get('model_context_tokens', 4096)) - int(attempt_prompt_cost)
    except (TypeError, ValueError):
        return False
    return measure < MIN_VIABLE_OUTPUT


def configured_timeout(state):
    """Per-call provider window from run state, environment, or the run's own budget.

    One call may never claim more than half of the run's wall-clock budget: the planner
    still needs room for the evidence it already gathered to be reported.
    """
    raw = state.get('llm_timeout_seconds')
    if raw in (None, ''):
        raw = os.getenv('ADAPTIX_LLM_TIMEOUT') or None
    try:
        configured = float(raw) if raw is not None else DEFAULT_PROVIDER_SECONDS
    except (TypeError, ValueError):
        configured = DEFAULT_PROVIDER_SECONDS
    if configured <= 0:
        configured = DEFAULT_PROVIDER_SECONDS
    budget = float(state.get('time_budget_seconds') or 0)
    return max(1.0, min(configured, budget / 2)) if budget > 0 else configured


def measured_output_rate(metrics):
    """Output tokens per second observed for this provider in this run, if known."""
    try:
        rate = float(metrics.get('output_tokens_per_second') or 0)
    except (TypeError, ValueError):
        return None
    return rate if rate > 0 else None


def configured_output_rate(state, metrics):
    """Output tokens per second to plan against.

    The rate a run observes on its own calls is never assumed to exceed the measured
    rate for a full-size planning decision: a short first decision decodes faster than
    the longer ones that follow, so trusting it would pick an envelope that cannot
    finish. A slower provider still tightens further, which is the useful direction.
    """
    configured = state.get('llm_output_tokens_per_second')
    if configured in (None, ''):
        configured = os.getenv('ADAPTIX_OUTPUT_TOKENS_PER_SECOND') or PLANNING_OUTPUT_RATE
    try:
        configured = float(configured)
    except (TypeError, ValueError):
        configured = PLANNING_OUTPUT_RATE
    if configured <= 0:
        configured = PLANNING_OUTPUT_RATE
    observed = measured_output_rate(metrics)
    return min(observed, configured) if observed else configured


def is_timeout_error(name):
    """True for any provider timeout spelling, including the builtin ``TimeoutError``."""
    text = str(name or '').lower()
    return text in {alias.lower() for alias in TIMEOUT_ERRORS} or 'timeout' in text


VALIDATION_HINTS = {
    'less_than_equal': 'value exceeds the allowed maximum; priority scores must be within 0.0 to 1.0',
    'greater_than_equal': 'value is below the allowed minimum',
    'greater_than': 'value must be greater than the minimum',
    'less_than': 'value must be less than the maximum',
    'int_parsing': 'expected an integer',
    'int_type': 'expected an integer',
    'float_parsing': 'expected a number',
    'float_type': 'expected a number',
    'string_type': 'expected a string',
    'string_too_short': 'text must not be empty',
    'string_too_long': 'text exceeds the allowed length',
    'too_long': 'too many items',
    'list_type': 'expected an array',
    'dict_type': 'expected an object',
    'bool_type': 'expected a boolean',
    'missing': 'required field is missing',
    'extra_forbidden': 'unknown field is not allowed',
    'literal_error': 'value is not one of the allowed choices',
    'json_invalid': 'response was not valid JSON',
}


def validation_fields(exc, limit=6):
    """Bounded, JSON-safe description of a schema failure for repair feedback."""
    return [{'field': '.'.join(str(part) for part in item['loc']), 'type': item['type']}
            for item in exc.errors(include_input=False, include_url=False)[:limit]]


def validation_repair(fields, total=None):
    """Explain a schema failure without turning it into a security conclusion.

    The model sees the offending fields plus a plain-language meaning. Validation
    types such as ``less_than_equal`` are not JSON Schema keywords, so naming them
    alone invites the model to repeat the same out-of-range value or to stop.
    """
    explained = '; '.join(f"{row['field']}: {VALIDATION_HINTS.get(row['type'], row['type'])}" for row in fields)
    more = f' (+{total - len(fields)} more errors)' if total and total > len(fields) else ''
    return (
        'Schema repair only: the assessment objective and observed evidence in the original request are unchanged. '
        'The previous response failed Pydantic validation, not authorization: ' + explained + more + '. '
        'These are validation error types, not JSON Schema keywords; for example less_than_equal means a numeric '
        'value exceeded its allowed maximum. Return one complete JSON object with the required types and ranges, and '
        'priority scores must be within 0.0 to 1.0. Do not fabricate security observations and do not treat this '
        'formatting error as a reason to stop the assessment: re-propose the action you intended with corrected '
        'values. reflection and review.decision_change must contain nonempty text: decision_change states what to do '
        'next, including stopping after sufficient evidence or reporting a limitation. Empty strings are allowed only '
        'for absent failure/uncertainty. Use evidence_refs=[] before observations.'
    )


def request_decision(state, kwargs, metrics, prompt_cost, tighten=None):
    def cache_key(parameters):
        return hashlib.sha256(json.dumps({k: v for k, v in parameters.items() if k not in ('timeout', 'num_retries')},
                                         sort_keys=True, default=str).encode()).hexdigest()
    key = cache_key(kwargs)
    cache = dict(state.get('planner_cache', {}))
    ledger = list(state.get('token_ledger', []))
    if key in cache:
        try:
            decision = PlannerDecision.model_validate(cache[key])
            metrics['cache_hits'] = metrics.get('cache_hits', 0) + 1
            ledger.append({'cache_key': key, 'source': 'cache', 'tokens_charged': 0,
                           'provider_call': False, 'result': 'valid_decision'})
            return decision, metrics, cache, ledger, None
        except ValueError:
            cache.pop(key, None)
    metrics['cache_misses'] = metrics.get('cache_misses', 0) + 1
    retries = max(0, min(int(state.get('planner_retry_limit', 0)), 3))
    tokens = int(metrics.get('tokens_used', 0))
    calls = int(metrics.get('llm_calls', 0))
    last_error = None
    decision = None
    repair = None
    envelope_too_large = False
    compat_stripped = False
    reported_prompt_tokens = 0
    for attempt in range(retries + 1):
        remaining = remaining_tokens(state, tokens)
        parameters = dict(kwargs)
        attempt_prompt_cost = prompt_cost
        attempt_state = {**state, 'token_ledger': ledger, 'planner_cache': cache}
        if repair:
            parameters['messages'] = [*kwargs['messages'], {'role': 'user', 'content': repair}]
            try:
                attempt_prompt_cost = litellm.token_counter(model=kwargs['model'], messages=parameters['messages'])
            except Exception:
                attempt_prompt_cost = prompt_cost + len(repair.encode('utf-8')) // 3 + 32
        if attempt and reported_prompt_tokens:
            # The provider is the ground truth on prompt size: its own count of
            # the previous request dominates any local tokenizer estimate, so a
            # retry can never underreserve and truncate by surprise.
            attempt_prompt_cost = max(attempt_prompt_cost, reported_prompt_tokens
                                      + (len(repair.encode('utf-8')) // 3 + 32 if repair else 0))
        if attempt and envelope_too_large:
            # Snapshot the cap first: tighten() may edit the mapping it is given, and
            # comparing a value against itself would look like "unchanged".
            previous_cap = int(parameters.get('max_tokens', kwargs['max_tokens']))
            tightened = dict(tighten(dict(parameters), attempt) if tighten else parameters)
            # The cap must match the tightened envelope: a cap below what the smaller
            # envelope needs truncates a decision that would now have fitted. A
            # schema-constrained decision can never validate under the schema's own
            # minimum, so shrinking further than that is misclassifying completion
            # as an output constraint and asks a doomed identical question.
            if tightened.get('max_tokens') in (None, previous_cap):
                schema_floor = (MIN_VIABLE_OUTPUT if parameters.get('response_format')
                                and isinstance(parameters.get('response_format'), dict)
                                else MIN_RETRY_OUTPUT)
                tightened['max_tokens'] = max(schema_floor, int(previous_cap * ENVELOPE_SHRINK))
            parameters = tightened
            attempt_prompt_cost = prompt_cost
        output_limit = min(max(0, int(parameters.get('max_tokens', kwargs['max_tokens']))),
                           max(0, int(state.get('model_context_tokens', 4096)) - attempt_prompt_cost))
        remaining_run = remaining_seconds(state)
        token_room_short = remaining is not None and remaining < attempt_prompt_cost + min(128, output_limit)
        if (context_limited(state, attempt_prompt_cost) or output_limit < 32
                or token_room_short
                or remaining_run <= 0 or (attempt > 0 and remaining_run < MIN_PROVIDER_SECONDS)):
            # A truncated retry that cannot carry MIN_VIABLE_OUTPUT is context
            # exhaustion, not a schema or output problem: refuse it and report
            # the class honestly instead of burning tokens on an identical doomed ask.
            if context_limited(state, attempt_prompt_cost):
                last_error = 'ContextHeadroomInsufficient'
            break
        actual_kwargs = {**parameters, 'max_tokens': min(output_limit, remaining - attempt_prompt_cost
                                                           if remaining is not None else output_limit),
                         'timeout': min(kwargs['timeout'], remaining_run), 'num_retries': 0}
        reserved = attempt_prompt_cost + actual_kwargs['max_tokens']
        actual_key = cache_key(actual_kwargs)
        calls += 1
        if attempt:
            metrics['retries_used'] = metrics.get('retries_used', 0) + 1
        tokens += reserved
        started = time.monotonic()
        entry = {'provider_call': True, 'attempt': attempt + 1, 'cache_key': actual_key,
                 'model': kwargs['model'], 'source': 'reservation', 'tokens_charged': reserved,
                 'timeout': actual_kwargs['timeout'], 'requested_timeout': kwargs['timeout'],
                 'deadline_clamped': actual_kwargs['timeout'] < kwargs['timeout'],
                 'run_seconds_remaining': round(remaining_run, 2)}
        entry['generation_parameters'] = {k: actual_kwargs.get(k) for k in ('max_tokens', 'reasoning_effort', 'response_format', 'temperature', 'api_base')}
        finish_reason = ''
        try:
            response = litellm.completion(**actual_kwargs)
            elapsed = max(time.monotonic() - started, 1e-9)
            usage = getattr(response, 'usage', None)
            prompt_tokens = int(getattr(usage, 'prompt_tokens', 0) or 0)
            completion_tokens = int(getattr(usage, 'completion_tokens', 0) or 0)
            actual = int(getattr(usage, 'total_tokens', 0) or 0) or prompt_tokens + completion_tokens
            reported_prompt_tokens = max(reported_prompt_tokens, prompt_tokens)
            if actual:
                tokens += actual - reserved
                entry.update(source='provider', prompt_tokens=prompt_tokens,
                             completion_tokens=completion_tokens, tokens_charged=actual)
            metrics['last_prompt_tokens'] = prompt_tokens or prompt_cost
            metrics['last_completion_tokens'] = completion_tokens
            finish_reason = str(getattr(response.choices[0], 'finish_reason', '') or '')
            if completion_tokens:
                # Learn this provider's real throughput so later passes size their own
                # envelope from measurement instead of a hardcoded constant.
                metrics['output_tokens_per_second'] = round(completion_tokens / elapsed, 3)
            decision = PlannerDecision.model_validate_json(response.choices[0].message.content)
            entry['result'] = 'valid_decision'
            entry['finish_reason'] = finish_reason
            cache[actual_key] = decision.model_dump()
            # Bound the resident cache for memory safety even when no cumulative
            # budget exists: this is a storage bound, not an execution budget.
            cache_bound = (STORE_CACHE_BOUND if state.get('max_iterations') is None
                           else max(1, int(state.get('max_iterations'))))
            while len(cache) > cache_bound:
                cache.pop(next(iter(cache)))
            last_error = None
            envelope_too_large = False
        except Exception as exc:
            decision = None
            # Do not persist provider errors that may echo prompt credentials.
            last_error = type(exc).__name__
            entry.update(result='failed', error_type=last_error)
            if not compat_stripped and 'response_format' in str(exc).lower() and 'response_format' in parameters:
                # A provider that refuses the declared response_format is a
                # compatibility fact, not a failure of the decision; strip the
                # parameter once at the base kwargs (the per-attempt copy is
                # rebuilt from them) and let strict local schema validation
                # carry the contract. Recorded, never silent.
                compat_stripped = True
                parameters.pop('response_format', None)
                kwargs.pop('response_format', None)
                entry['result'] = 'compat_fallback'
                metrics['response_format_compat_fallback'] = metrics.get('response_format_compat_fallback', 0) + 1
            if is_timeout_error(last_error) or isinstance(exc, TimeoutError) or finish_reason == 'length':
                # Cut off at the output limit means the envelope, not the schema, was
                # too large for the window; the next attempt must be smaller.
                envelope_too_large = True
                entry['envelope'] = 'too_large'
            if isinstance(exc, ValidationError):
                errors = exc.errors(include_input=False, include_url=False)
                fields = validation_fields(exc, limit=len(errors))
                entry['validation_fields'] = fields
                entry['error_class'] = 'validation'
                if finish_reason:
                    entry['finish_reason'] = finish_reason
                repair = validation_repair(fields[:6], total=len(errors))
            else:
                entry['error_class'] = 'provider'
        entry['seconds'] = round(time.monotonic() - started, 6)
        ledger.append(entry)
        metrics['seconds'] = metrics.get('seconds', 0) + entry['seconds']
        if decision is not None:
            break
    metrics.update(llm_calls=calls, tokens_used=tokens)
    return decision, metrics, cache, ledger, last_error or ('BudgetUnavailable' if decision is None else None)
