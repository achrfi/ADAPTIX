"""Exact-input decision cache and bounded retries, with a provider token ledger."""
import hashlib
import json
import time
import litellm
from pydantic import ValidationError
from src.adaptix.agents.schema import PlannerDecision
from src.adaptix.workflow.budget import remaining_seconds


def request_decision(state, kwargs, metrics, prompt_cost):
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
    for attempt in range(retries + 1):
        remaining = int(state.get('token_budget', 50000)) - tokens
        parameters = dict(kwargs)
        attempt_prompt_cost = prompt_cost
        if repair:
            parameters['messages'] = [*kwargs['messages'], {'role': 'user', 'content': repair}]
            try:
                attempt_prompt_cost = litellm.token_counter(model=kwargs['model'], messages=parameters['messages'])
            except Exception:
                attempt_prompt_cost = prompt_cost + len(repair.encode()) + 32
        output_limit = min(kwargs['max_tokens'], max(0, int(state.get('model_context_tokens', 4096)) - attempt_prompt_cost))
        if output_limit < 32 or remaining < attempt_prompt_cost + min(128, output_limit) or remaining_seconds(state) <= 0:
            break
        actual_kwargs = {**parameters, 'max_tokens': min(output_limit, remaining - attempt_prompt_cost),
                         'timeout': min(kwargs['timeout'], remaining_seconds(state)), 'num_retries': 0}
        reserved = attempt_prompt_cost + actual_kwargs['max_tokens']
        actual_key = cache_key(actual_kwargs)
        calls += 1
        if attempt:
            metrics['retries_used'] = metrics.get('retries_used', 0) + 1
        tokens += reserved
        started = time.monotonic()
        entry = {'provider_call': True, 'attempt': attempt + 1, 'cache_key': actual_key,
                 'model': kwargs['model'], 'source': 'reservation', 'tokens_charged': reserved}
        entry['generation_parameters'] = {k: actual_kwargs.get(k) for k in ('max_tokens', 'reasoning_effort', 'response_format', 'temperature', 'api_base')}
        try:
            response = litellm.completion(**actual_kwargs)
            usage = getattr(response, 'usage', None)
            prompt_tokens = int(getattr(usage, 'prompt_tokens', 0) or 0)
            completion_tokens = int(getattr(usage, 'completion_tokens', 0) or 0)
            actual = int(getattr(usage, 'total_tokens', 0) or 0) or prompt_tokens + completion_tokens
            if actual:
                tokens += actual - reserved
                entry.update(source='provider', prompt_tokens=prompt_tokens,
                             completion_tokens=completion_tokens, tokens_charged=actual)
            metrics['last_prompt_tokens'] = prompt_tokens or prompt_cost
            metrics['last_completion_tokens'] = completion_tokens
            decision = PlannerDecision.model_validate_json(response.choices[0].message.content)
            entry['result'] = 'valid_decision'
            cache[actual_key] = decision.model_dump()
            # Bound resident cache by this run's planning budget, not a global store.
            while len(cache) > max(1, int(state.get('max_iterations', 20))):
                cache.pop(next(iter(cache)))
            last_error = None
        except Exception as exc:
            decision = None
            # Do not persist provider errors that may echo prompt credentials.
            last_error = type(exc).__name__
            entry.update(result='failed', error_type=last_error)
            if isinstance(exc, ValidationError):
                fields = [{'field': '.'.join(str(part) for part in item['loc']), 'type': item['type']}
                          for item in exc.errors(include_input=False, include_url=False)]
                entry['validation_fields'] = fields
                repair = 'Correct these JSON schema errors: ' + json.dumps(fields) + '. Return the required types and complete JSON only. reflection and review.decision_change must contain nonempty text: decision_change states what to do next, including stopping after sufficient evidence or reporting a limitation. Empty strings are allowed only for absent failure/uncertainty. Use evidence_refs=[] before observations.'
        entry['seconds'] = round(time.monotonic() - started, 6)
        ledger.append(entry)
        metrics['seconds'] = metrics.get('seconds', 0) + entry['seconds']
        if decision is not None:
            break
    metrics.update(llm_calls=calls, tokens_used=tokens)
    return decision, metrics, cache, ledger, last_error or ('BudgetUnavailable' if decision is None else None)
