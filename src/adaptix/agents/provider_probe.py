"""Provider preflight: prove a model + base URL + key actually plans, before a run.

The failure this prevents: an operator configures a hosted provider, starts a
2000-second assessment, and discovers at minute 40 that the key was wrong, the
base URL needed `/v1`, the model id did not exist, the model is a reasoning model
that returns empty content, or - the case this module was rebuilt for - the
gateway silently ignores `max_tokens` and truncates the JSON mid-object.

Two lessons are baked in here, both learned by getting them wrong first:

1. Probe with the REAL decision schema, not a toy one. A three-key schema passes
   on a provider whose full decision never fits, which is precisely how a broken
   provider reached a real run.
2. Measure cap compliance. If the provider returns more completion tokens than
   `max_tokens` asked for, the envelope arithmetic in the planner is void: it
   believes it is bounding the answer, and it is not.

This module is deliberately side-effect free: it sends one prompt, spends no scan
budget, writes no artifact, and never prints the API key.
"""
import json
import time

import litellm

litellm.suppress_debug_info = True
litellm.set_verbose = False

DEFAULT_PROBE_TIMEOUT = 90.0

PROBE_SYSTEM = (
    'You are a penetration-test planner. Reply with ONE JSON object that validates against '
    'the provided schema. Be extremely terse: rationale and reflection each under 120 '
    'characters, at most one action, at most one hypothesis.'
)
PROBE_USER = (
    'The authorized target is http://127.0.0.1:3000 with 74 discovered routes and one '
    'scanner match. Choose the single best next action.'
)


def _redact(text, api_key):
    """Remove the key from any diagnostic string before it is printed."""
    if not text:
        return text
    if api_key:
        text = str(text).replace(api_key, '<redacted>')
    return text


def _decision_schema():
    """The real planner schema, or None if it cannot be imported."""
    try:
        from src.adaptix.agents.schema import PlannerDecision
    except Exception:  # noqa: BLE001 - a probe must not fail on import shape
        return None
    try:
        return PlannerDecision.model_json_schema()
    except Exception:  # noqa: BLE001
        return None


def _validate(text):
    """Does this text validate as a real PlannerDecision? Returns (ok, detail)."""
    try:
        from src.adaptix.agents.schema import PlannerDecision
    except Exception:  # noqa: BLE001
        return None, 'PlannerDecision schema unavailable'
    try:
        PlannerDecision.model_validate_json(text)
        return True, ''
    except Exception as exc:  # noqa: BLE001 - any validation failure is the answer
        return False, _short_validation_error(str(exc))


def _short_validation_error(message, limit=300):
    """One readable line from a pydantic error blob."""
    message = ' '.join(str(message).split())
    return message[:limit]


def probe(model, api_base=None, api_key=None, native_json=None, timeout=DEFAULT_PROBE_TIMEOUT,
          temperature=0.0, max_tokens=1216, context_tokens=None, strict_schema=False):
    """Send one planner-shaped request and report whether the provider answers.

    `max_tokens` should be the envelope the real planner will allocate; the probe
    then measures whether the provider actually honours it. `strict_schema` sends
    the real `json_schema` response_format the planner uses for native-JSON
    families - a gateway that accepts it and ignores the schema still needs to be
    caught, because it lets the model write as much as it likes.
    """
    report = {'model': model, 'api_base': api_base or None, 'api_key_present': bool(api_key),
              'ok': False, 'problems': [], 'warnings': [], 'seconds': None,
              'prompt_tokens': None, 'output_tokens': None, 'max_tokens_requested': max_tokens,
              'finish_reason': None, 'content_chars': None, 'reasoning_chars': 0,
              'json_ok': False, 'schema_ok': None, 'provider_honours_max_tokens': None,
              'text': None}

    schema = _decision_schema()
    user = PROBE_USER
    if schema is not None:
        user = PROBE_USER + ' Schema: ' + json.dumps(schema, separators=(',', ':'))

    kwargs = {'model': model,
              'messages': [{'role': 'system', 'content': PROBE_SYSTEM},
                           {'role': 'user', 'content': user}],
              'max_tokens': max_tokens, 'temperature': temperature, 'timeout': timeout}
    if api_base:
        kwargs['api_base'] = api_base
    if api_key:
        kwargs['api_key'] = api_key
    family = str(model or '').lower().split('/', 1)[0] + '/'
    if strict_schema and schema is not None:
        kwargs['response_format'] = {'type': 'json_schema', 'json_schema': {
            'name': 'PlannerDecision', 'strict': True, 'schema': schema}}
    elif native_json is True:
        kwargs['response_format'] = {'type': 'json_object'}
    elif native_json is None and family in ('ollama_chat/', 'ollama/', 'openai/', 'openrouter/', 'azure/'):
        kwargs['response_format'] = {'type': 'json_object'}

    started = time.monotonic()
    try:
        response = litellm.completion(**kwargs)
    except Exception as exc:  # noqa: BLE001 - every provider error is a diagnostic here
        report['seconds'] = round(time.monotonic() - started, 2)
        report['problems'].append(_redact(f'{type(exc).__name__}: {exc}', api_key))
        return report
    report['seconds'] = round(time.monotonic() - started, 2)

    try:
        choice = response.choices[0]
        message = choice.message
    except (AttributeError, IndexError):
        report['problems'].append('provider returned a response with no choices[0].message')
        return report

    content = getattr(message, 'content', None) or ''
    reasoning = getattr(message, 'reasoning_content', None) or ''
    usage = getattr(response, 'usage', None)
    report['content_chars'] = len(content)
    report['reasoning_chars'] = len(reasoning)
    report['finish_reason'] = getattr(choice, 'finish_reason', None)
    if usage is not None:
        report['prompt_tokens'] = getattr(usage, 'prompt_tokens', None)
        report['output_tokens'] = getattr(usage, 'completion_tokens', None)

    # Cap compliance: the planner's envelope arithmetic assumes the provider stops
    # where it is told. A violation is not automatically fatal - the answer may
    # still have completed - but it makes truncation unpredictable.
    if report['output_tokens'] is not None:
        honoured = int(report['output_tokens']) <= int(max_tokens)
        report['provider_honours_max_tokens'] = honoured

    if not content.strip():
        if reasoning:
            report['problems'].append(
                f'reasoning model returned empty content and {len(reasoning)} chars of '
                'reasoning_content with finish_reason=%r at max_tokens=%d: the output budget '
                'was spent thinking before any answer was written. Raise '
                '--model-context-tokens or send reasoning_effort=none for this family.'
                % (report['finish_reason'], max_tokens))
        else:
            report['problems'].append('provider returned empty content with no reasoning field')
        return report

    stripped = content.strip()
    if stripped.startswith('```'):
        stripped = stripped.strip('`')
        if stripped.lower().startswith('json'):
            stripped = stripped[4:]
    parsed = None
    try:
        parsed = json.loads(stripped)
    except (ValueError, TypeError):
        start, end = stripped.find('{'), stripped.rfind('}')
        if start != -1 and end > start:
            try:
                parsed = json.loads(stripped[start:end + 1])
            except (ValueError, TypeError):
                parsed = None
    if isinstance(parsed, dict):
        report['json_ok'] = True
        report['text'] = parsed
        # Validate the extracted object, not the raw body: a fenced or
        # prose-padded answer is still a usable decision once extracted.
        validation_text = json.dumps(parsed)
    else:
        report['text'] = content.strip()[:400]
        validation_text = None
        truncated = report['finish_reason'] == 'length'
        report['problems'].append(
            'response was not a JSON object'
            + ('; finish_reason=length means it was cut off mid-object' if truncated else '')
            + '. The planner requires a complete JSON decision.')

    if report['finish_reason'] == 'length':
        report['problems'].append(
            'finish_reason=length: the answer was cut off before it completed. If the provider '
            'ignored max_tokens this is unavoidable at this setting - raise the window or '
            'choose a less verbose model.')

    # A cap violation only matters if the answer did not complete on its own. A
    # verbose-but-finished decision is usable; the warning records that the
    # planner's token arithmetic is approximate on this gateway.
    if report['provider_honours_max_tokens'] is False and report['finish_reason'] != 'length':
        report['warnings'].append(
            f'provider returned {report["output_tokens"]} completion tokens for a requested '
            f'max_tokens of {max_tokens}: the answer finished anyway, but the planner\'s token '
            'accounting is approximate on this gateway. Give it a generous context budget.')

    # Validate against the real schema. This is what catches a provider that
    # returns well-formed JSON that still cannot drive the graph.
    if validation_text is not None:
        ok, detail = _validate(validation_text)
        report['schema_ok'] = ok
        if ok is False:
            report['problems'].append(
                'JSON did not validate as a PlannerDecision: ' + detail)

    report['ok'] = report['json_ok'] and not report['problems']

    if context_tokens and report['prompt_tokens']:
        headroom = int(context_tokens) - int(report['prompt_tokens'])
        report['headroom_tokens'] = headroom
        if headroom < 512:
            report['ok'] = False
            report['problems'].append(
                f'only {headroom} tokens of headroom after a {report["prompt_tokens"]}-token '
                f'prompt in a {context_tokens}-token window; a planner decision needs more. '
                'Raise --model-context-tokens or shrink the run context.')
    return report
