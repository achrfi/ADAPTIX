"""ADAPTIX unified module. Iterasi 4: LLM-driven adaptive planner with budget-aware fallback."""
import json
import litellm
from pydantic import ValidationError
from src.adaptix.config import config
from src.adaptix.security.scope import allowed_url
from src.adaptix.tools.registry import tool_registry
from src.adaptix.agents.schema import PlannerDecision
from src.adaptix.workflow.events import log


def _deterministic_fallback(state):
    ports = {80, 443, 8080, 8443, 18080}
    selected = []
    for svc in state.get('services', []):
        name = svc['service'].lower()
        if 'http' not in name and svc['port'] not in ports:
            continue
        host = svc['host']
        if ':' in host:
            host = f'[{host}]'
        scheme = 'https' if svc['port'] in (443, 8443, 9443) or svc['tunnel'] == 'ssl' else 'http'
        selected.append(f'{scheme}://{host}:{svc["port"]}')
    limits = config('scope.yaml')['limits']
    return list(dict.fromkeys(selected))[:int(limits['max_web_urls'])]


def adaptive_planning(state):
    limits = config('scope.yaml')['limits']
    max_iterations = int(state.get('max_iterations', 8))
    tool_call_budget = int(state.get('tool_call_budget', 20))
    token_budget = int(state.get('token_budget', 50_000))

    metrics = dict(state.get('planner_metrics', {}))
    tokens_used = int(metrics.get('tokens_used', 0))
    tool_calls_used = int(metrics.get('tool_calls_used', 0))
    iteration = int(state.get('iterations', 0))

    budget_exhausted = (
        iteration >= max_iterations
        or tool_calls_used >= tool_call_budget
        or tokens_used >= token_budget
    )
    if budget_exhausted:
        selected = _deterministic_fallback(state)
        return {
            'planned_urls': selected,
            'planner_metrics': {**metrics, 'mode': 'fallback_budget_exhausted'},
            'events': log(state, f'Adaptive Planning: budget exhausted, fallback ({len(selected)} URLs)'),
        }

    registry = tool_registry()
    available_tools = [name for name, info in registry.items() if info.get('enabled') and info.get('path')]
    hosts = state.get('hosts', [])
    services = state.get('services', [])

    system_prompt = (
        'You are a pentest planner focused on web/API attack surface, especially '
        'authentication, session, and object-access endpoints that may later need '
        'authorization (IDOR/BOLA) testing. You may ONLY choose tools from this list: '
        f'{available_tools}. You may ONLY target these authorized hosts: {hosts}. '
        'When ranking actions, prioritize endpoints that look like API paths '
        '(e.g. /api/, /v1/, query params with IDs) or auth flows over generic static pages. '
        'Reply with ONLY JSON matching this schema: '
        f'{PlannerDecision.model_json_schema()}. No prose, no markdown fences.'
    )
    user_prompt = json.dumps({'services': services}, ensure_ascii=False)

    try:
        response = litellm.completion(
            model=state.get('llm_model', 'groq/llama-3.3-70b-versatile'),
            messages=[{'role': 'system', 'content': system_prompt},
                      {'role': 'user', 'content': user_prompt}],
            response_format={'type': 'json_object'},
            timeout=20,
        )
        usage = getattr(response, 'usage', None)
        input_tokens = getattr(usage, 'prompt_tokens', 0) or 0
        output_tokens = getattr(usage, 'completion_tokens', 0) or 0
        raw = response.choices[0].message.content
        decision = PlannerDecision.model_validate_json(raw)
    except (ValidationError, Exception) as exc:
        selected = _deterministic_fallback(state)
        return {
            'planned_urls': selected,
            'planner_metrics': {**metrics, 'mode': 'fallback_llm_error', 'last_error': str(exc)[:200]},
            'events': log(state, f'Adaptive Planning: LLM error, fallback - {exc}'),
        }

    allowed_ports = {int(p) for p in str(config('scope.yaml')['limits']['nmap_ports']).split(',')}
    approved = []
    for action in decision.actions:
        if action.tool not in available_tools:
            continue
        if not allowed_url(action.target, hosts, allowed_ports):
            continue
        approved.append(action.target)
    selected = list(dict.fromkeys(approved))[: int(limits['max_web_urls'])]

    new_metrics = {
        **metrics,
        'mode': 'llm',
        'tokens_used': tokens_used + input_tokens + output_tokens,
        'tool_calls_used': tool_calls_used + 1,
        'last_input_tokens': input_tokens,
        'last_output_tokens': output_tokens,
        'rationale': decision.rationale[:500],
    }
    return {
        'planned_urls': selected,
        'planner_metrics': new_metrics,
        'events': log(state, f'Adaptive Planning (LLM): {len(selected)} endpoints, {input_tokens+output_tokens} tokens'),
    }
