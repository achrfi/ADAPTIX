"""Ollama context-window contract: num_ctx must be sent for ollama families.

Observed production failure: Ollama silently truncates any prompt larger than
its default 4096-token context window when num_ctx is not sent. Planner prompts
are 4k-16k tokens, so head-instructions were cut mid-ask; the model then drifted
to out-of-scope targets and empty plans. The planner must pass the same finite
window it built the prompt against, and must never send num_ctx to remote
providers that treat it as noise.

Offline test: the real graph runs with a mocked litellm.completion capturing
the provider kwargs; no network, no model, no target traffic.
"""
from unittest.mock import MagicMock

from src.adaptix.agents import planner
from src.adaptix.workflow.graph import graph
from src.adaptix.tools import registry

PRIORITY = {'goal_relevance': 0.5, 'information_gain': 0.5, 'evidence_value': 0.5,
            'confidence': 0.5, 'estimated_tokens': 50, 'estimated_seconds': 1,
            'estimated_requests': 1}
CATALOG = {'http_request': {'enabled': True, 'path': 'module'}}
STATE_ATTRIBUTES = {
    'run_id': 'ollama-num-ctx-fixture', 'events': [], 'execution_metrics': {},
    'raw_bytes': 0, 'errors': [], 'target': ['http://127.0.0.1:18080'],
    'hosts': ['127.0.0.1'], 'scope_ports': [18080],
    'scope_manifest': {'hosts': ['127.0.0.1']}, 'time_budget_seconds': 600,
    'tool_call_budget': 5, 'token_budget': 50000, 'run_started_at': 0.0,
    'model_context_tokens': 16384, 'attempted_actions': [], 'action_outcomes': [],
    'recent_evidence_keys': [], 'goal_status': None, 'stopped': False,
}


def _run(model, monkeypatch):
    done = {'calls': 0}

    def completion(**kwargs):
        done['calls'] += 1
        done['kwargs'] = kwargs
        return MagicMock(**{'choices': [MagicMock(**{'message': MagicMock(
            content='{"actions": [], "observations": [], "recommendations": [], "hypotheses": [], '
                    '"summary": "empty"}',
            tool_calls=None)})],
            'usage': None})

    monkeypatch.setattr(planner, 'tool_registry', lambda: CATALOG)
    monkeypatch.setattr(registry, 'tool_registry', lambda: CATALOG)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 100)
    monkeypatch.setattr(planner.litellm, 'completion', completion)
    import time
    graph.invoke({
        **STATE_ATTRIBUTES,
        'status': 'scope_ok', 'authorization': {'type': 'local_loopback'},
        'llm_model': model, 'time_budget_seconds': 600,
        'run_started_at': time.time(),
    })
    return done


def test_ollama_chat_prompt_carries_num_ctx(monkeypatch):
    model = 'ollama_chat/qwen3.5:9b-q4_K_M'
    result = _run(model, monkeypatch)
    assert 'num_ctx' in result['kwargs'], \
        'ollama_chat prompts must declare the context window: 4096 default truncation cut real instructions'
    assert result['kwargs']['num_ctx'] == 16384
    assert result['calls'] >= 1


def test_remote_family_does_not_get_ollama_num_ctx(monkeypatch):
    result = _run('openai/gpt-5.3', monkeypatch)
    assert 'num_ctx' not in result['kwargs'], 'num_ctx is an Ollama/llama.cpp knob, not a generic OpenAI parameter'
