"""Provider integration: .env loading, preflight diagnosis, and key hygiene.

The invariant these tests protect: an operator can point Adaptix at a hosted
provider with a base URL and a key, learn *before* a long run whether that
combination can actually drive the planner, and never see the key leak.

Two failures are pinned here because both were hit for real and both looked like
"the provider is broken" from the outside:

- a toy probe schema passing on a provider whose REAL decision does not fit;
- a gateway that ignores `max_tokens`, so the planner's envelope arithmetic is
  fiction and the JSON is truncated mid-object.
"""
import json

import pytest

from src.adaptix import config as config_module
from src.adaptix.agents import provider_probe
from src.adaptix.agents.schema import PlannerDecision


# --- .env loading -----------------------------------------------------------

def test_dotenv_sets_missing_variables_and_never_overrides(tmp_path, monkeypatch):
    env = tmp_path / '.env'
    env.write_text(
        '# comment\n'
        'ADAPTIX_TEST_NEW=from-file\n'
        'export ADAPTIX_TEST_EXPORTED=exported-value\n'
        'ADAPTIX_TEST_QUOTED="quoted value"\n'
        'ADAPTIX_TEST_ALREADY=file-value\n'
        'ADAPTIX_TEST_TRAILING=value#not-a-comment\n'
        'malformed line without equals\n',
        encoding='utf-8')
    monkeypatch.setattr(config_module, 'ROOT', tmp_path)
    monkeypatch.setenv('ADAPTIX_TEST_ALREADY', 'shell-wins')
    for name in ('ADAPTIX_TEST_NEW', 'ADAPTIX_TEST_EXPORTED', 'ADAPTIX_TEST_QUOTED',
                 'ADAPTIX_TEST_TRAILING'):
        monkeypatch.delenv(name, raising=False)

    applied = config_module.load_dotenv()

    import os
    assert 'ADAPTIX_TEST_ALREADY' not in applied, 'an existing env var must win'
    assert os.environ['ADAPTIX_TEST_ALREADY'] == 'shell-wins'
    assert os.environ['ADAPTIX_TEST_NEW'] == 'from-file'
    assert os.environ['ADAPTIX_TEST_EXPORTED'] == 'exported-value'
    assert os.environ['ADAPTIX_TEST_QUOTED'] == 'quoted value'
    # A '#' inside a value is data, not a comment.
    assert os.environ['ADAPTIX_TEST_TRAILING'] == 'value#not-a-comment'
    assert len(applied) == 4


def test_dotenv_returns_names_never_values(tmp_path, monkeypatch):
    (tmp_path / '.env').write_text('ADAPTIX_TEST_SECRET=super-secret-value\n', encoding='utf-8')
    monkeypatch.setattr(config_module, 'ROOT', tmp_path)
    monkeypatch.delenv('ADAPTIX_TEST_SECRET', raising=False)
    applied = config_module.load_dotenv()
    assert applied == ['ADAPTIX_TEST_SECRET']
    assert 'super-secret-value' not in ' '.join(applied)


def test_dotenv_absent_file_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, 'ROOT', tmp_path)
    assert config_module.load_dotenv() == []


# --- fakes ------------------------------------------------------------------

class _Usage:
    def __init__(self, prompt_tokens=100, completion_tokens=40):
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens


class _Message:
    def __init__(self, content, reasoning_content=None):
        self.content = content
        self.reasoning_content = reasoning_content


class _Choice:
    def __init__(self, message, finish_reason='stop'):
        self.message = message
        self.finish_reason = finish_reason


class _Response:
    def __init__(self, choice, usage=None):
        self.choices = [choice]
        self.usage = usage or _Usage()


def _valid_decision():
    """A decision that passes the real PlannerDecision schema."""
    return json.dumps({
        'actions': [{
            'tool': 'http_request',
            'target': 'http://127.0.0.1:3000/',
            'reason': 'fingerprint the root',
            'priority': {'goal_relevance': 0.9, 'information_gain': 0.8,
                         'evidence_value': 0.7, 'confidence': 0.8,
                         'estimated_tokens': 120, 'estimated_seconds': 1.0,
                         'estimated_requests': 1},
        }],
        'rationale': 'fingerprint first',
        'reflection': 'root response headers will guide the next step',
    })


# --- preflight diagnosis ----------------------------------------------------

def test_probe_passes_on_a_real_planner_decision(monkeypatch):
    seen = {}

    def fake_completion(**kwargs):
        seen.update(kwargs)
        return _Response(_Choice(_Message(_valid_decision())), _Usage(100, 200))

    monkeypatch.setattr(provider_probe.litellm, 'completion', fake_completion)
    report = provider_probe.probe('openai/gpt-4o-mini', api_base='https://api.example.com/v1',
                                  api_key='sk-test-key', max_tokens=1216)

    assert report['ok'] is True
    assert report['json_ok'] is True
    assert report['schema_ok'] is True
    assert report['problems'] == []
    assert seen['api_base'] == 'https://api.example.com/v1'
    assert seen['api_key'] == 'sk-test-key'
    assert seen['response_format'] == {'type': 'json_object'}
    assert seen['max_tokens'] == 1216


def test_probe_sends_the_real_decision_schema_not_a_toy_one(monkeypatch):
    """A toy schema passes where the real one fails - that is how a bad provider shipped."""
    seen = {}

    def fake_completion(**kwargs):
        seen.update(kwargs)
        return _Response(_Choice(_Message(_valid_decision())))

    monkeypatch.setattr(provider_probe.litellm, 'completion', fake_completion)
    provider_probe.probe('openai/gpt-4o-mini')

    prompt = ' '.join(m['content'] for m in seen['messages'])
    assert '"actions"' in prompt
    assert 'hypotheses' in prompt, 'the probe must describe the real decision schema'


def test_probe_rejects_json_that_cannot_drive_the_graph(monkeypatch):
    """Well-formed JSON missing required fields is still a broken planner."""
    def fake_completion(**kwargs):
        return _Response(_Choice(_Message('{"reasoning": "r", "action": "a", "target": "t"}')))

    monkeypatch.setattr(provider_probe.litellm, 'completion', fake_completion)
    report = provider_probe.probe('openai/gpt-4o-mini')

    assert report['ok'] is False
    assert report['json_ok'] is True
    assert report['schema_ok'] is False
    assert any('PlannerDecision' in p for p in report['problems'])


def test_probe_detects_a_gateway_that_ignores_max_tokens(monkeypatch):
    """Measured for real: asked 16-4096, the gateway always returned 1027 tokens.

    A finished answer that overran the cap is a warning, not a failure - but a
    cut-off one (finish_reason=length) is fatal, because the JSON is incomplete.
    """
    def fake_finished(**kwargs):
        return _Response(_Choice(_Message(_valid_decision()), finish_reason='stop'),
                         _Usage(5000, 1842))

    monkeypatch.setattr(provider_probe.litellm, 'completion', fake_finished)
    report = provider_probe.probe('openai/autoapp/glm-5.3', max_tokens=1216)

    assert report['provider_honours_max_tokens'] is False
    assert report['ok'] is True, 'a complete, schema-valid answer is usable'
    assert any('max_tokens' in w for w in report['warnings'])

    def fake_truncated(**kwargs):
        return _Response(_Choice(_Message(_valid_decision()), finish_reason='length'),
                         _Usage(5000, 2048))

    monkeypatch.setattr(provider_probe.litellm, 'completion', fake_truncated)
    cut = provider_probe.probe('openai/autoapp/glm-5.3', max_tokens=850)

    assert cut['ok'] is False
    assert any('finish_reason=length' in p for p in cut['problems'])


def test_probe_records_cap_compliance_when_the_provider_obeys(monkeypatch):
    def fake_completion(**kwargs):
        return _Response(_Choice(_Message(_valid_decision())), _Usage(500, 120))

    monkeypatch.setattr(provider_probe.litellm, 'completion', fake_completion)
    report = provider_probe.probe('openai/gpt-4o-mini', max_tokens=850)

    assert report['provider_honours_max_tokens'] is True


def test_probe_identifies_reasoning_model_starvation(monkeypatch):
    """Empty content + reasoning_content is a starved reasoning model, not a bad key."""
    def fake_completion(**kwargs):
        return _Response(_Choice(_Message('', reasoning_content='x' * 900), finish_reason='length'),
                         _Usage(100, 320))

    monkeypatch.setattr(provider_probe.litellm, 'completion', fake_completion)
    report = provider_probe.probe('ollama_chat/qwen3:8b')

    assert report['ok'] is False
    assert any('reasoning model' in p for p in report['problems'])


def test_probe_redacts_the_api_key_from_provider_errors(monkeypatch):
    def explode(**kwargs):
        raise RuntimeError('401 Unauthorized for key sk-leaked-abcdef123456')

    monkeypatch.setattr(provider_probe.litellm, 'completion', explode)
    report = provider_probe.probe('openai/gpt-4o-mini', api_key='sk-leaked-abcdef123456')

    assert report['ok'] is False
    blob = json.dumps(report)
    assert 'sk-leaked-abcdef123456' not in blob
    assert '<redacted>' in blob


def test_probe_flags_non_json_output(monkeypatch):
    def fake_completion(**kwargs):
        return _Response(_Choice(_Message('Sure! I will start by scanning the host.')))

    monkeypatch.setattr(provider_probe.litellm, 'completion', fake_completion)
    report = provider_probe.probe('openai/gpt-4o-mini')

    assert report['ok'] is False
    assert any('not a JSON object' in p for p in report['problems'])


def test_probe_accepts_json_wrapped_in_a_code_fence(monkeypatch):
    def fake_completion(**kwargs):
        return _Response(_Choice(_Message('```json\n' + _valid_decision() + '\n```')))

    monkeypatch.setattr(provider_probe.litellm, 'completion', fake_completion)
    report = provider_probe.probe('openai/gpt-4o-mini')

    assert report['ok'] is True
    assert report['schema_ok'] is True


def test_probe_does_not_send_response_format_to_anthropic(monkeypatch):
    seen = {}

    def fake_completion(**kwargs):
        seen.update(kwargs)
        return _Response(_Choice(_Message(_valid_decision())))

    monkeypatch.setattr(provider_probe.litellm, 'completion', fake_completion)
    provider_probe.probe('anthropic/claude-sonnet-4', api_key='sk-ant')

    assert 'response_format' not in seen


def test_probe_reports_connection_failure_without_raising(monkeypatch):
    def explode(**kwargs):
        raise ConnectionError('Connection refused to http://127.0.0.1:20128/v1')

    monkeypatch.setattr(provider_probe.litellm, 'completion', explode)
    report = provider_probe.probe('openai/gpt-4o-mini', api_base='http://127.0.0.1:20128/v1')

    assert report['ok'] is False
    assert 'ConnectionError' in report['problems'][0]


def test_probe_fails_when_the_window_has_no_room_to_answer(monkeypatch):
    """A 7.8k prompt in an 8k window is the defect that looked like a dead provider."""
    def fake_completion(**kwargs):
        return _Response(_Choice(_Message(_valid_decision())), _Usage(7800, 30))

    monkeypatch.setattr(provider_probe.litellm, 'completion', fake_completion)
    report = provider_probe.probe('openai/gpt-4o-mini', context_tokens=8192)

    assert report['ok'] is False
    assert report['headroom_tokens'] == 392
    assert any('headroom' in p for p in report['problems'])


def test_probe_passes_with_ample_headroom(monkeypatch):
    def fake_completion(**kwargs):
        return _Response(_Choice(_Message(_valid_decision())), _Usage(900, 40))

    monkeypatch.setattr(provider_probe.litellm, 'completion', fake_completion)
    report = provider_probe.probe('openai/gpt-4o-mini', context_tokens=32768)

    assert report['ok'] is True
    assert report['headroom_tokens'] == 32768 - 900


def test_the_probe_decision_fixture_matches_the_live_schema():
    """Guard against the probe drifting away from what the graph accepts."""
    PlannerDecision.model_validate_json(_valid_decision())
