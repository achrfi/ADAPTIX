import pytest


@pytest.fixture(autouse=True)
def isolated_operator_env(monkeypatch):
    """A real operator `.env` must not reach the test suite.

    `load_dotenv()` runs at CLI startup, and the provider flags read their
    defaults from the environment. Left in place, an operator's hosted provider
    and budgets silently became the suite's defaults: tests that assert the local
    Ollama default or a finite remote-budget guard failed purely because
    `.env` said otherwise. Configuration under test is explicit, never ambient.
    """
    for name in ('ADAPTIX_LLM_MODEL', 'ADAPTIX_API_BASE', 'ADAPTIX_API_KEY',
                 'ADAPTIX_MODEL_CONTEXT_TOKENS', 'ADAPTIX_LLM_TIMEOUT',
                 'ADAPTIX_TIME_BUDGET', 'ADAPTIX_TOOL_CALL_BUDGET',
                 'ADAPTIX_TOKEN_BUDGET', 'ADAPTIX_MAX_ITERATIONS',
                 'ADAPTIX_OLLAMA_BASE_URL'):
        monkeypatch.delenv(name, raising=False)
    # Deleting the variables is not enough: main() calls load_dotenv() itself,
    # which would read the operator's real .env back into the test process.
    from src.adaptix import main as main_module
    monkeypatch.setattr(main_module, 'load_dotenv', lambda: [])


@pytest.fixture(autouse=True)
def offline_tokenizer(monkeypatch):
    from src.adaptix.agents import planner
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kwargs: 100)


@pytest.fixture(autouse=True)
def no_live_sweep(monkeypatch):
    """Static content discovery is a real network sweep; unit tests never run one.

    Every other adapter in the suite is reached through monkeypatched ``read_get``
    style seams. The ffuf sweep is a subprocess against a live origin, so left
    unpatched it silently made an unrelated baseline test perform ~5,000 real HTTP
    requests. Tests that assert discovery behaviour patch this fixture's function
    themselves; the rest get an instant, recorded skip.
    """
    from src.adaptix.tools import static_discovery as module

    def unavailable(state):
        return {'discovery_limitations': list(state.get('discovery_limitations', [])) + [
                    {'url': str((state.get('planned_actions') or [{}])[0].get('target')),
                     'reason': 'disabled_in_tests'}],
                'static_discovery': {'skipped': 'disabled_in_tests'},
                'events': list(state.get('events', [])) + ['Static Discovery: disabled in tests']}

    monkeypatch.setattr(module, 'static_discovery', unavailable)
    from src.adaptix.workflow import baseline as baseline_module
    monkeypatch.setattr(baseline_module, 'static_discovery', unavailable)


@pytest.fixture
def verification_record():
    return {'template_id': 'idor', 'url': 'http://127.0.0.1:18080', 'object_id': '42',
            'verification_method': 'deterministic_replay', 'verification_basis': 'private_object_access',
            'ground_truth': {'private': True, 'identities_valid': True, 'owner': 'owner', 'object_id': '42'},
            'requests': [{'method': 'GET', 'url': 'http://127.0.0.1:18080', 'identity': name} for name in ('owner', 'other')],
            'responses': [{'status_code': 200, 'headers': {}, 'body_excerpt': 'private-object', 'body_sha256': 'a' * 64} for _ in range(2)],
            'steps': ['Replay known lab object as two accounts'],
            'expected_behavior': 'private data exposed to non-owner', 'actual_behavior': 'identical private data exposed'}
