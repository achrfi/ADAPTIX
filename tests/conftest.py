import pytest

@pytest.fixture(autouse=True)
def offline_tokenizer(monkeypatch):
    from src.adaptix.agents import planner
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kwargs: 100)


@pytest.fixture
def verification_record():
    return {'template_id': 'idor', 'url': 'http://127.0.0.1:18080', 'object_id': '42',
            'verification_method': 'deterministic_replay', 'verification_basis': 'private_object_access',
            'ground_truth': {'private': True, 'identities_valid': True, 'owner': 'owner', 'object_id': '42'},
            'requests': [{'method': 'GET', 'url': 'http://127.0.0.1:18080', 'identity': name} for name in ('owner', 'other')],
            'responses': [{'status_code': 200, 'headers': {}, 'body_excerpt': 'private-object', 'body_sha256': 'a' * 64} for _ in range(2)],
            'steps': ['Replay known lab object as two accounts'],
            'expected_behavior': 'private data exposed to non-owner', 'actual_behavior': 'identical private data exposed'}
