"""Collections that prove ownership must be fetched deterministically.

Measured: two full runs reached `scenario_candidates: 0` although the collection
(`/books/v1`) was documented, in scope, unauthenticated to read, and one GET away.
Candidate derivation only runs when a 200 observation of the collection exists, and
nothing but the model's own choices ever requested it. An obvious BOLA therefore
produced no finding. `collection_index` selects those collections without model input.
"""
from src.adaptix.tools.discovery import collection_index

IDENT = {'identities': [{'name': 'owner', 'headers': {'Authorization': 'Bearer x'}}]}


def _state(operations, observations=(), identities=IDENT):
    # Scope is expressed as hosts + ports, matching what the guard actually reads.
    return {'api_operations': operations, 'api_observations': list(observations),
            'identity_context': identities, 'hosts': ['127.0.0.1'],
            'target': 'http://127.0.0.1:18080'}


OPS = [{'url': 'http://127.0.0.1:18080/books/v1', 'method': 'GET', 'authenticated': False},
       {'url': 'http://127.0.0.1:18080/books/v1/{book_title}', 'method': 'GET', 'authenticated': True}]


def test_documented_collection_is_selected():
    assert collection_index(_state(OPS)) == ['http://127.0.0.1:18080/books/v1']


def test_already_observed_collection_is_not_refetched():
    seen = [{'url': 'http://127.0.0.1:18080/books/v1', 'status_code': 200}]
    assert collection_index(_state(OPS, seen)) == []


def test_no_identity_context_means_no_objective():
    """Without identities there is no owner to compare against."""
    assert collection_index(_state(OPS, identities={})) == []


def test_unauthenticated_detail_is_not_a_privileged_object():
    ops = [{'url': 'http://127.0.0.1:18080/users/v1/{username}', 'method': 'GET', 'authenticated': False}]
    assert collection_index(_state(ops)) == []


def test_nested_template_is_not_a_direct_collection():
    ops = [{'url': 'http://127.0.0.1:18080/books/v1/{shelf}/{book_title}', 'method': 'GET', 'authenticated': True}]
    assert collection_index(_state(ops)) == []


def test_non_get_operations_are_ignored():
    ops = [{'url': 'http://127.0.0.1:18080/books/v1/{book_title}', 'method': 'POST', 'authenticated': True}]
    assert collection_index(_state(ops)) == []


def test_out_of_scope_collection_is_refused():
    ops = [{'url': 'http://evil.example.com/books/v1/{id}', 'method': 'GET', 'authenticated': True}]
    assert collection_index(_state(ops)) == []


def test_each_collection_appears_once():
    ops = OPS + [{'url': 'http://127.0.0.1:18080/books/v1/{isbn}', 'method': 'GET', 'authenticated': True}]
    assert collection_index(_state(ops)) == ['http://127.0.0.1:18080/books/v1']
