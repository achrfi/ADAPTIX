"""The extraction targets must come from the target's own schema, not from this repo.

Measured defect this locks: `tools/union_extract.py` carried
`EXPRESSIONS = (('email', 'Users', 'user_email'), ('password', 'Users', 'password_hash'))`.
The column count was measured while the names were assumed, so the capability worked on
exactly one deployment. Names must now be read from the target's catalogue; this fake
target answers like a SQLite application and knows nothing about this repository.
"""
import sys

sys.path.insert(0, '/root/projects/adaptix')

from src.adaptix.evidence.union_extract import enumerate_schema, extraction_targets

SCHEMA = {'accounts': ['id', 'login', 'mail_addr', 'secret_hash'],
          'invoices': ['id', 'total', 'issued_at'],
          'widgets': ['id', 'label']}


def make_fetch(observed):
    def fetch(url):
        observed.append(url)
        if 'sqlite_master' not in url and "pragma_table_info" not in url:
            return 200, '{"data":[{"id":1,"label":"x"}]}'
        # Model the server: a catalogue query answers with a listing of identifiers.
        if 'sqlite_master' in url and "pragma_table_info('" not in url:
            return 200, '{"data":[{"id":1,"label":"%s"}]}' % ';'.join(SCHEMA)
        for table, columns in SCHEMA.items():
            if table in url:
                if table == 'accounts':
                    # The long listing case: the real target truncated at the excerpt cap.
                    return 200, '{"data":[{"id":1,"label":"%s"}]}' % ';'.join(columns)
                return 200, '{"data":[{"id":1,"label":"%s"}]}' % ';'.join(columns)
        return 200, '{"data":[{"id":1,"label":""}]}'
    return fetch


def test_the_catalogue_query_is_answered_and_parsed():
    observed = []
    schema = enumerate_schema(make_fetch(observed), 'http://h/rest/search', 'q',
                              {'columns': 10, 'opener': "a'))"})
    assert schema['dialect'] == 'sqlite', schema
    assert set(schema['tables']) == set(SCHEMA), schema['tables']
    assert schema['tables']['accounts'] == SCHEMA['accounts']
    # Named tables were only learned from the target, never declared in the tool.
    assert any('sqlite_master' in url for url in observed)


def test_extraction_targets_come_from_the_discovered_schema():
    observed = []
    schema = enumerate_schema(make_fetch(observed), 'http://h/rest/search', 'q',
                              {'columns': 10, 'opener': "a'))"})
    targets = extraction_targets(schema)
    expressions = {expression for expression, _table, _label in targets}
    # The credential pair is picked from the discovered columns.
    assert ('secret_hash', 'accounts', 'password_hash') in targets, targets
    assert ('mail_addr', 'accounts', 'user_email') in targets, targets
    # Nothing from another application's schema may appear.
    assert not any('Users' == table for _e, table, _l in targets if table), targets
    assert 'Users' not in ' '.join(expressions)


def test_an_unreadable_catalogue_falls_back_without_naming_a_table():
    def dead_fetch(url):
        return 500, '{"error":"no such table"}'

    schema = enumerate_schema(dead_fetch, 'http://h/rest/search', 'q',
                              {'columns': 10, 'opener': "a'))"})
    assert schema['tables'] == {}, schema
    targets = extraction_targets(schema)
    # A version string names no table, so it is the only honest fallback.
    assert [row[1] for row in targets] == [None, None], targets
    assert all('version' in row[2] for row in targets), targets
