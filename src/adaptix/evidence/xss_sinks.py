"""Derive XSS sinks from the mapped surface instead of one literal fragment.

Measured defect this closes: ``script_probe`` built ``'/#/search?q='`` as a constant, so a
browser XSS could only ever be found on an application whose sink happened to sit on that
exact route with that exact parameter. On every other target the class reported zero for
the wrong reason - not "not vulnerable" but "never tested".

The mapped surface already carries what is needed: ``web_routes`` holds every path the
bundle, links, forms, robots and ffuf produced, plus the parameter names the bundles wrote
after those paths (``/rest/products/search?q=``, ``/api/Challenges/?key=``). This module
turns that inventory into candidate sinks and orders them by how likely a client sink is,
so the browser probe spends its budget where input actually lands.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

# A bundled path that is clearly a static asset is not a sink.
_ASSET = re.compile(r'\.(?:js|mjs|css|map|ico|png|jpe?g|gif|svg|webp|avif|bmp|woff2?|ttf|otf|eot|mp4|webm|ogg|wav|mp3|pdf|zip)(?:$|\?)', re.I)
# Path segments that suggest the value is echoed into a page rather than consumed as JSON.
_PAGE_HINT = re.compile(r'(?i)(search|query|redirect|track|feedback|contact|profile|comment|review|message|name|address|q\b)')
# Paths that are clearly an API and therefore rarely render into HTML.
_API_HINT = re.compile(r'(?i)^/(?:api|rest|graphql|gql|rpc|services?)(?:/|$)')

# Parameter names a client-side router is known to read. These are conventional names a
# browser router exposes, not values belonging to one application.
ROUTER_PARAMETERS = ('q', 'query', 'search', 'name', 'id', 'term', 'redirect', 'url', 'message')


def _entry_urls(state):
    """The documents a browser can open: the root, and any observed HTML document."""
    entries = []
    for row in state.get('web_routes') or []:
        if not isinstance(row, dict):
            continue
        url = str(row.get('url') or '')
        parsed = urlsplit(url)
        if parsed.scheme not in ('http', 'https'):
            continue
        path = parsed.path.rstrip('/')
        kind = str(row.get('kind') or '')
        if kind in ('document', 'link') or path in ('', '/index.html', '/index.htm'):
            entries.append('%s://%s%s' % (parsed.scheme, parsed.netloc, parsed.path))
    # Deterministic order, root first.
    return sorted(dict.fromkeys(entries), key=lambda u: (urlsplit(u).path not in ('', '/'), u))


def _parameters_for(state, path):
    """Parameter names observed for a path, plus the echoed query of the mapped URL."""
    names = []
    for row in state.get('web_routes') or []:
        if not isinstance(row, dict):
            continue
        url = str(row.get('url') or '')
        parsed = urlsplit(url)
        if parsed.path.rstrip('/') != path.rstrip('/'):
            continue
        for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
            if key and key not in names:
                names.append(key)
        # A route captured as `/x/y?q=` carries the name in the raw text, not in parse_qsl.
        for key in re.findall(r'[?&]([A-Za-z0-9_\-]+)=', parsed.query or ''):
            if key and key not in names:
                names.append(key)
        tail = url.split(parsed.path, 1)[1] if parsed.path in url else ''
        for key in re.findall(r'[?&]([A-Za-z0-9_\-]+)=', tail):
            if key not in names:
                names.append(key)
    return names


def candidate_sinks(state, limit=12):
    """Ordered candidate sinks: (mode, url_template, parameter).

    ``mode`` is ``query`` (a normal ``?param=`` on an HTML-rendering path) or ``fragment``
    (a hash route, which is where an SPA router reads its input). Nothing here is
    specific to one application: the paths and parameter names come from the mapped
    inventory, and the router parameter list is a set of conventional names.
    """
    entries = _entry_urls(state)
    if not entries:
        return []
    candidates = []
    seen = set()

    def add(mode, url, parameter):
        key = (mode, url, parameter)
        if key in seen:
            return
        seen.add(key)
        candidates.append((mode, url, parameter))

    # Hash routes first: an SPA answering on its entry document reads the fragment, and a
    # hash route is invisible to a server-side probe by definition.
    entry = entries[0]
    for parameter in ROUTER_PARAMETERS:
        add('fragment', entry, parameter)

    for row in state.get('web_routes') or []:
        if not isinstance(row, dict):
            continue
        url = str(row.get('url') or '')
        parsed = urlsplit(url)
        if parsed.scheme not in ('http', 'https'):
            continue
        path = parsed.path.rstrip('/')
        if not path or path in ('', '/index.html', '/index.htm') or _ASSET.search(path):
            continue
        for parameter in _parameters_for(state, path):
            # A query parameter on a page-like path is a real server-side reflection sink.
            base = '%s://%s%s' % (parsed.scheme, parsed.netloc, parsed.path)
            if _PAGE_HINT.search(path) or not _API_HINT.search(path):
                add('query', base, parameter)

    # Deterministic and bounded: page-like paths with a page-like hint come first.
    def rank(item):
        mode, url, parameter = item
        return (0 if mode == 'fragment' else 1,
                0 if _PAGE_HINT.search(url) else 1,
                0 if parameter in ROUTER_PARAMETERS[:4] else 1,
                url, parameter)

    return sorted(candidates, key=rank)[:limit]
