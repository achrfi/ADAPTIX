"""Tool capability contract and endpoint provenance.

Capability is not security. This module answers one question about an action:
*does the run hold the inputs that this tool declares as prerequisites, and which
inputs are eligible right now?* It reports the missing prerequisite and the
eligible alternatives. It never refuses an action because it is tactically unwise,
and it never encodes an attack order, an endpoint priority or a payload list.

The distinction that matters: **missing evidence is not an unauthorized action**.
A route extracted from a JavaScript bundle is real observed evidence of an endpoint
existing in the application, so it is eligible for a bounded, authorized request
that establishes whether it answers; it is not eligible for a claim about it.
"""
import re
from urllib.parse import urlsplit

from src.adaptix.config import config
from src.adaptix.security.guard import is_destructive
from src.adaptix.security.scope import allowed_url, endpoint_key
from src.adaptix.security.ports import ports_for_state

# Conventional machine-readable index documents. These are *hypotheses* the run may
# test with one bounded GET; listing them is not a claim that they exist.
DOC_PATHS = ('/openapi.json', '/swagger.json', '/api/openapi.json', '/api-docs')

# Provenance sources. ``validated`` marks sources that carry a real observed HTTP
# response; the rest prove the endpoint exists in the application but not that it
# answers for us.
VALIDATED_SOURCES = frozenset({'seed_target', 'http_service', 'http_observation',
                               'browser_observation', 'api_observation', 'http_probe',
                               'fetched_document', 'scenario_object'})
VALIDATION_FIELDS = frozenset({'status_code', 'validated'})

# Tools whose input is a configured name rather than a URL. Their prerequisites are
# about stored fixtures, not about scope.
NAMED_TOOLS = frozenset({'scenario', 'idor'})


def permitted_tools(state=None):
    """The tool names the runtime actually holds, derived from the live registry.

    This is the single source of the planner's tool vocabulary. It is computed from
    the same registry the executor dispatches from, so a name the run cannot execute
    can never be proposed as if it were available. No static list of tool names is
    duplicated here: an unknown tool is not a tool.
    """
    from src.adaptix.tools.registry import tool_registry
    return tuple(sorted(name for name, spec in tool_registry().items()
                        if spec.get('enabled') and spec.get('path')))


def origin(url):
    parsed = urlsplit(url)
    return f'{parsed.scheme}://{parsed.netloc}'


def permitted(state, url):
    manifest = state.get('scope_manifest') or {}
    hosts = manifest.get('hosts') if manifest else state.get('hosts', [])
    aliases = manifest.get('aliases') if manifest else state.get('scope_aliases', {})
    networks = manifest.get('networks') if manifest else state.get('scope_networks', [])
    return allowed_url(url, hosts or [], set(ports_for_state(state, config('scope.yaml')['limits'])),
                       aliases or {}, networks or [])


def resolve_target(state, target):
    """Resolve a model-authored relative path against the run's authorized origin.

    Scope is a property of the destination (scheme, host, port), never of the path:
    a test value or endpoint path the model constructs for an observed, authorized
    surface is not a new authorization question. A leading-slash relative path is
    resolved against the origins the operator pinned in ``state['target']`` and kept
    only when the absolute result passes the same scope check the executor applies.
    Protocol-relative and host-bearing forms are never resolved: changing the
    origin is always a new authorization question.
    """
    if not isinstance(target, str) or not target.startswith('/') or target.startswith('//'):
        return target if target and '://' in str(target) else None
    parsed = urlsplit(target)
    if parsed.netloc or parsed.scheme:
        return None
    targets = state.get('target') or []
    targets = [targets] if isinstance(targets, str) else list(targets)
    for value in targets:
        if '://' not in str(value or ''):
            continue
        absolute = origin(value).rstrip('/') + target
        try:
            if permitted(state, absolute):
                return absolute
        except (ValueError, KeyError):
            continue
    return None


def endpoint_provenance(state):
    """Map every endpoint the run knows about to how it came to be known.

    Every source is recorded so the planner can tell a reference observed in a
    bundle apart from a response that actually came back. Provenance is additive:
    discovering a route never erases the fact that it was later validated.
    """
    provenance = {}

    def note(url, source, kind=None, status_code=None, method='GET'):
        key = endpoint_key(url) if '://' in str(url or '') else None
        if not key:
            return None
        row = provenance.setdefault(key, {'urls': [], 'sources': set(), 'kinds': set(),
                                          'validated': False, 'status_codes': set(),
                                          'methods': set(), 'references': 0})
        if url not in row['urls'] and len(row['urls']) < 4:
            row['urls'].append(url)
        row['sources'].add(source)
        row['methods'].add(str(method or 'GET').upper())
        if kind:
            row['kinds'].add(kind)
        if isinstance(status_code, int):
            row['status_codes'].add(status_code)
            row['validated'] = True
        elif source in VALIDATED_SOURCES:
            row['validated'] = True
        if source not in VALIDATED_SOURCES:
            row['references'] += 1
        return row

    targets = state.get('target', [])
    targets = [targets] if isinstance(targets, str) else list(targets)
    for value in targets:
        if '://' in str(value or ''):
            note(value, 'seed_target')
            note(origin(value).rstrip('/') + '/', 'seed_target')
    for row in state.get('services', []):
        if 'http' in str(row.get('service', '')).lower():
            scheme = 'https' if row.get('tunnel') == 'ssl' or int(row.get('port', 80)) == 443 else 'http'
            host = '[' + row['host'] + ']' if ':' in str(row['host']) else row['host']
            note(f'{scheme}://{host}:{row["port"]}/', 'http_service', status_code=200)
    for kind, source in (('http_services', 'http_observation'), ('browser_evidence', 'browser_observation'),
                         ('api_observations', 'api_observation')):
        for row in state.get(kind, []):
            note(row.get('url'), source, kind=kind, status_code=row.get('status_code'))
            for link in row.get('links', []) or []:
                note(link, source, kind='link')
    for row in state.get('probe_traces', []):
        note(row.get('url'), 'http_probe', kind='probe', status_code=row.get('status_code'),
             method=row.get('method'))
    for row in state.get('web_routes', []):
        note(row.get('url'), 'discovered_route', kind=row.get('kind'),
             status_code=row.get('status_code'), method=row.get('method'))
    for value in state.get('discovered_documents', []) or []:
        note(value, 'fetched_document', kind='document', status_code=200)
    for row in state.get('api_operations', []) or []:
        if '{' not in str(row.get('url', '')):
            note(row.get('url'), 'documented_operation', kind=row.get('method', 'GET').lower(),
                 status_code=200)
    for row in state.get('scenario_candidates', []) or []:
        note(row.get('url'), 'scenario_candidate', kind='scenario', status_code=200)
    for row in state.get('idor_scenarios', []) or []:
        note(row.get('base_url'), 'scenario_object', kind='idor', status_code=200)
    for row in state.get('ffuf_observations', []) or []:
        # Operator-imported ffuf rows carry the operator's own recorded HTTP
        # response: provenance for a bounded authorized request, with the
        # unverified provenance flag preserved on the observation row.
        note(row.get('url'), 'operator_ffuf_json', kind='ffuf_observation',
             status_code=row.get('status_code'), method=row.get('method'))
    return provenance


def provenance_row(provenance, url):
    key = endpoint_key(url) if '://' in str(url or '') else None
    row = provenance.get(key) if key else None
    if not row:
        return None
    return {'url': (row['urls'] or [url])[0], 'sources': sorted(row['sources']),
            'kinds': sorted(row['kinds']), 'http_validated': bool(row['validated']),
            'status_codes': sorted(row['status_codes']), 'methods': sorted(row['methods']),
            'references': row['references']}


def document_probes(state):
    """Conventional index documents for every in-scope origin, labelled as probes."""
    urls = set()
    targets = state.get('target', [])
    targets = [targets] if isinstance(targets, str) else list(targets)
    for value in targets:
        if '://' in str(value or ''):
            urls.add(str(value))
    for kind in ('http_services', 'browser_evidence'):
        for row in state.get(kind, []) or []:
            if row.get('url'):
                urls.add(str(row['url']))
    for key, row in endpoint_provenance(state).items():
        if row['validated']:
            urls.update(row['urls'])
    candidates = set()
    for url in urls:
        for path in DOC_PATHS:
            probe = origin(url) + path
            if permitted(state, probe):
                candidates.add(probe)
    return sorted(candidates, key=lambda u: (not u.endswith(('openapi.json', 'openapi.yaml')), u))


def documentation_attempts(state):
    """Document probes that were actually fetched, with the outcome that was recorded."""
    attempts = {}
    for row in state.get('api_observations', []) or []:
        url = row.get('url')
        if not url:
            continue
        kind = row.get('document_kind')
        status = row.get('status_code')
        attempts[url] = {'url': url, 'status_code': status, 'document_kind': kind,
                         'usable': bool(kind in ('openapi', 'json')) and (status is None or int(status) < 400),
                         'evidence_ref': row.get('evidence_ref'), 'reason': row.get('reason')}
    return attempts


def failed_document_origins(state):
    """Origins where a conventional index document was already fetched for nothing.

    A 404 or 500 on a conventional document path is a recorded negative result, not
    a missing prerequisite: retrying the same guess on the same origin adds no
    information. The family reopens only if the application itself later points at
    a document URL through some other evidence.
    """
    origins = {}
    for url, row in documentation_attempts(state).items():
        if row['usable']:
            continue
        if any(url.endswith(path) for path in DOC_PATHS):
            origins.setdefault(origin(url), row)
    return origins


class Evidence:
    """Derived views of the run's evidence, computed once per planning pass.

    Provenance, document attempts and the conventional-probe list are all derived
    from the same state, so resolving them once keeps a pass linear in the number
    of endpoints instead of quadratic.
    """

    def __init__(self, state):
        self.state = state
        self.provenance = endpoint_provenance(state)
        self.attempts = documentation_attempts(state)
        self.probes = document_probes(state)
        self.failed_origins = failed_document_origins(state)

    def external_sources(self, url):
        """Provenance sources other than the fetch that already answered for this URL."""
        return {name for name in (self.provenance.get(endpoint_key(url)) or {}).get('sources', ())
                if name != 'api_observation'}


def _probed(state):
    """Requests already issued: path -> set of recorded (method, payload) pairs."""
    probes = {}
    for trace in state.get('probe_traces', []) or []:
        if not isinstance(trace, dict):
            continue
        probes.setdefault(trace.get('path_key'), set()).add(
            (str(trace.get('method') or 'GET').upper(), str(trace.get('payload') or '')))
    return probes


def path_key(url):
    parsed = urlsplit(url)
    return f'{parsed.scheme}://{parsed.netloc}{parsed.path}'


def payload_candidates(url):
    from urllib.parse import parse_qsl, unquote_plus
    values = []
    for _, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        values.extend([value, unquote_plus(value)])
    return sorted({value for value in values if value})


def missing_prerequisites(state, action, evidence=None):
    """Prerequisites this run does not satisfy for ``action``.

    Returns a list of ``{'code', 'missing', 'detail'}``. An empty list means the
    tool's declared inputs are present; it never implies the action is authorized
    or advisable, both of which are decided elsewhere.
    """
    tool = action.get('tool')
    target = action.get('target', '')
    missing = []
    evidence = evidence or Evidence(state)
    provenance = evidence.provenance

    def require(code, detail, *names):
        missing.append({'code': code, 'missing': list(names) or [code], 'detail': detail})

    if tool in NAMED_TOOLS:
        from src.adaptix.tools.discovery import derive_candidates
        if tool == 'scenario':
            names = {row['name'] for row in derive_candidates(state)}
            if target not in names:
                require('unknown_scenario_candidate',
                        'Unknown scenario candidate: scenario_candidates lists the names built from observed '
                        'collection ownership and a documented GET detail route', 'scenario_candidate_name')
            context = state.get('identity_context', {})
            identities = context.get('identities', [])
            if len({i.get('name') for i in identities}) != 2:
                require('identity_context_required',
                        'Two distinct operator-supplied sessions are required before an ownership scenario can be validated',
                        'two_identities')
            if not (context.get('private_fields') and context.get('identity_json_path')):
                require('private_field_policy_required',
                        'An explicit private-field policy and identity response path are required',
                        'private_field_policy')
        else:
            names = {row.get('name') for row in state.get('idor_scenarios', [])}
            if target not in names:
                require('unknown_scenario_name',
                        'Unknown IDOR scenario: idor_scenarios lists the names produced by the scenario tool',
                        'idor_scenario_name')
        return missing

    if tool in ('nmap', 'httpx', 'playwright', 'browser_test', 'nuclei', 'http_request',
                'web_discover', 'api_discover', 'static_discovery'):
        # Path-only relative targets are model-authored construction for an
        # in-scope surface, resolved against the authorized origin; only a form
        # scope can express (an absolute URL) is required here.
        resolved = resolve_target(state, target)
        if tool != 'nmap' and not endpoint_key(resolved):
            require('malformed_target', 'Target must be an http/https URL in scope: observed absolute URLs are eligible, '
                                        'and a relative test path is eligible with a leading slash (for example /api/v1/status) '
                                        'which the runtime resolves against the authorized origin', 'in_scope_url')
            return missing
        if tool != 'nmap':
            target = resolved
        methods = sorted((provenance.get(endpoint_key(target)) or {}).get('methods', ())) if endpoint_key(target) else []
        # http_request carries its own method field, so a route only ever observed
        # as POST is actionable for it; GET-only tools issue GETs they did not choose.
        if tool != 'http_request' and methods and not set(methods) & {'GET', 'HEAD'}:
            require('method_mismatch',
                    f'This route was only ever observed as {"/".join(methods)}; these tools issue a GET',
                    'get_capable_route')
        # A URL the run has already fetched and learned nothing from is not an open
        # question. This is evidence-based, applies to whichever tool would re-fetch
        # it, and is re-opened by any new reference from the application itself.
        prior = evidence.attempts.get(target)
        external = evidence.external_sources(target)
        if tool == 'browser_test':
            marker = str(action.get('marker') or '')
            if not re.fullmatch(r'[A-Za-z0-9_.-]{6,64}', marker) or marker not in target:
                require('marker_required',
                        'The action must carry a 6-64 character marker that appears inside the URL: the browser test '
                        'signs execution from the marker dialog on the payload navigation and its absence on a '
                        'control navigation of the marker-stripped URL', 'marker_in_url')
                return missing
        if prior is not None and not prior['usable'] and not external:
            require('already_fetched_unusable',
                    f'This URL was already fetched and returned HTTP {prior.get("status_code")}'
                    f' ({prior.get("document_kind")}); fetching it again adds nothing without new evidence',
                    'new_evidence')
        if prior is not None and not prior['usable'] and not external:
            require('already_fetched_unusable',
                    f'This URL was already fetched and returned HTTP {prior.get("status_code")}'
                    f' ({prior.get("document_kind")}); fetching it again adds nothing without new evidence',
                    'new_evidence')
        exhausted = evidence.failed_origins
        if target in set(evidence.probes) and origin(target) in exhausted and not external:
            record = exhausted[origin(target)]
            require('documentation_exhausted',
                    f'No index document is served here: a conventional one already returned HTTP '
                    f'{record.get("status_code")} ({record.get("document_kind")}). Documentation discovery for this '
                    'origin is done; investigate the routes and responses actually observed instead',
                    'new_evidence')
    if tool == 'http_request':
        method = str(action.get('method') or 'GET').upper()
        identity = str(action.get('identity') or '').strip()
        if identity:
            names = {row.get('name') for row in (state.get('identity_context') or {}).get('identities', [])
                     if isinstance(row, dict) and row.get('name')}
            if identity not in names:
                require('unknown_identity',
                        'Unknown identity: capability inputs list identity_names from operator configuration; '
                        'its headers cannot be invented by the model', 'identity_name')
            elif method not in ('GET', 'HEAD'):
                require('identity_safe_method_only',
                        'A selected identity accompanies read-only requests only', 'identity_safe_method')
        if method in ('GET', 'HEAD'):
            proposed = tuple(payload_candidates(target))
            if not proposed:
                visited = {endpoint_key(value) for value in state.get('discovered_documents', [])
                           if isinstance(value, str) and endpoint_key(value)}
                key = endpoint_key(target)
                if key and key in visited:
                    require('document_already_fetched',
                            'Document already fetched by discovery; a repeated control request adds no information. '
                            'A discovered application endpoint is eligible instead', 'novel_request')
            else:
                recorded = tuple(sorted(value for value in str(
                    next((t.get('payload') for t in state.get('probe_traces', [])
                          if t.get('path_key') == path_key(target)
                          and str(t.get('method') or 'GET').upper() == method), '')).split('&') if value))
                if any(t.get('path_key') == path_key(target)
                       and str(t.get('method') or 'GET').upper() == method
                       and tuple(sorted(value for value in str(t.get('payload') or '').split('&') if value)) == proposed
                       for t in state.get('probe_traces', []) if isinstance(t, dict)):
                    require('request_already_probed',
                            'This payload set was already probed on the path; a different payload or a different '
                            'endpoint is eligible', 'novel_request')
            from src.adaptix.agents.progress import parameter_variation_no_gain
            if parameter_variation_no_gain(state, action):
                require('zero_information_gain',
                        'Measured information gain is zero: distinct values of this parameter already returned '
                        'identical responses with no signature, so varying it again adds nothing',
                        'novel_parameter')
        return missing

    if tool == 'static_discovery':
        # One bounded sweep per (origin, profile). A repeated sweep costs the same
        # requests for the same answer, so it is refused with the profiles that have
        # not been run yet, not with a generic denial.
        profile = str(action.get('profile') or 'common')
        done = set(state.get('static_swept') or [])
        if profile in done:
            from src.adaptix.tools.static_discovery import PROFILES
            remaining = sorted(set(PROFILES) - done)
            require('profile_already_swept',
                    f'Origin already swept with the {profile!r} wordlist profile; '
                    + (f'profiles not yet used here: {", ".join(remaining)}' if remaining
                       else 'every configured profile has been used on this origin'),
                    'unused_wordlist_profile')
        return missing

    if tool == 'web_discover':
        from src.adaptix.tools.web import document_probes as web_document_probes
        if all(probe in set(state.get('discovered_documents', []))
               for probe in web_document_probes(state, target)):
            require('documents_already_fetched',
                    'Web discovery already covered this document set; the stored web_routes are its result. A new '
                    'seed document or a direct request is eligible instead', 'new_seed_document')
        return missing

    if tool == 'api_discover':
        if is_destructive(target):
            require('destructive_path',
                    'This path names a state-changing administrative resource; a bounded read of it needs the same '
                    'exact human approval a mutation would', 'non_destructive_path')
        row = provenance.get(endpoint_key(target)) if endpoint_key(target) else None
        if row is None and target not in set(evidence.probes):
            # Missing evidence, not an unauthorized action: the tool may still be
            # used on any endpoint the application itself referenced.
            require('no_provenance',
                    'Endpoint has no observed provenance and is not a listed documentation probe: the URL appears in '
                    'no target, service, response, probe, discovered route or documented operation',
                    'endpoint_provenance')
        return missing

    return missing


def eligible_targets(state, tool, limit=8, evidence=None):
    """Inputs that currently satisfy ``tool``'s prerequisites, best evidenced first."""
    evidence = evidence or Evidence(state)
    if tool == 'browser_test':
        return []  # markers are model-authored payloads; static endpoint examples cannot carry them
    provenance = evidence.provenance
    rows = []
    for key in provenance:
        urls = provenance[key]['urls']
        row = provenance_row(provenance, urls[0] if urls else '')
        if row and permitted(state, row['url']):
            rows.append(row)
    # Examples are ranked by what they teach the planner: an application route the
    # application itself references beats another copy of the site root, and among
    # API-like routes one carrying an input surface (query parameters the JS
    # references, or an attached form) is a stateful probe rather than another
    # parameterless fetch of a page whose response is already stored.
    rows.sort(key=lambda row: (not _api_like(row), not _has_inputs(row), row['url']))
    from src.adaptix.agents.action_identity import already_completed
    candidates = []
    for row in rows:
        action = {'tool': tool, 'target': row['url'], 'method': 'GET'}
        if tool == 'api_discover' and is_destructive(row['url']):
            continue
        if already_completed(action, state):
            # Never advertise an input whose result is already stored: that is what
            # makes a model keep choosing the one action that will be refused.
            continue
        if not missing_prerequisites(state, action, evidence):
            candidates.append(row)
        if len(candidates) >= limit:
            break
    if tool == 'api_discover':
        for probe in evidence.probes:
            if len(candidates) >= limit:
                break
            if not missing_prerequisites(state, {'tool': tool, 'target': probe, 'method': 'GET'}, evidence):
                candidates.append(provenance_row(provenance, probe)
                                  or {'url': probe, 'sources': ['document_probe'], 'kinds': ['document_probe'],
                                      'http_validated': False, 'status_codes': [], 'methods': ['GET'],
                                      'references': 0})
    return candidates


def _api_like(row):
    return any(str(k).lower() in ('xhr', 'fetch', 'api', 'script_route') for k in row.get('kinds', []))


def _has_inputs(row):
    return '?' in row['url'] or any(str(k).lower() == 'form' for k in row.get('kinds', []))


def _tool_inputs(tool, state=None):
    """Input affordances the runtime tool contract actually supports, not tactics.

    These are re-read from the runtime schema and tool module on every call, so the
    contract never drifts from what dispatch can execute. Tactics - which URL to
    hit, which body value to send - are deliberately absent: they belong to the
    model, and no list of them lives here. Identity names are the one exception:
    selecting *which* operator-configured session to send is an input decision the
    model legitimately makes; the credential values behind a name stay hidden.
    """
    try:
        if tool == 'static_discovery':
            from src.adaptix.tools.static_discovery import PROFILES, DEFAULT_PROFILE
            return {'supports': 'one bounded wordlist sweep over the origin supplied as target',
                    'profiles': sorted(PROFILES),
                    'default_profile': DEFAULT_PROFILE,
                    'profile_field': 'profile',
                    'behavior': ('every matching path becomes an observed web_route; a match means the '
                                 'path answered, never that it is vulnerable. One sweep per profile per origin'),
                    'hypothesis_field': 'category the action tests, if any'}
        if tool == 'browser_test':
            return {'supports': 'one payload navigation + one control navigation (target url carrying your marker; marker 6-64 chars [A-Za-z0-9_.-] inside the url)',
                    'marker_field': 'marker',
                    'behavior': 'dialogs are captured and dismissed; nothing is clicked; the payload/control dialog comparison is signed as the browser_execution proof',
                    'hypothesis_field': 'category the action tests; declare it when the evidence suggests a class'}
        if tool == 'http_request':
            from src.adaptix.tools.web import MUTATING_METHODS, SAFE_METHODS
            from src.adaptix.agents.schema import Action
            properties = Action.model_json_schema().get('properties', {})
            body_schema = (properties.get('body') or {}).get('anyOf', [{}])[0]
            body_cap = body_schema.get('maxLength')
            context = (state or {}).get('identity_context') or {}
            names = sorted({row.get('name') for row in (context.get('identities') or [])
                            if isinstance(row, dict) and row.get('name')})
            inputs = {'supports': 'one bounded request (url, query on the url, optional request body)',
                      'methods_without_approval': list(SAFE_METHODS),
                      'methods_with_human_approval': list(MUTATING_METHODS),
                      'body_max_chars': body_cap,
                      'hypothesis_field': 'category the action tests; declare it when the evidence suggests a class',
                      'headers_field': 'model headers (up to 4, e.g. Content-Type); transport/identity headers are not yours',
                      'controls': 'detection-bearing probes get a runtime-issued clean control'}
            if names:
                inputs['identity_names'] = names[:8]
                inputs['identity_field'] = ('name of an operator-configured identity; its headers arrive from '
                                            "operator configuration - the model sends only the name, and only "
                                            'on non-destructive methods')
            return inputs
    except (ImportError, AttributeError, KeyError, ValueError, IndexError, TypeError):
        return None
    return None


def named_tool_targets(state, tool):
    """Executable scenario names a configured named tool is actually ready to run.

    Named tools take an operator- or evidence-derived scenario name, not an endpoint,
    so a URL-driven target scan never surfaces them. Each row pairs the executable
    name with the endpoint the scenario names (its ``base_url``), so an alternative
    can be linked to the hypothesis about that same path.
    """
    rows = []
    if tool == 'scenario':
        from src.adaptix.tools.discovery import derive_candidates
        rows = [{'name': row['name'], 'url': row.get('url')} for row in derive_candidates(state)]
    elif tool == 'idor':
        rows = [{'name': row.get('name'), 'url': row.get('base_url')}
                for row in state.get('idor_scenarios', []) if row.get('name')]
    return [row for row in rows
            if not missing_prerequisites(state, {'tool': tool, 'target': row['name'], 'method': 'GET'})]


def capability_contract(state, tools, limit=4):
    """Per-tool capability summary for the planner: prerequisites, counts, examples.

    The planner receives this before choosing a tool, so it can pick a tool whose
    inputs the run actually holds instead of guessing. The rendering is deliberately
    terse: a long capability report costs context and, more importantly, gets
    truncated into something that contradicts the feedback it is paired with.
    """
    evidence = Evidence(state)
    contract = {}
    for tool in sorted(tools):
        declared = TOOL_REQUIREMENTS.get(tool, {})
        named = named_tool_targets(state, tool) if tool in NAMED_TOOLS else []
        if named:
            contract[tool] = {'requires': list(declared.get('requires', [])),
                              'eligible': len(named),
                              'targets': [row['name'] for row in named[:limit]]}
        else:
            targets = [] if tool in NAMED_TOOLS else eligible_targets(state, tool, limit=limit, evidence=evidence)
            row = {'requires': list(declared.get('requires', []))}
            if targets:
                row['eligible'] = len(targets)
                row['targets'] = [item['url'] for item in targets[:2]]
            else:
                codes = sorted({code for code in _missing_codes(state, tool, evidence)})
                row['eligible'] = 0
                row['missing'] = codes[:3] or ['no_observed_input']
            contract[tool] = row
        inputs = _tool_inputs(tool, state)
        if inputs:
            contract[tool]['inputs'] = inputs
    return contract


def _missing_codes(state, tool, evidence=None):
    """Which prerequisites currently block ``tool`` anywhere in the observed inputs."""
    evidence = evidence or Evidence(state)
    if tool in NAMED_TOOLS:
        from src.adaptix.tools.discovery import derive_candidates
        if tool == 'scenario':
            names = sorted({row['name'] for row in derive_candidates(state)})[:16]
        else:
            names = sorted({row.get('name') for row in state.get('idor_scenarios', []) if row.get('name')})[:16]
        if not names:
            yield 'no_' + ('scenario_candidate' if tool == 'scenario' else 'validated_scenario')
        for name in names:
            for item in missing_prerequisites(state, {'tool': tool, 'target': name}, evidence):
                yield item['code']
        return
    provenance = evidence.provenance
    probes = evidence.probes if tool == 'api_discover' else []
    urls = [row['urls'][0] for row in provenance.values() if row['urls']][:32] + probes[:8]
    for url in urls:
        for item in missing_prerequisites(state, {'tool': tool, 'target': url, 'method': 'GET'}, evidence):
            yield item['code']
    if not urls:
        yield 'no_observed_input'


# Declared contract, not a strategy: what each tool consumes and which prerequisites
# must hold before it can run. Nothing here says which tool to prefer or what to test.
TOOL_REQUIREMENTS = {
    'nmap': {'takes': 'host', 'requires': ['in_scope_host'],
             'purpose': 'Service inventory for one pinned host.'},
    'httpx': {'takes': 'url', 'requires': ['in_scope_url', 'observed_or_discovered_endpoint'],
              'purpose': 'One HTTP observation with technology and title metadata.'},
    'playwright': {'takes': 'url', 'requires': ['in_scope_url'],
                   'purpose': 'Rendered page observation, screenshot and discovered XHR/fetch routes.'},
    'browser_test': {'takes': 'url', 'requires': ['in_scope_url', 'marker_in_url'],
                     'purpose': 'Deterministic browser-execution proof for a candidate XSS surface: the URL carries the run marker, the payload and marker-stripped control navigations are compared by captured dialogs.'},
    'web_discover': {'takes': 'seed_document_url', 'requires': ['in_scope_url', 'undiscovered_seed_document'],
                     'purpose': 'Retrieve a seed document plus robots/sitemap and extract in-scope routes and forms.'},
    'static_discovery': {'takes': 'origin_url', 'requires': ['in_scope_url', 'unused_wordlist_profile'],
                         'purpose': ('Wordlist sweep of one origin (ffuf). Finds paths the application never '
                                     'links to - admin panels, backups, API prefixes, upload dirs. A match is an '
                                     'observed route, never a finding.')},
    'http_request': {'takes': 'url_or_seed_url', 'requires': ['in_scope_url', 'novel_request'],
                     'purpose': 'One bounded request reduced to a comparable response trace with deterministic signatures.'},
    'nuclei': {'takes': 'url', 'requires': ['in_scope_url', 'template_policy'],
               'purpose': 'Run the configured template policy and record unverified matches.'},
    'api_discover': {'takes': 'url', 'requires': ['endpoint_provenance_or_documented_probe'],
                     'purpose': 'Retrieve one documented or discovered JSON resource and record its structure.'},
    'scenario': {'takes': 'scenario_candidate_name', 'requires': ['observed_scenario_candidate', 'two_identities', 'private_field_policy'],
                 'purpose': 'Validate two supplied sessions and observed object ownership.'},
    'idor': {'takes': 'idor_scenario_name', 'requires': ['validated_scenario'],
             'purpose': 'Execute one validated scenario once and compare both identities.'},
}