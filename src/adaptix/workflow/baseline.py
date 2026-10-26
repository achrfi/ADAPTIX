"""Deterministic baseline reconnaissance: bounded discovery with no model in the loop.

The phase prepares structured reconnaissance evidence before the first
vulnerability-testing model decision. It is target-aware (explicit HTTP URL vs
authorized host/network scope), capability-aware (tools must be registered,
enabled and installed), scope-aware (every request passes the pinned-scope
adapters' own checks) and budget-aware (phase-local caps plus the shared run
budget). It never changes application state, never follows redirects and never
fabricates a successful scan: unavailable tools and skipped work are recorded as
limitations. All strategy after the baseline stays with the model.
"""
import time
from collections import Counter
from src.adaptix.config import config
from src.adaptix.processing.normalize import deduplicate
from src.adaptix.tools.registry import tool_registry
from src.adaptix.tools.web import web_discover
from src.adaptix.tools.discovery import api_discover, collection_index, discovery_targets
from src.adaptix.tools.static_discovery import static_discovery
from src.adaptix.processing.observations import observation_processing
from src.adaptix.agents.evidence_context import evidence_key
from src.adaptix.workflow.budget import remaining_seconds
from src.adaptix.workflow.events import log

HTTP_PORTS = {80, 443, 3000, 8000, 8080, 18080, 8443, 9443}


def baseline_settings():
    """Validated baseline policy; an invalid operator config fails loudly."""
    raw = config('baseline.yaml').get('baseline_reconnaissance') or {}
    errors = []
    extras = set(raw) - {'enabled', 'max_seconds', 'max_tool_calls', 'max_hosts',
                         'max_web_origins', 'api_document_probes', 'max_web_routes',
                         'adaptive_tool_call_reserve', 'fallback_when_tool_missing'}
    if extras:
        errors.append('unknown baseline settings: ' + ', '.join(sorted(extras)))
    if not isinstance(raw.get('enabled', False), bool):
        errors.append('enabled must be a boolean')
    values = {}
    for name in ('max_seconds', 'max_tool_calls', 'max_hosts', 'max_web_origins',
                 'api_document_probes', 'max_web_routes', 'adaptive_tool_call_reserve'):
        value = raw.get(name, 0 if name == 'adaptive_tool_call_reserve' else None)
        if not isinstance(value, int) or isinstance(value, bool) or value < (0 if name == 'adaptive_tool_call_reserve' else 1):
            errors.append(f'{name} must be a {"non-negative" if name == "adaptive_tool_call_reserve" else "positive"} integer')
        else:
            values[name] = value
    if str(raw.get('fallback_when_tool_missing', 'record_limitation')) != 'record_limitation':
        errors.append('fallback_when_tool_missing only supports record_limitation')
    if errors:
        raise ValueError('Invalid baseline.yaml: ' + '; '.join(errors))
    return {'enabled': bool(raw.get('enabled')), **values,
            'fallback_when_tool_missing': 'record_limitation'}


def static_settings():
    """Static content discovery policy (ffuf), validated like every other phase."""
    raw = config('baseline.yaml').get('static_discovery') or {}
    errors = []
    extras = set(raw) - {'enabled', 'profile', 'max_seconds', 'max_profiles'}
    if extras:
        errors.append('unknown static_discovery settings: ' + ', '.join(sorted(extras)))
    if not isinstance(raw.get('enabled', True), bool):
        errors.append('static_discovery.enabled must be a boolean')
    values = {}
    for name, minimum in (('max_seconds', 1), ('max_profiles', 0)):
        value = raw.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
            errors.append(f'static_discovery.{name} must be an integer >= {minimum}')
        else:
            values[name] = value
    from src.adaptix.tools.static_discovery import PROFILES, DEFAULT_PROFILE
    profile = str(raw.get('profile') or DEFAULT_PROFILE)
    if profile not in PROFILES:
        errors.append(f'static_discovery.profile must be one of {", ".join(sorted(PROFILES))}')
    if errors:
        raise ValueError('Invalid baseline.yaml: ' + '; '.join(errors))
    return {'enabled': bool(raw.get('enabled', True)), 'profile': profile, **values}


def phase_used_calls(state, metrics):
    """Tool calls consumed by this phase so far (metrics carry the shared counter)."""
    return int((metrics or {}).get('tool_calls_used', 0)) - int(state.get('execution_metrics', {}).get('tool_calls_used', 0))


def run_deadline_reached(state):
    from src.adaptix.workflow.budget import remaining_seconds
    return remaining_seconds(state) <= 0


def _stop_reason(state, metrics, settings, deadline):
    """Why the phase had to stop. Returns None while work may continue."""
    used = phase_used_calls(state, metrics)
    # The adaptive loop keeps a protected reserve of the run's tool budget: the
    # baseline may fill its own cap but never spend the calls the model-planned
    # phase needs to act on what the baseline discovered.
    reserve = max(0, int(settings.get('adaptive_tool_call_reserve', 0)))
    from src.adaptix.workflow.budget import budget_limit, DEFAULT_TOOL_CALL_BUDGET
    tool_limit = budget_limit(state, 'tool_call_budget', DEFAULT_TOOL_CALL_BUDGET)
    # An unlimited tool-call budget removes only the run's ceiling; the phase
    # cap (max_tool_calls) remains as the phase's own bounded configuration.
    cap = (int(settings['max_tool_calls']) if tool_limit is None
           else min(int(settings['max_tool_calls']), max(0, tool_limit - reserve)))
    if used >= cap:
        return ('adaptive_reserve_protected'
                if tool_limit is not None and cap < int(settings['max_tool_calls'])
                else 'phase_tool_call_limit')
    budget_used = int((metrics or {}).get('tool_calls_used', 0))
    run_tool_limit = budget_limit(state, 'tool_call_budget', DEFAULT_TOOL_CALL_BUDGET)
    if run_tool_limit is not None and budget_used >= run_tool_limit:
        return 'run_tool_call_budget'
    if run_deadline_reached(state) or time.monotonic() >= deadline:
        return 'phase_time_limit' if time.monotonic() >= deadline else 'run_time_budget'
    return None


def _probe_slots_free(state, metrics, settings, remaining):
    """Whether the reserved class-probe calls still fit under the phase cap."""
    from src.adaptix.workflow.budget import budget_limit, DEFAULT_TOOL_CALL_BUDGET
    used = phase_used_calls(state, metrics)
    reserve = max(0, int(settings.get('adaptive_tool_call_reserve', 0)))
    tool_limit = budget_limit(state, 'tool_call_budget', DEFAULT_TOOL_CALL_BUDGET)
    cap = (int(settings['max_tool_calls']) if tool_limit is None
           else min(int(settings['max_tool_calls']), max(0, tool_limit - reserve)))
    return used + remaining <= cap


# Keys a phase contributes to cumulatively. Tool results and probe results carry
# only their own additions, so replacement would silently drop prior evidence.
# `verified_findings` is accumulated for the same reason as the rest: a capability that
# proves a record while the run is still going (the extraction writes its proven-impact
# finding here) had its write replaced by the next tool result, so the proof vanished from
# the report even though it had been executed.
ACCUMULATING = ('verification_evidence', 'injection_findings', 'script_findings',
                'idor_findings', 'verified_findings')


def _merge(working, update):
    """Thread one tool result through the working state (metrics come threaded).

    Accumulating keys are appended, never replaced: a probe returns only the records
    it signed, so overwriting `verification_evidence` meant each deterministic check
    erased the previous one's proof and the report saw a single class at most.
    """
    for key, value in (update or {}).items():
        if key in ACCUMULATING and isinstance(value, list) and isinstance(working.get(key), list):
            working[key] = working[key] + value
        else:
            working[key] = value
    return working


def _http_seeds(services, settings):
    """Candidate HTTP origins built only from the observed service inventory.

    A nmap service that names HTTP, or an open port on the run's HTTP port set,
    becomes the only seed candidate; nothing outside the observed inventory is
    ever assumed or invented.
    """
    seeds = []
    for svc in services if isinstance(services, list) else []:
        if not isinstance(svc, dict) or svc.get('status') not in (None, 'open'):
            continue
        port = int(svc.get('port', 0) or 0)
        if 'http' not in str(svc.get('service', '')).lower() and port not in HTTP_PORTS:
            continue
        host = svc.get('host')
        if not host:
            continue
        hostname = f'[{host}]' if ':' in host and not host.startswith('[') else host
        scheme = 'https' if port in (443, 8443, 9443) or svc.get('tunnel') == 'ssl' else 'http'
        seed = f'{scheme}://{hostname}:{port}'
        if seed not in seeds:
            seeds.append(seed)
    return seeds[:settings['max_web_origins']]


def _discover_origin(state, seed, settings, deadline, skipped):
    """web discovery, bounded documentation probes and one static sweep per origin."""
    working = dict(state)
    steps = []
    # Static content discovery runs FIRST on the origin. It is the only pass that
    # finds paths the application never links to, and it was previously scheduled
    # last - so on every run the baseline spent its whole tool-call cap on crawl and
    # document probes and the sweep never executed at all. The crawl then runs over
    # the union of what it finds and what the sweep discovered, which makes the
    # crawl's own budget go further.
    working['planned_actions'] = [{'tool': 'web_discover', 'target': seed}]
    working = _merge(working, web_discover(working))
    steps.append({'tool': 'web_discover', 'target': seed, 'routes': len(working.get('web_routes', []))})
    # Documentation probes only fetch endpoints discovery itself surfaced
    # (including conventional document paths it proposed), never invented paths.
    probed = set(working.get('discovered_documents', []))
    for document in [u for u in discovery_targets(working) if u not in probed][:settings['api_document_probes']]:
        reason = _stop_reason(state, working.get('execution_metrics', {}), settings, deadline)
        if reason:
            skipped.append(reason)
            break
        working['planned_actions'] = [{'tool': 'api_discover', 'target': document}]
        working = _merge(working, api_discover(working))
        steps.append({'tool': 'api_discover', 'target': document})
        # Object-level authorization needs the collection rows that prove ownership
        # alongside the documented detail endpoint. Deriving candidates only from what
        # the model happened to request left whole runs at `scenario_candidates: 0`
        # while the collection was one deterministic, in-scope, read-only GET away.
        # It is fetched here, immediately after the document that documents it, so a
        # later document probe cannot exhaust the phase budget first.
        for collection in collection_index(working):
            if collection in probed or any(s.get('target') == collection for s in steps):
                continue
            reason = _stop_reason(state, working.get('execution_metrics', {}), settings, deadline)
            if reason:
                skipped.append(reason)
                break
            working['planned_actions'] = [{'tool': 'api_discover', 'target': collection}]
            working = _merge(working, api_discover(working))
            steps.append({'tool': 'api_discover', 'target': collection, 'purpose': 'collection_rows'})
    # Object-level authorization is decided by two identities on a route discovery already
    # observed. It used to require an OpenAPI entry declaring `security`, so an application
    # with no specification produced `scenario_candidates: 0` while its basket and user
    # routes were plainly cross-readable. This runs after the observations exist and
    # before the sweep, and signs nothing unless the contract is satisfied.
    # Deterministic class checks. The model could not schedule these on an application
    # without a specification, and each check signs its own record through a replay
    # contract, so a suspicion never becomes a finding.
    from src.adaptix.tools.vuln_probes import authorization_probe, injection_probe, script_probe
    probes = (('injection_probe', injection_probe, 'injection_findings'),
              ('authorization_probe', authorization_probe, 'idor_findings'),
              ('script_probe', script_probe, 'script_findings'))
    # Their slots are reserved out of the phase cap, not borrowed from it: with the cap
    # already consumed by discovery these three never executed and the run reported
    # zero for every class they cover.
    probe_slots = len(probes)
    for tool_name, probe, finding_key in probes:
        reason = _stop_reason(state, working.get('execution_metrics', {}), settings, deadline)
        if reason and not _probe_slots_free(state, working.get('execution_metrics', {}), settings, probe_slots):
            skipped.append(reason)
            break
        working['planned_actions'] = [{'tool': tool_name, 'target': seed}]
        from src.adaptix.agents.priority import observation_facts
        before_facts = observation_facts(working)
        started_at = time.monotonic()
        outcome = probe(working)
        working = _merge(working, outcome)
        probe_slots -= 1
        confirmed = len(working.get(finding_key) or [])
        steps.append({'tool': tool_name, 'target': seed, 'confirmed': confirmed})
        from src.adaptix.agents.priority import observation_facts, record_outcome
        _, outcome = record_outcome(working, before_facts, outcome,
                                    {'tool': tool_name, 'target': seed},
                                    time.monotonic() - started_at)
        working.setdefault('action_outcomes', []).append(outcome)
    # The sweep runs LAST on purpose: it is one tool call but consumes nearly the whole
    # phase wall-clock, so running it first starved the cheap document probes and the
    # collection fetch that object-level authorization needs. It keeps a reserved slot
    # so it still executes when the probes above used the phase's call cap.
    try:
        static = static_settings()
    except (ValueError, OSError, KeyError) as exc:
        skipped.append(f'static_discovery_misconfigured:{str(exc)[:60]}')
        static = {'enabled': False}
    if static.get('enabled', True):
        already = set(working.get('static_swept') or [])
        for profile in [static['profile']] if static.get('max_profiles', 1) else []:
            if profile in already:
                continue
            reason = _stop_reason(state, working.get('execution_metrics', {}), settings, deadline)
            if reason:
                skipped.append(reason)
                break
            working['planned_actions'] = [{'tool': 'static_discovery', 'target': seed,
                                           'profile': profile}]
            before = len(working.get('web_routes', []))
            working = _merge(working, static_discovery(working))
            step = {'tool': 'static_discovery', 'target': seed, 'profile': profile,
                    'routes': len(working.get('web_routes', [])) - before}
            if (working.get('static_discovery') or {}).get('skipped'):
                step['skipped'] = working['static_discovery']['skipped']
            steps.append(step)
    return working, steps


def baseline_reconnaissance(state):
    """One bounded, deterministic pass; success is recorded, never assumed.

    Nothing here requests model guidance. When the run has already completed its
    baseline (or the operator disabled it) the node is a no-op and replanning
    never repeats it.
    """
    if state.get('status') != 'scope_ok' or not state.get('authorization'):
        return {'events': log(state, 'Baseline Recon: skipped; scope not approved')}
    marker = state.get('baseline_recon') or {}
    if marker.get('completed'):
        return {'events': log(state, 'Baseline Recon: already completed; not repeating')}
    try:
        settings = baseline_settings()
    except (ValueError, OSError, KeyError) as exc:
        return {'baseline_recon': {'completed': True, 'mode': 'misconfigured'},
                'errors': list(state.get('errors', [])) + ['Baseline config invalid: ' + str(exc)[:160]],
                'events': log(state, f'Baseline Recon: misconfigured ({str(exc)[:80]})')}
    if not settings['enabled'] or state.get('baseline_disabled'):
        return {'baseline_recon': {'completed': True, 'mode': 'disabled'},
                'events': log(state, 'Baseline Recon: disabled by configuration')}
    if run_deadline_reached(state):
        return {'baseline_recon': {'completed': True, 'mode': 'skipped'},
                'baseline_metrics': {'limitations': ['run time budget exhausted before the baseline'],
                                     'steps': [], 'limitations_count': 1},
                'events': log(state, 'Baseline Recon: skipped; no run time remaining')}
    started = time.monotonic()
    deadline = started + min(float(settings['max_seconds']), max(0.0, remaining_seconds(state)))
    registry = tool_registry()
    limitations, skipped, steps = [], [], []
    errors = list(state.get('errors', []))
    # Events append to the run's history, never replace it: the scope-guard and
    # run-start events recorded before this phase must stay first in the run log.
    events = list(state.get('events', []))
    seen_events = set(events)

    def absorb(source):
        for row in source:
            if isinstance(row, str) and row not in seen_events:
                seen_events.add(row)
                events.append(row)

    working = {**state, 'planned_actions': []}
    targets = [state['target']] if isinstance(state.get('target'), str) else list(state.get('target', []))
    urls = [t for t in targets if isinstance(t, str) and '://' in t]
    mode = 'complete'
    seeds = []
    if urls:
        # An explicitly supplied HTTP URL defines the scope of interest: no port
        # scan, no unrelated host expansion.
        skipped.append('network_scan_skipped_for_explicit_url_scope')
        seeds = urls[:settings['max_web_origins']]
        if len(urls) > len(seeds):
            limitations.append(f'{len(urls) - len(seeds)} URL target(s) above the {settings["max_web_origins"]} origin cap')
    else:
        skipped.append('network_scan_retired')
        limitations.append('Network scanning retired; provide an explicit http:// or https:// target URL')
        mode = 'limited'
    for seed in seeds:
        reason = _stop_reason(state, working.get('execution_metrics', {}), settings, deadline)
        if reason:
            skipped.append(reason)
            break
        working, origin_steps = _discover_origin(working, seed, settings, deadline, skipped)
        steps.extend(origin_steps)
        absorb(working.get('events', []))
    routes = deduplicate('web_routes', list(working.get('web_routes', [])))
    if len(routes) > settings['max_web_routes']:
        limitations.append(f'route records capped at {settings["max_web_routes"]} of {len(routes)}')
    routes = routes[:settings['max_web_routes']]
    documents = list(dict.fromkeys(working.get('discovered_documents', [])))
    execution_metrics = working.get('execution_metrics', {})
    reason = _stop_reason(state, execution_metrics, settings, deadline)
    if reason and reason not in skipped:
        skipped.append(reason)
    stop = reason or 'complete'
    by_tool = Counter({tool: int(count) - int((state.get('execution_metrics', {}) or {}).get('by_tool', {}).get(tool, 0))
                       for tool, count in dict(execution_metrics.get('by_tool', {})).items() if count})
    baseline_metrics = {'seconds': round(time.monotonic() - started, 3),
                        'tool_calls': sum(by_tool.values()),
                        'tools_by_tool': dict(sorted(by_tool.items())),
                        'web_routes': len(routes), 'services': len(working.get('services', [])),
                        'documents_probed': len(documents), 'steps': steps,
                        'limitations': limitations, 'skipped': skipped, 'mode': mode,
                        'stop_reason': stop}
    events.append(f'Baseline Recon: {mode}; {baseline_metrics["tool_calls"]} tool calls, '
                  f'{len(routes)} routes, {len(documents)} documents probed'
                  + (f'; {len(limitations)} limitation(s)' if limitations else ''))
    update = {'baseline_recon': {'completed': True, 'mode': mode},
              'baseline_metrics': baseline_metrics,
              'web_routes': routes, 'services': working.get('services', []),
              'recon_inventory': working.get('recon_inventory', []),
              'discovered_documents': documents,
              'api_observations': working.get('api_observations', []),
              'api_operations': working.get('api_operations', []),
              'http_services': working.get('http_services', []),
              'discovery_limitations': working.get('discovery_limitations', []),
              # Deterministic class-check results travel with the phase that produced
              # them. They were absent from this projection, so a probe could sign a
              # record and reflection would still see zero findings.
              'action_outcomes': working.get('action_outcomes', []),
              'injection_findings': working.get('injection_findings', []),
              'script_findings': working.get('script_findings', []),
              'idor_findings': working.get('idor_findings', []),
              'verification_evidence': working.get('verification_evidence', []),
              'errors': errors,
              'execution_metrics': execution_metrics,
              'raw_bytes': working.get('raw_bytes', 0),
              'events': events}
    # Token-efficiency: apply the same deterministic dedupe/normalization and
    # structured-observation projection the adaptive loop uses, so the model never
    # sees raw tool output even on the pass immediately after the baseline.
    processed = observation_processing({**working, **update,
                                        'events': list(working.get('events', []))})
    for key, value in processed.items():
        if key == 'events':
            absorb(value)
        else:
            update[key] = value
    return update


def baseline_inventory(state, limit=8):
    """Compact token-bounded model view of what the deterministic baseline produced.

    Provenance stays authoritative in state: every route row already cites its
    source artifact. This projection never turns a discovered route into a claim
    that it is exploitable, and it never invents endpoint parameters.
    """
    marker = state.get('baseline_recon') or {}
    metrics = state.get('baseline_metrics') or {}
    routes = [row for row in state.get('web_routes', []) if isinstance(row, dict) and not row.get('static_asset')]
    # Entry points carry the same evidence_ref the validator computes over the
    # stored route row, so a reflection citing one resolves against web_routes.
    entry_points = [{'url': row['url'], 'method': str(row.get('method', 'GET')).upper(),
                     'evidence_ref': evidence_key('web_routes', row)}
                    for row in routes
                    if str(row.get('method', 'GET')).upper() in ('GET', 'HEAD')][:limit]
    kinds = Counter(str(row.get('kind')) for row in routes)
    return {'mode': marker.get('mode') or ('disabled' if state.get('baseline_disabled') else 'not_run'),
            'seconds': metrics.get('seconds'), 'tool_calls': metrics.get('tool_calls'),
            'stop_reason': metrics.get('stop_reason'),
            'route_kinds': dict(sorted(kinds.items())),
            'api_operations': len(state.get('api_operations', [])),
            'documents_probed': metrics.get('documents_probed'),
            'entry_points': entry_points,
            'services': [{'host': row.get('host'), 'port': row.get('port'), 'service': row.get('service')}
                         for row in state.get('services', []) if isinstance(row, dict)][:6],
            'coverage_limitations': list(metrics.get('limitations', []))[:4]}
