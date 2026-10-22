"""Rank feasible model-generated actions using utility, cost and observed feedback."""
import json
import math
from src.adaptix.workflow.budget import remaining_seconds

MAX_ESTIMATED_TOKENS = 2_000_000
MAX_ESTIMATED_SECONDS = 3_600.0
MAX_ESTIMATED_REQUESTS = 1_000
SCORE_FIELDS = ('goal_relevance', 'information_gain', 'evidence_value', 'confidence')
COST_FIELDS = {'estimated_tokens': MAX_ESTIMATED_TOKENS,
               'estimated_seconds': MAX_ESTIMATED_SECONDS,
               'estimated_requests': MAX_ESTIMATED_REQUESTS}


def nuclei_seconds_floor(state):
    """Honest wall-clock lower bound for a nuclei action from recorded facts.

    The engine's approved manifest is the runtime's own data: the last template
    selection row states how many templates the exact scan executes. At the
    configured request rate the scan cannot finish faster than manifest/rate, so
    the model's guess about scanning cost is replaced by a fact floor where one
    exists. A scan that does not fit the remaining time is then DEFERRED with a
    named alternative instead of executing past the deadline, which is what
    consumed an entire short run before any input testing could start.
    """
    rows = [row for row in (state.get('nuclei_template_selections') or []) if isinstance(row, dict)]
    if not rows:
        return 0.0
    executed = max(int(row.get('executable_count') or 0) for row in rows[-2:])
    if executed <= 0:
        return 0.0
    from src.adaptix.config import config
    limits = config('scope.yaml')['limits']
    rate = max(1, int(limits.get('rate_per_second', 2)))
    room = int(limits.get('concurrent_requests', 10)) * 5 + 25
    return executed / rate + room



def bounded_score(value):
    """Return a finite 0..1 score, or None when the model supplied garbage."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and 0.0 <= number <= 1.0 else None


def bounded_cost(value, maximum):
    """Return a finite positive cost within the allowed bound, or None."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and 0.0 < number <= maximum else None


def rank_actions(state, actions, budget):
    profiles = state.get('tool_profiles', {})
    # A None cumulative budget is unlimited: it removes that comparison rather
    # than becoming a fake large number, while usage stays metered.
    left_tokens = None if budget.get('token_limit') is None else budget['token_limit'] - budget['tokens']
    left_calls = None if budget.get('tool_call_limit') is None else budget['tool_call_limit'] - budget['tool_calls']
    left_time = remaining_seconds(state)
    overhead = int(state.get('planner_metrics', {}).get('last_prompt_tokens', 0)) + int(state.get('planner_metrics', {}).get('last_completion_tokens', 0))
    ranked, deferred = [], []
    for action in actions:
        priority = dict(action.get('priority') or {})
        scores = {key: bounded_score(priority.get(key)) for key in SCORE_FIELDS}
        if any(value is None for value in scores.values()):
            deferred.append({'action': action,
                             'reason': 'Priority scores must be finite numbers within 0.0 to 1.0; correct the value and re-plan'})
            continue
        costs = {key: bounded_cost(priority.get(key), maximum) for key, maximum in COST_FIELDS.items()}
        if any(value is None for value in costs.values()):
            deferred.append({'action': action,
                             'reason': 'Estimated resources must be finite positive values within bounds '
                                       f'(tokens 1-{MAX_ESTIMATED_TOKENS}, seconds >0-{int(MAX_ESTIMATED_SECONDS)}, '
                                       f'requests 1-{MAX_ESTIMATED_REQUESTS}); correct the value and re-plan'})
            continue
        priority.update(scores)
        profile = profiles.get(action['tool'], {})
        tokens = overhead + max(int(costs['estimated_tokens']), int(profile.get('mean_context_tokens', 0)))
        seconds = max(costs['estimated_seconds'], float(profile.get('mean_seconds', 0)))
        scan_floor = nuclei_seconds_floor(state) if action['tool'] == 'nuclei' else 0.0
        seconds = max(seconds, scan_floor)
        min_calls = {'idor': 2, 'scenario': 3}.get(action['tool'], 1)
        requests = max(int(costs['estimated_requests']), min_calls)
        if ((left_tokens is not None and tokens > left_tokens)
                or (left_time is not None and seconds > left_time)
                or (left_calls is not None and min_calls > left_calls)):
            if scan_floor > 0 and seconds >= scan_floor > left_time:
                from src.adaptix.config import config as _config
                limits = _config('scope.yaml')['limits']
                templates = int(max(0, scan_floor - (int(limits.get('concurrent_requests', 10)) * 5 + 25))) \
                    * max(1, int(limits.get('rate_per_second', 2)))
                deferred.append({'action': action,
                                 'reason': f'The recorded manifest executes {templates} templates and needs about '
                                           f'{int(scan_floor)} seconds at the configured rate; propose a smaller template '
                                           'set or request-level checks that fit the remaining time'})
            else:
                deferred.append({'action': action, 'reason': 'Estimated cost does not fit remaining token/time/tool-call budget'})
            continue
        benefit = (0.4 * priority['goal_relevance'] + 0.3 * priority['information_gain'] + 0.3 * priority['evidence_value'])
        calibration = 0.25 + 0.75 * float(profile.get('mean_goal_progress', profile.get('productive_fraction', 1)))
        benefit *= priority['confidence'] * calibration
        if benefit <= 0:
            deferred.append({'action': action, 'reason': 'No positive expected utility; propose a useful alternative or stop'})
            continue
        utility_per_token = 1000 * benefit / max(1, tokens)
        pressure = 1 + .25 * seconds / max(.001, left_time) + .15 * requests / max(1, max(requests, left_calls) if left_calls is not None else requests)
        priority.update(score=round(utility_per_token / pressure, 6), expected_progress_per_1000_tokens=round(utility_per_token, 6), effective_tokens=tokens,
                        effective_seconds=seconds, effective_requests=requests,
                        expected_benefit=round(benefit, 6))
        ranked.append({**action, 'priority': priority})
    ranked.sort(key=lambda a: -a['priority']['score'])
    for rank, action in enumerate(ranked, 1):
        action['priority']['rank'] = rank
    return ranked, deferred


def observation_facts(state):
    fields = ('services', 'http_services', 'candidates', 'browser_evidence', 'idor_findings', 'verification_evidence', 'api_observations', 'scenario_validations', 'web_routes', 'probe_traces')
    facts = set()
    volatile = {'timestamp', 'evidence_id', 'evidence_ref', 'screenshot'}
    for field in fields:
        for item in state.get(field, []):
            stable = {k: v for k, v in item.items() if k not in volatile}
            facts.add(field + ':' + json.dumps(stable, sort_keys=True, default=str))
    return facts


def record_outcome(state, before, result, action, seconds):
    after = {**state, **result}
    new_facts = observation_facts(after) - before
    from src.adaptix.agents.evidence_context import marginal_tokens, evidence_key, FIELDS
    from src.adaptix.agents.progress import progress_assessment
    context_tokens, measurement = marginal_tokens(state, result)
    progress = progress_assessment(state, result)
    profiles = {k: dict(v) for k, v in state.get('tool_profiles', {}).items()}
    old = profiles.get(action['tool'], {})
    count = int(old.get('samples', 0))
    failed = len(result.get('errors', [])) > len(state.get('errors', []))
    productive = progress['goal_progress']
    def mean(key, value): return (float(old.get(key, 0)) * count + value) / (count + 1)
    profiles[action['tool']] = {'samples': count + 1, 'mean_seconds': mean('mean_seconds', seconds),
        'mean_context_tokens': mean('mean_context_tokens', context_tokens),
        'productive_fraction': mean('productive_fraction', productive),
        'mean_goal_progress': mean('mean_goal_progress', productive), 'objective_kind': progress['objective_kind']}
    outcome = {'action': action, 'seconds': round(seconds, 4), 'new_facts': len(new_facts),
               'context_tokens_estimate': context_tokens, 'context_token_measurement': measurement,
               'failed': failed, **progress,
               'new_evidence_keys': [evidence_key(kind, row) for kind in FIELDS for row in result.get(kind, [])
                                     if evidence_key(kind, row) not in {evidence_key(kind, old) for old in state.get(kind, [])}]}
    return profiles, outcome
