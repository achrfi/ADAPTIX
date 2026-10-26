"""Live view model for the ADAPTIX terminal UI.

Everything here is deterministic: token counts, findings and log lines are read out of
the run state that the workflow already produces, so the screen cannot disagree with the
report. No LLM call and no network access happens in this module.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, urlsplit

from src.adaptix.reporting.finding_ids import finding_ref


def _as_int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


@dataclass
class TokenMeter:
    """What the provider actually reported, per call and cumulative.

    ``charged`` is the reservation-or-actual figure the budget is debited by, so it is
    the honest "cost" number. ``out`` is completion tokens: the tokens the model
    generated, which is what an operator asks for first.
    """

    calls: int = 0
    provider_calls: int = 0
    cache_hits: int = 0
    failed_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    charged: int = 0
    last_prompt: int = 0
    last_completion: int = 0
    last_model: str = ''
    budget: int | None = None

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    @property
    def remaining(self) -> int | None:
        if self.budget is None:
            return None
        return max(0, self.budget - self.charged)

    @property
    def used_fraction(self) -> float:
        if not self.budget:
            return 0.0
        return min(1.0, self.charged / float(self.budget))

    def summary(self, width: int | None = None) -> str:
        """Tokens used, and nothing else.

        Measured: the line read ``out 0  in 0  total 0  calls 5  failed 5 | last out 0
        in 0 |`` on a run whose ledger plainly held 666,503 charged tokens - the per-call
        figures were absent on failed calls, so every field printed zero and the operator
        concluded the run had spent nothing. Report the one number that is always
        meaningful: the total the provider charged. Where the provider also reported the
        prompt/completion split, show it; never print a field that is merely unknown.
        """
        used = self.charged or self.total
        parts = [f'used {used:,}']
        if self.prompt_tokens or self.completion_tokens:
            parts.append(f'(in {self.prompt_tokens:,} / out {self.completion_tokens:,})')
        if self.budget:
            parts.append(f'of {self.budget:,}')
        text = '  '.join(parts)
        if width is not None and len(text) + 9 > width:
            text = f'used {used:,}'
        return text

    def bar(self, width: int = 28) -> str:
        """A budget bar in text, so it renders on any terminal."""
        filled = int(round(self.used_fraction * width))
        return '[' + '#' * filled + '-' * (width - filled) + ']'


def read_tokens(state) -> TokenMeter:
    """Derive the meter from a run state snapshot or a final report."""
    state = state or {}
    ledger = [row for row in (state.get('token_ledger') or []) if isinstance(row, dict)]
    metrics = state.get('planner_metrics') or {}
    meter = TokenMeter(budget=(None if state.get('token_budget') is None
                               else _as_int(state.get('token_budget'))))
    for row in ledger:
        meter.calls += 1
        if row.get('source') == 'cache' or not row.get('provider_call'):
            meter.cache_hits += 1
        else:
            meter.provider_calls += 1
        if row.get('result') in ('failed', 'reasoning_starvation') or row.get('error_type'):
            meter.failed_calls += 1
        meter.charged += _as_int(row.get('tokens_charged'))
        meter.prompt_tokens += _as_int(row.get('prompt_tokens'))
        meter.completion_tokens += _as_int(row.get('completion_tokens'))
        if row.get('prompt_tokens') is not None or row.get('completion_tokens') is not None:
            meter.last_prompt = _as_int(row.get('prompt_tokens'))
            meter.last_completion = _as_int(row.get('completion_tokens'))
            meter.last_model = str(row.get('model') or meter.last_model)
    if not ledger:
        # A run before its first pass has only metrics; use them rather than showing 0.
        meter.prompt_tokens = _as_int(metrics.get('last_prompt_tokens'))
        meter.completion_tokens = _as_int(metrics.get('last_completion_tokens'))
        meter.last_prompt = meter.prompt_tokens
        meter.last_completion = meter.completion_tokens
        meter.charged = _as_int(metrics.get('tokens_used'))
        meter.provider_calls = _as_int(metrics.get('llm_calls'))
        meter.calls = meter.provider_calls
    return meter


_BASIS_CLASSES = {
    'differential_injection': 'sql_injection',
    'boolean_injection': 'sql_injection',
    'browser_execution': 'cross_site_scripting',
    'private_object_access': 'broken_object_level_authorization',
    'nuclei_template_match': 'potential_vulnerability',
}

def _finding_class(row):
    value = (row.get('class') or row.get('finding_type') or row.get('category')
             or _BASIS_CLASSES.get(str(row.get('verification_basis') or ''), ''))
    return str(value or '').strip().lower()

def finding_rows(state, include_unverified=True) -> list[dict]:
    """Every proven finding in the snapshot, deduplicated the way the report dedupes.

    The report keys a finding on (path, parameter, class); the live view must use the
    same rule or the number on screen will not match the number in the deliverable.
    ``include_unverified`` is true while a run is live, so a scanner match or an
    inconclusive candidate can seed the operator's attention. The final report view
    passes false: at the end only evidence that met the verification contract is shown.
    """
    state = state or {}
    rows = []
    for key in ('findings', 'verified_findings', 'scanner_matched_findings'):
        for row in state.get(key) or []:
            if isinstance(row, dict):
                rows.append(row)
    for key in ('injection_findings', 'idor_findings', 'script_findings'):
        for row in state.get(key) or []:
            if isinstance(row, dict):
                rows.append(row)
    if not include_unverified:
        unverified = {'scanner_matched', 'inconclusive', 'rejected', 'false_positive',
                      'candidate', 'unverified'}
        rows = [row for row in rows
                if str(row.get('verification_status') or '').lower() not in unverified]
    # The report keys a finding on (path, parameter, class) and keeps the strongest
    # record. Measured: without the same rule the screen listed the extraction as
    # `critical` and the boolean proof of the same hole as `high` - two rows for one
    # vulnerability, and the count disagreed with the deliverable.
    rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    merged = {}
    order = []
    for row in rows:
        target = str(row.get('target') or row.get('url') or '')
        path = target.split('?')[0]
        parameter = str(row.get('parameter') or '').lower()
        if not parameter and '?' in target:
            parameter = ','.join(name for name, _value in
                                 parse_qsl(urlsplit(target).query, keep_blank_values=True))
        # Probe buckets such as injection_findings/script_findings carry proof but
        # no class or severity. Without deriving their class they became separate
        # rows headed "?" beside the report's canonical row, so the live screen
        # showed five findings for the three the deliverable contained.
        category = _finding_class(row)
        if category and not row.get('class'):
            row = {**row, 'class': category}
        identity = (path, parameter, category)
        previous = merged.get(identity)
        if previous is None:
            merged[identity] = dict(row)
            order.append(identity)
            continue
        best = merged[identity]
        # A proven-impact record wins outright; otherwise severity decides.
        if row.get('impact_proven') and not best.get('impact_proven'):
            merged[identity] = {**best, **row}
        elif rank.get(str(row.get('severity')), -1) > rank.get(str(best.get('severity')), -1):
            merged[identity] = {**best, **row}
        else:
            for key, value in row.items():
                best.setdefault(key, value)
    return [merged[identity] for identity in order]


def _has_query_or_fragment(url):
    parsed = urlsplit(str(url or ''))
    return bool(parsed.query or parsed.fragment)


def _payload_from_url(url, parameter=''):
    parsed = urlsplit(str(url or ''))
    query = parsed.query or parsed.fragment.partition('?')[2]
    pairs = parse_qsl(query, keep_blank_values=True)
    for name, value in pairs:
        if not parameter or str(parameter) == name:
            return value
    return pairs[0][1] if pairs else ''


def _url_with_payload(target, parameter, payload):
    target = str(target or '')
    if not target or not parameter or not payload or '?' in target:
        return target
    return '%s?%s=%s' % (target.split('#', 1)[0], parameter,
                         quote(str(payload), safe=',()/*-'))


def finding_detail(row, explanations=None) -> dict:
    """The five things an operator needs to act on a finding.

    Endpoint, parameter, payload, the full request, and the class - plus the model-written
    cause, impact and remedy once the final report exists. Anything the run did not record
    stays blank rather than being invented: a fabricated payload in a report is worse than
    a missing one.
    """
    from src.adaptix.ui.explain import explain

    row = row or {}
    target = str(row.get('target') or '')
    evidence = row.get('verification_evidence') or {}
    reproduction = row.get('reproduction') if isinstance(row.get('reproduction'), dict) else {}
    evidence_url = (str(evidence.get('url') or '') if isinstance(evidence, dict) else '')
    reproduction_url = str(reproduction.get('url') or '')
    url = str(row.get('url') or '') or target
    # A canonical finding can name only the endpoint while its signed replay records the
    # exact injected URL. Prefer the URL that actually carries the payload, or the screen
    # would show a verified SQL injection with a bare path and no reproduction.
    if not _has_query_or_fragment(url):
        url = next((candidate for candidate in (reproduction_url, evidence_url)
                    if _has_query_or_fragment(candidate)), url)
    payload = (str(row.get('payload') or '')
               or str(reproduction.get('payload') or '')
               or (str(evidence.get('payload') or '') if isinstance(evidence, dict) else ''))
    if not payload:
        # A verified injection record keeps the exact input on its attempts.
        for attempt in (row.get('attempts') or []):
            if isinstance(attempt, dict) and attempt.get('payload'):
                payload = str(attempt['payload'])
                break
    parameter = (row.get('parameter') or reproduction.get('parameter')
                 or (evidence.get('parameter') if isinstance(evidence, dict) else '') or '')
    if not parameter and _has_query_or_fragment(url):
        parsed = urlsplit(url)
        query = parsed.query or parsed.fragment.partition('?')[2]
        names = [name for name, _value in parse_qsl(query, keep_blank_values=True)]
        parameter = ','.join(names)
    if not payload:
        payload = _payload_from_url(url, parameter)
    if not _has_query_or_fragment(url) and payload and parameter:
        url = _url_with_payload(url, parameter, payload)
    endpoint = url.split('?')[0]
    category = str(row.get('class') or row.get('finding_type') or row.get('category') or '')
    explanation = explain(row)
    modeled = {}
    if isinstance(explanations, dict):
        modeled = explanations.get(finding_ref(row)) or {}
        if not isinstance(modeled, dict):
            modeled = {}
    return {
        'endpoint': endpoint,
        'parameter': str(parameter),
        'payload': payload,
        'url': url,
        'class': category,
        'severity': str(row.get('severity') or ''),
        'status': str(row.get('verification_status') or ''),
        'title': str(modeled.get('title') or explanation.get('title') or category),
        'cwe': explanation.get('cwe') or '',
        'cause': str(modeled.get('cause') or ''),
        'mitigation': str(modeled.get('remediation') or ''),
        'impact': str(modeled.get('impact') or ''),
        'extracted': list(row.get('extracted_classes') or []),
        'impact_proven': bool(row.get('impact_proven')),
    }


@dataclass
class LiveView:
    """Renderable state of one run: header facts, log tail, findings, token meter."""

    target: list = field(default_factory=list)
    model: str = ''
    run_id: str = ''
    objective: str = ''
    status: str = 'idle'
    stop_reason: str = ''
    iteration: int = 0
    log: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    details: list = field(default_factory=list)
    tokens: TokenMeter = field(default_factory=TokenMeter)
    elapsed: float = 0.0
    started_at: float | None = None
    workflow_node: str = ''
    workflow_phase: str = ''
    narrative: dict = field(default_factory=dict)
    # Run configuration the operator can change from the prompt line. Defaults come
    # from .env so the TUI inherits the CLI setup instead of demanding flags.
    identity: str = ''
    context_tokens: int = 32768
    time_budget: int | None = 2400
    tool_budget: int | None = 90
    token_budget: int | None = 5000000
    max_iterations: int = 40

    def header_lines(self) -> list[str]:
        target = ', '.join(self.target) or '(no target — type /target <url>)'
        lines = [f'target  {target}',
                 f'model   {self.model or "(from .env)"}   run {self.run_id or "-"}']
        progress = f'pass {self.iteration}'
        if self.max_iterations:
            progress += f'/{self.max_iterations}'
        if self.workflow_node:
            progress = f'graph {self.workflow_node} {self.workflow_phase} · {progress}'.strip()
        lines.append(f'status  {self.status}   {progress}   {self.elapsed:.0f}s'
                     + (f'   stop {self.stop_reason}' if self.stop_reason else ''))
        return lines

    def append(self, text: str, stamp: bool = True) -> None:
        text = str(text)
        if stamp:
            text = f'{datetime.datetime.now().strftime("%H:%M:%S")}  {text}'
        self.log.append(text.rstrip())
        # Bound the resident log: a long run logs thousands of lines and the screen
        # only ever shows the tail.
        if len(self.log) > 4000:
            del self.log[:1000]


def view_from_state(state, view: LiveView | None = None) -> LiveView:
    """Fold one workflow snapshot into the view."""
    state = state or {}
    view = view or LiveView()
    if state.get('target'):
        target = state['target']
        view.target = list(target) if isinstance(target, (list, tuple)) else [str(target)]
    view.model = str(state.get('llm_model') or view.model)
    view.run_id = str(state.get('run_id') or view.run_id)
    view.iteration = _as_int(state.get('iterations'))
    if state.get('max_iterations') is not None:
        view.max_iterations = _as_int(state.get('max_iterations'))
    view.tokens = read_tokens(state)
    report = state.get('report') or {}
    view.findings = finding_rows(state, include_unverified=not bool(report))
    explanations = report.get('finding_explanations') if isinstance(report, dict) else {}
    view.details = [finding_detail(row, explanations) for row in view.findings]
    if report:
        view.status = str(report.get('status') or view.status)
        view.stop_reason = str(report.get('stop_reason') or (report.get('termination') or {}).get('stop_reason') or '')
        if isinstance(report.get('narrative'), dict):
            view.narrative = report['narrative']
    elif state.get('stop_reason'):
        view.stop_reason = str(state.get('stop_reason'))
    events = [str(e) for e in (state.get('events') or []) if e is not None]
    # Only the unseen tail is appended: snapshots repeat the whole event list.
    if events:
        known = len(view.log)
        already = sum(1 for line in view.log if line[10:].strip())
        if len(events) > already:
            for event in events[already:]:
                view.append(event)
        del known
    return view


def view_from_progress(progress, view=None):
    view = view or LiveView()
    progress = progress or {}
    view.workflow_node = str(progress.get('node') or view.workflow_node)
    view.workflow_phase = str(progress.get('phase') or view.workflow_phase)
    view.stop_reason = str(progress.get('stop_reason') or view.stop_reason)
    if view.workflow_phase == 'running':
        view.status = 'running'
    elif view.workflow_phase == 'failed':
        view.status = 'failed'
    return view


def view_from_report(report, view=None):
    view = view or LiveView()
    report = report or {}
    if not report:
        return view
    view.status = str(report.get('status') or view.status)
    view.stop_reason = str(report.get('stop_reason')
                           or (report.get('termination') or {}).get('stop_reason') or view.stop_reason)
    view.model = str(report.get('llm_model') or view.model)
    view.findings = finding_rows(report, include_unverified=False)
    explanations = report.get('finding_explanations') or {}
    view.details = [finding_detail(row, explanations) for row in view.findings]
    if isinstance(report.get('narrative'), dict):
        view.narrative = report['narrative']
    configured = ((report.get('budget_status') or {}).get('token_budget') or {}).get('configured')
    view.tokens = read_tokens({**report, 'token_budget': configured if isinstance(configured, int) else None})
    view.workflow_node = 'final_report'
    view.workflow_phase = 'completed'
    return view
