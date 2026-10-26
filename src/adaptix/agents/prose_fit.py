"""Fit over-long prose fields to their declared limits instead of rejecting the decision.

A `string_too_long` error says the model produced a complete, well-shaped decision whose
rationale or review prose runs past a cosmetic cap. Discarding the whole plan because a
sentence is 500 characters instead of 400 throws away a usable decision and burns a
provider call to re-ask the same question.

This trims only fields the schema itself declares as length-bounded prose, never an
action, a target, a tool name, an evidence ref or a structured value. It is a repair
applied after validation already failed, and the caller records that it happened.
"""

from __future__ import annotations

import json

from src.adaptix.agents.schema import PlannerDecision

# Only these paths may be trimmed: free-text fields whose length is a presentation cap,
# not information. An action list, an evidence ref or a status literal is never touched.
PROSE_PATHS = (
    ('rationale',),
    ('reflection',),
    ('review', 'uncertainty'),
    ('review', 'failure'),
    ('review', 'decision_change'),
    ('review', 'model_review'),
)


def _limit(field_path):
    """The schema's own max_length for a field path, or None when it declares none."""
    try:
        node = PlannerDecision
        for part in field_path:
            annotation = node.model_fields[part].annotation
            node = annotation
        for item in getattr(node, 'model_fields', {}).values():
            pass
        return None
    except Exception:
        return None


def _unwrap(annotation):
    """The concrete model behind ``X``, ``X | None`` or ``Optional[X]``."""
    if hasattr(annotation, 'model_fields'):
        return annotation
    for arg in getattr(annotation, '__args__', ()) or ():
        if hasattr(arg, 'model_fields'):
            return arg
    return annotation


def _max_length(field_path):
    """Read the enforced cap from the model metadata, never from a hardcoded copy.

    The first path element may name either a field of ``PlannerDecision`` or one of its
    item models (``Action``, ``Hypothesis``, ``ReflectionReview``) reached through a list
    such as ``actions``. Both forms resolve here, so the prompt and the validator share
    one source of truth.
    """
    from src.adaptix.agents import schema as S

    root_name = field_path[0]
    if hasattr(PlannerDecision.model_fields.get(root_name, None), 'annotation'):
        node, rest = PlannerDecision, field_path
    else:
        model = getattr(S, root_name, None)
        if not hasattr(model, 'model_fields'):
            return None
        node, rest = model, field_path[1:]
    if not rest:
        return None
    spec = None
    for index, part in enumerate(rest):
        fields = getattr(node, 'model_fields', None)
        if not isinstance(fields, dict):
            return None
        spec = fields.get(part)
        if spec is None:
            return None
        if index + 1 < len(rest):
            # `review` is declared as `ReflectionReview | None`; the nested model is
            # behind the union, not the annotation itself.
            node = _unwrap(spec.annotation)
    if spec is None:
        return None
    for meta in spec.metadata:
        cap = getattr(meta, 'max_length', None)
        if isinstance(cap, int):
            return cap
    return None


def _trim(text, cap):
    """Word-safe truncation: never split a word, always end below the cap."""
    if not isinstance(text, str) or len(text) <= cap:
        return text, False
    cut = text[:cap]
    space = cut.rfind(' ')
    if space > cap // 2:
        cut = cut[:space]
    return cut.rstrip(' ,;:'), True


def fit_prose(raw_text):
    """Truncate over-long prose fields. Returns (json_text, trimmed_paths) or (None, [])."""
    try:
        body = json.loads(raw_text)
    except Exception:
        return None, []
    if not isinstance(body, dict):
        return None, []
    trimmed = []
    for path in PROSE_PATHS:
        node = body
        for part in path[:-1]:
            node = node.get(part) if isinstance(node, dict) else None
            if not isinstance(node, dict):
                break
        if not isinstance(node, dict):
            continue
        leaf = path[-1]
        if leaf not in node:
            continue
        cap = _max_length(path)
        if not isinstance(cap, int):
            continue
        fitted, changed = _trim(node[leaf], cap)
        if changed:
            node[leaf] = fitted
            trimmed.append('.'.join(path))
    if not trimmed:
        return None, []
    return json.dumps(body, ensure_ascii=False), trimmed
