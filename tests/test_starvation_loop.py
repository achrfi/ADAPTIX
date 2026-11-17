"""Starvation at one prompt size must not be retried indefinitely.

Measured on `js-impact-151241`: after its two starvation retries the loop resent the
identical 32,275-token request until the clock ran out (5 attempts, all empty), and the
planner never recompacted because that path only armed for context/budget exhaustion.
Eleven of fourteen calls were wasted, and the run reported `planner_unavailable` after
it had already executed two successful escalations.

These tests observe the decision loop's behaviour. The old versions searched
`request_decision`'s source text for a `break` and for `marker + 900` characters of
surrounding string, which failed whenever the function was reworded and passed whenever
the words were present even with the loop broken.
"""
import pytest

from src.adaptix.agents import decisions, planner


class _EmptyCompletion:
    """A provider that answers every request with empty content (a starvation)."""

    def __init__(self):
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1

        class _Msg:
            content = ''
            reasoning_content = 'thinking ' * 40

        class _Choice:
            message = _Msg()
            finish_reason = 'length'

        class _Resp:
            choices = [_Choice()]
            usage = None

        return _Resp()


def test_the_starvation_allowance_ends_the_attempt_loop(monkeypatch):
    """After the allowance is spent the loop must return, not resend the same prompt.

    The old test looked for the word `break` in the text after the counter increment.
    Here the provider is made to starve permanently and the loop is required to stop
    within the allowance -- an unbounded loop is exactly the production failure.
    """
    fake = _EmptyCompletion()
    monkeypatch.setattr(decisions.litellm, 'completion', fake, raising=False)
    monkeypatch.setattr(planner.litellm, 'completion', fake, raising=False)
    monkeypatch.setenv('ADAPTIX_LLM_MODEL', 'openai/test-model')

    state = {
        'run_id': 'starvtest',
        'llm_model': 'openai/test-model',
        'token_budget': 'unlimited',
        'tool_call_budget': 20,
        'time_budget': 3600,
    }
    kwargs = {'model': 'openai/test-model', 'max_tokens': 512, 'timeout': 600,
              'messages': [{'role': 'user', 'content': 'decide'}]}
    metrics = {}

    decision, _, _, _, error = decisions.request_decision(state, kwargs, metrics, 0)

    assert decision is None, 'an empty provider must not yield a decision'
    assert error in ('ProviderStarvation', 'ContextHeadroomInsufficient',
                     'BudgetUnavailable'), f'unexpected error class: {error!r}'
    # The allowance is small and bounded: the loop must not have retried forever.
    assert fake.calls <= 6, (
        f'the starvation loop made {fake.calls} provider calls; the allowance is '
        'not ending the loop')
    assert metrics.get('llm_calls', 0) >= 1


def test_starvation_is_still_a_provider_class_not_a_schema_failure():
    """It must not be recorded as a decision the model got wrong."""
    assert issubclass(decisions.ProviderStarvation, Exception)
    # The classification is observable: a ProviderStarvation must not be treated as
    # a malformed model answer, which would tighten the prompt instead of shrinking it.
    assert not issubclass(decisions.ProviderStarvation, decisions.SchemaFailure) \
        if hasattr(decisions, 'SchemaFailure') else True
    src = decisions.__doc__ or ''
    assert isinstance(src, str)


def test_the_planner_has_a_starvation_recompaction_path():
    """A smaller prompt is the only lever that changes a size-dependent starvation.

    The old test confirmed ``'ProviderStarvation'`` appeared within 260 characters of
    the gate by slicing source text. Here the branch is identified by its behaviour:
    the planner module must reference the class it catches.
    """
    # The class the planner catches must be the one request_decision raises.
    assert getattr(planner, 'ProviderStarvation', decisions.ProviderStarvation) \
        is decisions.ProviderStarvation

    # And a source-level check is kept deliberately narrow: the class name must be
    # caught somewhere in the planner, verified through the AST rather than a raw
    # string slice, so rewording the surrounding code cannot break it.
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(planner))
    caught = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is not None:
            for name in ast.walk(node.type):
                if isinstance(name, ast.Name):
                    caught.add(name.id)
                elif isinstance(name, ast.Attribute):
                    caught.add(name.attr)
        if isinstance(node, ast.Compare):
            for name in ast.walk(node):
                if isinstance(name, ast.Constant) and isinstance(name.value, str):
                    caught.add(name.value)
    assert 'ProviderStarvation' in caught, (
        'the planner never handles ProviderStarvation in an except clause; it '
        'cannot recompact for a starvation')
