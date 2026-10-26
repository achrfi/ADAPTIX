"""The report narrative is model-written and stays grounded in recorded findings."""
import json
import time

from src.adaptix.reporting import narrative
from src.adaptix.reporting.report import final_report


def _state(**over):
    row = {'evidence_id': 'EV-1', 'finding_type': 'sql_injection', 'severity': 'high',
           'target': 'http://h/search?q=a', 'parameter': 'q',
           'verification_status': 'verified', 'verification_method': 'deterministic_replay',
           'source_tool': 'injection_probe', 'reason': 'replay confirmed the injected quote',
           'payload': "a'"}
    state = {
        'target': ['http://h'], 'run_id': 'narrative-test', 'status': 'scope_ok',
        'findings': [row], 'verified_findings': [row], 'errors': [], 'events': [],
        'scope_manifest': {}, 'scope_touched': [], 'scope_deferred': [],
        'planner_metrics': {'mode': 'llm', 'tokens_used': 1000, 'llm_calls': 4},
        'run_started_at': time.time() - 5, 'time_budget_seconds': 600,
        'token_budget': 100000, 'model_context_tokens': 32768,
        'llm_model': 'openai/test', 'llm_api_base': None, 'llm_api_key': None,
        'report_model_enabled': True, 'action_outcomes': [], 'planning_history': [],
        'execution_metrics': {}, 'metrics': {}, 'candidates': [], 'nuclei_scan_metrics': {},
    }
    state.update(over)
    return state


class _Usage:
    prompt_tokens = 500
    completion_tokens = 100
    total_tokens = 600


class _Message:
    content = json.dumps({
        'title': 'Laporan assessment model',
        'executive_summary': 'Ringkasan dibuat oleh model dari bukti yang tercatat.',
        'findings': [{
            'finding_id': 'EV-1',
            'title': 'SQL injection pada parameter q',
            'cause': 'Nilai q masuk ke query tanpa parameter binding.',
            'impact': 'Penyerang dapat mengubah bentuk query.',
            'remediation': 'Gunakan prepared statement untuk parameter q.',
        }],
        'coverage_note': 'SQL injection diuji melalui replay deterministik.',
        'limitations': 'Dampak data penuh tidak diuji pada run ini.',
        'next_steps': 'Perbaiki query lalu ulangi replay.',
    })


class _Choice:
    message = _Message()
    finish_reason = 'stop'


class _Response:
    choices = (_Choice(),)
    usage = _Usage()


def _patch_io(monkeypatch, tmp_path):
    from src.adaptix.agents import reflector
    from src.adaptix.evidence import audit, storage
    monkeypatch.setattr(reflector, 'collect_findings', lambda _state: {})
    monkeypatch.setattr(storage, 'artifact_path',
                        lambda state, stage, host, suffix: tmp_path / f'{stage}.{suffix}')
    monkeypatch.setattr(audit, 'export_bundle',
                        lambda state, report, events: {})
    monkeypatch.setattr(narrative.litellm, 'token_counter', lambda **kwargs: 1000)


def test_model_writes_the_report_and_finding_explanations(tmp_path, monkeypatch):
    _patch_io(monkeypatch, tmp_path)
    calls = []

    def completion(**kwargs):
        calls.append(kwargs)
        return _Response()

    monkeypatch.setattr(narrative.litellm, 'completion', completion)
    result = final_report(_state(llm_reasoning_effort='none'))
    report = result['report']
    assert calls and calls[0]['model'] == 'openai/test'
    assert calls[0]['reasoning_effort'] == 'none'
    assert report['report_generation']['status'] == 'generated'
    assert report['narrative']['title'] == 'Laporan assessment model'
    assert report['finding_explanations']['EV-1']['cause'].startswith('Nilai q')
    assert 'Ringkasan dibuat oleh model' in result['markdown_report']
    assert 'report narrative: model `openai/test`' in result['markdown_report']
    assert 'SQL injection pada parameter q' in result['markdown_report']
    assert report['budget_status']['token_budget']['used'] == 1600
    assert report['token_ledger'][-1]['purpose'] == 'report_narrative'


def test_disabling_the_report_model_keeps_the_evidence_report_without_fake_prose(tmp_path, monkeypatch):
    _patch_io(monkeypatch, tmp_path)

    def completion(**kwargs):
        raise AssertionError('report model must not be called when disabled')

    monkeypatch.setattr(narrative.litellm, 'completion', completion)
    result = final_report(_state(report_model_enabled=False))
    report = result['report']
    assert report['report_generation']['status'] == 'disabled'
    assert 'narrative' not in report
    markdown = result['markdown_report']
    assert 'Penyebab belum dicatat untuk kelas ini.' not in markdown
    assert 'Tinjau bukti pada laporan dan uji ulang sebelum memperbaiki.' not in markdown


def test_provider_failure_does_not_break_the_report_or_leak_transport_noise(tmp_path, monkeypatch):
    _patch_io(monkeypatch, tmp_path)

    def completion(**kwargs):
        raise RuntimeError('Provider List: https://docs.litellm.ai/docs/providers')

    monkeypatch.setattr(narrative.litellm, 'completion', completion)
    result = final_report(_state())
    report = result['report']
    assert report['report_generation']['status'] == 'unavailable'
    assert report['report_generation']['error_class'] == 'RuntimeError'
    assert 'narrative' not in report
    assert 'Provider List' not in result['markdown_report']
    assert 'Penyebab belum dicatat untuk kelas ini.' not in result['markdown_report']

def test_report_model_does_not_start_when_the_provider_ledger_exhausted_the_budget(
        tmp_path, monkeypatch):
    _patch_io(monkeypatch, tmp_path)

    def completion(**kwargs):
        raise AssertionError('no report call fits the remaining budget')

    monkeypatch.setattr(narrative.litellm, 'completion', completion)
    state = _state(token_budget=3000)
    state['token_ledger'] = [{'provider_call': True, 'source': 'provider',
                              'tokens_charged': 2800, 'result': 'valid_decision'}]
    state['planner_metrics'] = {'mode': 'llm', 'tokens_used': 0, 'llm_calls': 1}
    report = final_report(state)['report']
    assert report['report_generation']['status'] == 'budget_exhausted'
    assert report['report_generation']['attempts'] == 0


def test_a_truncated_report_response_is_recorded_and_not_retried(tmp_path, monkeypatch):
    _patch_io(monkeypatch, tmp_path)
    calls = []

    class _TruncatedMessage:
        content = '{"title": "terpotong"'

    class _TruncatedChoice:
        message = _TruncatedMessage()
        finish_reason = 'length'

    class _TruncatedResponse:
        choices = (_TruncatedChoice(),)
        usage = _Usage()

    def completion(**kwargs):
        calls.append(kwargs)
        return _TruncatedResponse()

    monkeypatch.setattr(narrative.litellm, 'completion', completion)
    report = final_report(_state())['report']
    assert len(calls) == 1
    assert report['report_generation']['status'] == 'unavailable'
    assert report['report_generation']['error_class'] == 'TruncatedResponse'
    assert report['report_generation']['finish_reason'] == 'length'
    assert report['token_ledger'][-1]['result'] == 'truncated_response'
