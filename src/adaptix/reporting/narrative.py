"""Model-written report narrative grounded in the run's recorded evidence."""
from __future__ import annotations

import json
import os
import time

import litellm
from pydantic import BaseModel, ConfigDict, Field

from src.adaptix.agents.schema import strip_code_fence
from src.adaptix.reporting.finding_ids import finding_ref
from src.adaptix.workflow.budget import remaining_seconds, remaining_tokens

litellm.suppress_debug_info = True
litellm.set_verbose = False

REPORT_MAX_TOKENS = 4096
REPORT_MIN_OUTPUT = 600
REPORT_MAX_FINDINGS = 40


class FindingNarrative(BaseModel):
    model_config = ConfigDict(extra='ignore', str_strip_whitespace=True)
    finding_id: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=1, max_length=240)
    cause: str = Field(default='', max_length=4000)
    impact: str = Field(default='', max_length=4000)
    remediation: str = Field(default='', max_length=4000)


class ReportNarrative(BaseModel):
    model_config = ConfigDict(extra='ignore', str_strip_whitespace=True)
    title: str = Field(min_length=1, max_length=240)
    executive_summary: str = Field(min_length=1, max_length=8000)
    findings: list[FindingNarrative] = Field(default_factory=list, max_length=REPORT_MAX_FINDINGS)
    coverage_note: str = Field(default='', max_length=5000)
    limitations: str = Field(default='', max_length=4000)
    next_steps: str = Field(default='', max_length=5000)


def _short(value, limit):
    text = str(value or '').strip()
    return text[:limit]


def _payload(row):
    for value in (row.get('payload'),
                  (row.get('reproduction') or {}).get('payload') if isinstance(row.get('reproduction'), dict) else None,
                  (row.get('verification_evidence') or {}).get('payload') if isinstance(row.get('verification_evidence'), dict) else None):
        if value:
            return _short(value, 500)
    for attempt in row.get('attempts') or []:
        if isinstance(attempt, dict) and attempt.get('payload'):
            return _short(attempt['payload'], 500)
    return ''


def _finding_facts(row):
    return {
        'finding_id': finding_ref(row),
        'class': _short(row.get('class') or row.get('finding_type') or row.get('category'), 120),
        'severity': _short(row.get('severity'), 20),
        'verification_status': _short(row.get('verification_status'), 40),
        'verification_method': _short(row.get('verification_method') or row.get('verification_basis'), 80),
        'verification_level': _short(row.get('verification_level'), 40),
        'source_tool': _short(row.get('source_tool'), 80),
        'target': _short(row.get('target') or row.get('url'), 500),
        'parameter': _short(row.get('parameter'), 120),
        'payload': _payload(row),
        'reason': _short(row.get('reason'), 500),
        'impact': _short(row.get('impact'), 300),
        'impact_proven': bool(row.get('impact_proven')),
        'extracted_classes': [str(item)[:80] for item in (row.get('extracted_classes') or [])[:8]],
        'scanner_template': _short(row.get('template_id'), 120),
        'scanner_matcher': _short(row.get('matcher_name'), 120),
    }


def _report_facts(report):
    rows = [row for row in (report.get('findings') or []) if isinstance(row, dict)]
    if not rows:
        rows = [row for row in ((report.get('independently_verified_findings') or [])
                                + (report.get('scanner_matched_findings') or []))
                if isinstance(row, dict)]
    findings = []
    seen = set()
    for row in rows:
        ref = finding_ref(row)
        if ref in seen:
            continue
        seen.add(ref)
        findings.append(_finding_facts(row))
        if len(findings) >= REPORT_MAX_FINDINGS:
            break
    coverage = report.get('assessment_coverage') or {}
    classes = []
    for name, row in list((coverage.get('classes') or {}).items())[:24]:
        if not isinstance(row, dict):
            continue
        classes.append({'class': name, 'status': row.get('status'),
                        'reason': _short(row.get('reason'), 240)})
    termination = report.get('termination') or {}
    return {
        'objective': _short(report.get('user_prompt'), 1000),
        'target': report.get('target'),
        'status': report.get('status'),
        'stop_reason': report.get('stop_reason'),
        'termination': {'cause': termination.get('cause'), 'detail': _short(termination.get('detail'), 500)},
        'assessment_coverage': {'assessment_performed': coverage.get('assessment_performed'),
                                'classes': classes,
                                'notes': [str(note)[:300] for note in (coverage.get('notes') or [])[:8]]},
        'findings': findings,
        'transport_notes': [str(note)[:300] for note in (report.get('transport_notes') or [])[:6]],
        'errors': [str(error)[:300] for error in (report.get('errors') or [])[:6]],
    }


def _system_prompt():
    shape = {
        'title': 'judul laporan',
        'executive_summary': 'ringkasan eksekutif 2-4 paragraf',
        'findings': [{
            'finding_id': 'id persis dari data',
            'title': 'nama kelas yang mudah dipahami',
            'cause': 'penyebab teknis yang didukung data',
            'impact': 'dampak yang benar-benar dibuktikan data',
            'remediation': 'perbaikan spesifik dan dapat diuji',
        }],
        'coverage_note': 'apa yang diuji dan apa yang belum',
        'limitations': 'keterbatasan bukti dan cakupan',
        'next_steps': 'langkah verifikasi/perbaikan berikutnya',
    }
    return (
        'Anda menulis laporan assessment keamanan defensif untuk operator yang berwenang. '
        'Tulis dalam Bahasa Indonesia yang jelas, ringkas, dan profesional. '
        'Gunakan HANYA data JSON yang diberikan. Jangan mengarang temuan, endpoint, parameter, payload, ID, '
        'severity, status verifikasi, atau dampak. Jangan mengubah status bukti: scanner match bukan temuan yang '
        'diverifikasi independen, dan temuan berstatus belum terverifikasi tidak boleh disebut pasti. '
        'Jangan menyimpulkan target aman hanya karena tidak ada temuan. Jangan menyebut kelas sudah diuji kecuali '
        'assessment_coverage menyatakannya. Setiap entri findings harus memakai finding_id persis dari data dan '
        'menjelaskan sebab, dampak, serta perbaikan yang konsisten dengan bukti yang tercatat. '
        'Jika sebuah detail tidak ada di data, tulis bahwa detail itu tidak tercatat; jangan menebaknya. '
        'Kembalikan satu objek JSON saja, tanpa markdown fence dan tanpa teks lain, dengan bentuk: '
        + json.dumps(shape, ensure_ascii=False, separators=(',', ':'))
    )


def _user_prompt(report):
    facts = _report_facts(report)
    return ('Data assessment (satu-satunya sumber fakta):\n'
            + json.dumps(facts, ensure_ascii=False, indent=2, default=str)
            + '\n\nTulis narasi laporan untuk data di atas.')


def _parse(text):
    text = strip_code_fence(text or '').strip()
    if not text:
        return None
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        start, end = text.find('{'), text.rfind('}')
        if start < 0 or end <= start:
            return None
        try:
            value = json.loads(text[start:end + 1])
        except (TypeError, ValueError):
            return None
    return value if isinstance(value, dict) else None


def _content(response):
    try:
        message = response.choices[0].message
    except (AttributeError, IndexError, TypeError):
        return ''
    if isinstance(message, dict):
        return str(message.get('content') or '')
    return str(getattr(message, 'content', '') or '')


def _usage(response):
    usage = getattr(response, 'usage', None)
    if usage is None:
        return 0, 0, 0
    prompt = int(getattr(usage, 'prompt_tokens', 0) or 0)
    completion = int(getattr(usage, 'completion_tokens', 0) or 0)
    total = int(getattr(usage, 'total_tokens', 0) or 0) or prompt + completion
    return prompt, completion, total


def _finish_reason(response):
    try:
        return str(getattr(response.choices[0], 'finish_reason', '') or '')
    except (AttributeError, IndexError, TypeError):
        return ''


def _empty(meta, ledger=None):
    return {'meta': meta, 'ledger': list(ledger or []), 'narrative': None}


def generate_narrative(state, report):
    state = state or {}
    report = report or {}
    meta = {'status': 'disabled', 'model': state.get('llm_model') or os.getenv('ADAPTIX_LLM_MODEL') or '',
            'attempts': 0, 'tokens_charged': 0, 'finding_ids': [],
            'missing_finding_ids': [], 'ignored_finding_ids': []}
    if not state.get('report_model_enabled'):
        return _empty(meta)
    model = meta['model']
    if not model:
        meta['status'] = 'unavailable'
        meta['error_class'] = 'ModelNotConfigured'
        return _empty(meta)
    time_left = remaining_seconds(state)
    if time_left < 20:
        meta['status'] = 'time_exhausted'
        return _empty(meta)
    context = int(state.get('model_context_tokens') or 4096)
    facts = _report_facts(report)
    allowed = {row['finding_id']: row for row in facts['findings']}
    messages = [{'role': 'system', 'content': _system_prompt()},
                {'role': 'user', 'content': _user_prompt(report)}]
    try:
        prompt_tokens = int(litellm.token_counter(model=model, messages=messages))
    except Exception:  # noqa: BLE001 - any tokenizer failure falls back to bytes
        prompt_tokens = len(json.dumps(messages, ensure_ascii=False).encode()) // 3 + 128
    target_tokens = 1200 + 250 * len(facts['findings'])
    max_tokens = min(REPORT_MAX_TOKENS, max(2200, target_tokens),
                     context - prompt_tokens - 128)
    if max_tokens < REPORT_MIN_OUTPUT:
        meta['status'] = 'context_exhausted'
        return _empty(meta)
    planner_spent = int((state.get('planner_metrics') or {}).get('tokens_used', 0) or 0)
    ledger_spent = sum(int(row.get('tokens_charged', 0) or 0)
                       for row in (state.get('token_ledger') or []) if isinstance(row, dict))
    # Planner metrics and the provider ledger describe the same spend. Taking the
    # larger figure means a lagging metrics counter can never let the report model
    # start after the budget is already exhausted.
    budget_room = remaining_tokens(state, max(planner_spent, ledger_spent))
    if budget_room is not None:
        max_tokens = min(max_tokens, budget_room - prompt_tokens)
        if max_tokens < REPORT_MIN_OUTPUT:
            meta['status'] = 'budget_exhausted'
            return _empty(meta)
    timeout = min(float(state.get('llm_timeout_seconds') or os.getenv('ADAPTIX_LLM_TIMEOUT') or 180),
                  float(time_left))
    if timeout < 10:
        meta['status'] = 'time_exhausted'
        return _empty(meta)
    kwargs = {'model': model, 'messages': messages, 'temperature': 0.1,
              'max_tokens': int(max_tokens), 'timeout': max(1.0, timeout), 'num_retries': 0}
    if state.get('llm_api_base'):
        kwargs['api_base'] = state['llm_api_base']
    if state.get('llm_api_key'):
        kwargs['api_key'] = state['llm_api_key']
    if state.get('llm_reasoning_effort'):
        kwargs['reasoning_effort'] = state['llm_reasoning_effort']
    ledger = []
    narrative = None
    repair = ''
    for attempt in range(2):
        spent = sum(int(row.get('tokens_charged', 0) or 0) for row in ledger)
        if budget_room is not None and prompt_tokens + max_tokens > budget_room - spent:
            break
        call_messages = list(messages)
        if repair:
            call_messages.append({'role': 'user', 'content': repair})
        started = time.monotonic()
        entry = {'provider_call': True, 'purpose': 'report_narrative', 'attempt': attempt + 1,
                 'model': model, 'source': 'reservation', 'tokens_charged': prompt_tokens + max_tokens,
                 'prompt_tokens': 0, 'completion_tokens': 0, 'result': 'pending'}
        ledger.append(entry)
        meta['attempts'] = attempt + 1
        try:
            response = litellm.completion(**{**kwargs, 'messages': call_messages})
        except Exception as exc:  # noqa: BLE001 - report generation must never break the evidence report
            entry.update(result='failed', error_type=type(exc).__name__,
                         seconds=round(time.monotonic() - started, 6))
            meta['status'] = 'unavailable'
            meta['error_class'] = type(exc).__name__
            break
        prompt_used, completion_used, total_used = _usage(response)
        if total_used:
            entry.update(source='provider', tokens_charged=total_used,
                         prompt_tokens=prompt_used, completion_tokens=completion_used)
        entry['finish_reason'] = _finish_reason(response)
        entry['seconds'] = round(time.monotonic() - started, 6)
        payload = _parse(_content(response))
        if payload is None:
            truncated = entry['finish_reason'] == 'length'
            entry['result'] = 'truncated_response' if truncated else 'invalid_json'
            meta['finish_reason'] = entry['finish_reason']
            meta['error_class'] = 'TruncatedResponse' if truncated else 'InvalidJSON'
            if truncated:
                # Repeating the same call with the same output ceiling only spends
                # more budget on another truncated response.
                break
            repair = ('Respons sebelumnya bukan objek JSON yang lengkap. Kembalikan hanya satu objek JSON '
                      'valid dengan semua field yang diminta. Jangan menambah temuan atau ID baru.')
            continue
        try:
            candidate = ReportNarrative.model_validate(payload)
        except Exception as exc:  # noqa: BLE001 - schema errors are prompt feedback, not fatal
            entry['result'] = 'invalid_schema'
            entry['error_class'] = type(exc).__name__
            repair = ('Respons sebelumnya tidak sesuai bentuk yang diminta. Kembalikan objek JSON dengan field '
                      'title, executive_summary, findings, coverage_note, limitations, next_steps. '
                      'Setiap finding wajib berisi finding_id, title, cause, impact, remediation. '
                      'Jangan menambah temuan atau ID baru.')
            continue
        valid = []
        ignored = []
        seen = set()
        for row in candidate.findings:
            if row.finding_id not in allowed or row.finding_id in seen:
                ignored.append(row.finding_id)
                continue
            seen.add(row.finding_id)
            valid.append(row)
        missing = [ref for ref in allowed if ref not in seen]
        if missing and attempt == 0:
            entry['result'] = 'missing_findings'
            meta['missing_finding_ids'] = missing
            repair = ('Narasi belum mencakup semua finding_id yang ada di data: ' + ', '.join(missing)
                      + '. Lengkapi setiap finding_id tanpa menambah ID baru.')
            continue
        entry['result'] = 'valid_report'
        narrative = candidate.model_copy(update={'findings': valid})
        meta['status'] = 'generated' if not missing and not ignored else 'partial'
        meta['finding_ids'] = [row.finding_id for row in valid]
        meta['missing_finding_ids'] = missing
        meta['ignored_finding_ids'] = ignored
        break
    if narrative is None and meta['status'] == 'disabled':
        meta['status'] = 'unavailable'
    meta['tokens_charged'] = sum(int(row.get('tokens_charged', 0) or 0) for row in ledger)
    return {'meta': meta, 'ledger': ledger,
            'narrative': narrative.model_dump() if narrative is not None else None}
