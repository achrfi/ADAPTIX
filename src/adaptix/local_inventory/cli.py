"""Start live local inventory from one operator command; no pre-existing ffuf JSON."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import uuid

from src.adaptix.config import ROOT
from .scope import LocalScope
from .wordlists import load_wordlist
from .workflow import run_local


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', default=os.getenv('ADAPTIX_TARGET', ''),
                        help='Explicit localhost/loopback HTTP(S) origin, or ADAPTIX_TARGET')
    parser.add_argument('--wordlist', type=Path, default=os.getenv('ADAPTIX_WORDLIST') or None)
    parser.add_argument('--out', type=Path, help='New output directory inside project work/')
    parser.add_argument('--ai', action='store_true', help='Summarize inventory using local Ollama; no AI tool execution')
    parser.add_argument('--model', default='qwen3.5:9b-q4_K_M')
    parser.add_argument('--browser-channel', choices=('chrome', 'msedge'))
    args, unknown = parser.parse_known_args(argv)
    if unknown:
        # Main's hosted-provider flags may contain credentials; never echo unknown values.
        parser.error('Unsupported options in local recon mode; use --help for supported options')
    try:
        LocalScope.from_target(args.target)
        load_wordlist(args.wordlist)
    except ValueError as exc:
        parser.error(str(exc))
    label = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:6]
    output = args.out or ROOT / 'work/local-recon-runs' / label
    try:
        report = run_local(args.target, output, ai=args.ai, model=args.model,
                           browser_channel=args.browser_channel, wordlist=args.wordlist)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps({'status': report['status'], 'recon_status': report['recon_status'],
                      'assessment_status': report.get('assessment_status'),
                      'notes': {'r': report.get('assessment_status_reason'),
                                'meaning': report.get('meaning')},
                      'stages': report['stages'], 'output': str(output)}, indent=2))
    return 0 if report['status'] == 'success' else 2
