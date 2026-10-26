#!/usr/bin/env bash
# Point ADAPTIX at any OpenAI-compatible provider, verify it, then run.
#
#   ./scripts/use-provider.sh                    # verify whatever .env configures
#   ./scripts/use-provider.sh --verify-only      # preflight only, no scan
#
# Provider settings come from .env (ADAPTIX_LLM_MODEL / ADAPTIX_API_BASE /
# ADAPTIX_API_KEY) or from the environment. Everything after -- is passed to
# the assessment unchanged.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PY=.venv/bin/python
[ -x "$PY" ] || PY=python3

VERIFY_ONLY=0
if [ "${1:-}" = "--verify-only" ]; then
  VERIFY_ONLY=1
  shift
fi

# Never echo the key. Show only whether each setting is present.
mask() { [ -n "${1:-}" ] && printf '%s' "set" || printf '%s' "(empty)"; }
echo "model     : ${ADAPTIX_LLM_MODEL:-(from .env)}"
echo "base url  : ${ADAPTIX_API_BASE:-(provider default)}"
echo "api key   : $(mask "${ADAPTIX_API_KEY:-}")"
echo

echo "=== preflight: can this provider plan? ==="
$PY -m src.adaptix.main --check-model "$@"
status=$?
if [ $status -ne 0 ]; then
  echo
  echo "Preflight failed. Nothing was scanned. Fix the provider, then retry." >&2
  exit $status
fi
if [ $VERIFY_ONLY -eq 1 ]; then
  echo "Preflight passed."
  exit 0
fi

echo
echo "=== starting assessment ==="
exec $PY -m src.adaptix.main "$@"
