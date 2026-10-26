#!/bin/bash
# Same generic objective as e2e-generic.sh, with the budgets widened: the last two runs
# died in a provider retry storm around pass 8-12, and the wall clock (45 min) ran out
# while the process was still cycling. Give it 90 minutes and a matching time budget so a
# slow provider cannot end the run before the report is written.
set -uo pipefail
cd /root/projects/adaptix || exit 1
RID="js-long-$(date +%H%M%S)"
echo "$RID" > /tmp/last-long-run
echo "run_id=$RID"
timeout 5400 .venv/bin/python -m src.adaptix.main \
  --target http://127.0.0.1:3000 \
  --run-id "$RID" \
  --instruction "Uji aplikasi ini. Buktikan injeksi SQL dan capai dampak terukur: ekstrak data pengguna (email dan password hash) melalui injeksi itu. Objektif ACHIEVED hanya jika kredensial pengguna nyata berhasil diekstrak; menemukan kelas kerentanan saja TIDAK cukup. Gunakan kapabilitas eskalasi deterministik yang tersedia." \
  --identity-context /root/projects/adaptix/identity-juiceshop.json \
  --time-budget 5100 \
  --token-budget 9000000 \
  --tool-call-budget 140 \
  --max-iterations 60 \
  --planner-retries 3 \
  --model-context-tokens 32768 \
  --no-baseline \
  >> "/tmp/$RID.log" 2>&1
echo "exit=$?"
