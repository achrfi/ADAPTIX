#!/bin/bash
# Genericity proof: the objective no longer names a table, a column, or an endpoint path.
# If credentials still come out, the pipeline learned them from the target itself.
set -uo pipefail
cd /root/projects/adaptix || exit 1
RID="js-generic-$(date +%H%M%S)"
echo "$RID" > /tmp/last-tool-run
echo "run_id=$RID"
timeout 2700 .venv/bin/python -m src.adaptix.main \
  --target http://127.0.0.1:3000 \
  --run-id "$RID" \
  --instruction "Uji aplikasi ini. Buktikan injeksi SQL dan capai dampak terukur: ekstrak data pengguna (email dan password hash) melalui injeksi itu. Objektif ACHIEVED hanya jika kredensial pengguna nyata berhasil diekstrak; menemukan kelas kerentanan saja TIDAK cukup. Gunakan kapabilitas eskalasi deterministik yang tersedia." \
  --identity-context /root/projects/adaptix/identity-juiceshop.json \
  --time-budget 2400 \
  --token-budget 5000000 \
  --tool-call-budget 90 \
  --max-iterations 40 \
  --planner-retries 2 \
  --model-context-tokens 32768 \
  --no-baseline \
  >> "/tmp/$RID.log" 2>&1
echo "exit=$?"
