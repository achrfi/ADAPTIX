# Validasi perbaikan laporan IDOR

Perubahan diterapkan di /root/projects/adaptix melalui SSH sebagai root. Runtime Linux Conda base.
Tidak ada commit atau push. Laporan lama tetap dipertahankan.

## Hasil pemeriksaan

- Pytest: 112 passed in 4.34s.
- git diff --check: bersih.
- VAmPI operator: verified_findings=1; Reflection: 1 verified; integritas bundle terverifikasi.
- API Studio: label IDOR tanpa proof tidak dipromosikan; 0 verified, 1 inconclusive, tanpa model/tool call.
- LangGraph dimuat ulang; health /ok berhasil.

| Skenario Qwen3 nyata | Verified | Rejected | Inconclusive | Stop | Token provider |
|---|---:|---:|---:|---|---:|
| vulnerable | 1 | 0 | 0 | no_new_actions | 3051 |
| protected | 0 | 1 | 0 | no_new_actions | 2960 |

Kontrol publik tetap inconclusive. Native IDOR dan signed replay kandidat yang merujuk objek/pasangan identitas sama dihitung sekali. Tes mencakup bukti hilang, file diubah, run berbeda, label palsu, pasangan identitas berbeda, reflection berulang, report langsung, dan evidence expansion.

## Lokasi bukti

- /root/projects/adaptix/artifacts/scans/acceptance-i1-i6-1791995292-summary/acceptance-summary-39c763d06d7f.json
- /root/projects/adaptix/artifacts/runtime/idor-report-fix-live.log
- /root/projects/adaptix/artifacts/scans/idor-report-fix-vampi-1791995431/report-845e91831319.json
- /root/projects/adaptix/artifacts/runtime/idor-report-fix-api-summary.json
- Backup: /root/adaptix-backups/pre-idor-report-1791995250.tar.gz
- Source tree SHA-256: b1629146799b5613b6b885f7470303157c4f0f51799d457e738deb1c21447a53

## Perubahan perilaku

Hasil IDOR disertakan dalam daftar temuan utama dan penghitung Reflection. Proof bertanda tangan terikat run, endpoint, identitas dan trace. Legacy label tanpa proof tidak dipromosikan ketika digabung ulang. Jalankan ulang pengujian atau gunakan New Thread di Studio untuk menghasilkan laporan dengan kode baru.

reduction_percent menyatakan pengurangan nonnegatif. expansion_percent, evidence_overhead_bytes dan size_comparison menyatakan penambahan ukuran akibat metadata. Raw/structured bytes tetap terukur; ini bukan ukuran kompresi konteks LLM.
