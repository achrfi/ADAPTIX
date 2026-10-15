# ADAPTIX — Perbaikan audit dan verifikasi ulang

Tanggal: 15 Oktober 2026, Asia/Bangkok. Implementasi: `/root/projects/adaptix`, Linux Conda base. Model nyata: `ollama_chat/qwen3:14b`, temperature 0,2. Perubahan diterapkan pada working tree yang sudah ada dengan backup per langkah; tidak ada commit/push. Referensi tersinkron di `sources/` tidak diedit.

## Hasil

**Enam temuan fungsional audit F1–F6 telah diperbaiki dan diuji ulang.** 159 passed in 30.82s. Acceptance adapter default adaptive, uji kebijakan Nuclei, uji teknologi-ke-template dengan mesin asli, serta empat skenario model nyata lulus. Layanan LangGraph telah memuat versi baru; health dan penolakan scope melalui API lulus, PID 45413.

Ini mendukung fokus adaptive, self-reflective, dan manfaat per token pada skenario yang diuji. Hasil bukan jaminan optimalitas global atau cakupan semua aplikasi. Iterasi 7 dan evaluasi penelitian Iterasi 8 belum dinyatakan selesai.

## Penutupan temuan

| Temuan | Perbaikan | Bukti penerimaan |
|---|---|---|
| F1 — bukti terbaru terpotong | Hilangkan batas first-64/first-32; prioritaskan delta terbaru dan target aktif sebelum compaction. Projection dan evidence ID konsisten; bukti lengkap tetap di artifact. | Uji 91 HTTP/kandidat dan 51 browser: bukti terbaru terlihat saat konteks dipadatkan; data sumber tidak diubah. |
| F2 — profil Nuclei baru diblokir | Execution identity memakai tag/strategi/policy, hash file eksplisit, dan revisi index katalog. Profil identik diblokir; teknologi relevan baru diizinkan dalam budget. | Graph Nuclei → HTTPX menemukan WordPress → Nuclei pada URL sama. Mesin asli membuktikan discovery Nginx → state teknologi → template Nginx pada URL sama; Jenkins tidak dijalankan. |
| F3 — semua Nuclei dianggap observe | Klasifikasi isi per template; manifest SHA256, snapshot byte persis, katalog terisolasi, gate template aktif dan izin sekali pakai. | POST lab tanpa izin = 0 request; izin exact manifest = 1 POST; replay dan perubahan isi ditolak. Metadata katalog rumah tidak berubah. |
| F4 — record baru disamakan dengan manfaat | Feedback kemajuan mengikuti tujuan dan proof autentik. Ranking memakai expected progress per 1.000 token, dikalibrasi hasil aktual serta tekanan waktu/request. Biaya marginal memakai tokenizer pada projection model. | Bukti IDOR rentan/protected bernilai 1,0; public/kredensial gagal 0,1; pengulangan ketidakpastian tidak menambah progress. HTTP 401 bernilai sesuai tujuan, bukan otomatis berhasil. Blob yang tidak masuk prompt tidak dibebankan sebagai estimasi konteks. |
| F5 — refleksi hanya teks | Trim/larang whitespace; review terstruktur; referensi diperiksa dan pencapaian digrounding ke bukti tujuan. Feedback koreksi konkret; klaim yang ditolak tidak diteruskan sebagai fakta. Schema native pada Ollama chat. | Klaim keberhasilan palsu diblokir sebelum tool; replan korektif diuji. Model nyata mengikuti link runtime dan melaporkan kredensial gagal sebagai inconclusive/partial, tanpa temuan palsu. |
| F6 — acceptance mengharuskan baseline match | Validasi eksekusi/selection/scope, bukan memaksa match. No-match adaptive diterima jika memang sah; raw/structured bytes diukur tanpa memaksa rasio kompresi. | Acceptance default adaptive lulus dengan Nmap, HTTPX, Nuclei, browser, kontrol IDOR, signature/replay proof, reset/cleanup, dan integritas bundle. |

## Model dan tool nyata

| Skenario | Hasil | Token provider total | Detik | Status report |
|---|---|---:|---:|---|
| dynamic-browser | Lulus | 3,713 | 126.08 | scan_completed |
| cost-choice | Lulus | 2,260 | 107.74 | scan_completed |
| idor-private | Lulus | 3,088 | 115.54 | scan_completed |
| idor-expired | Lulus | 2,778 | 93.35 | completed_partial |

Dynamic-browser memakai path acak yang tidak diberikan dalam instruksi. Agent membuka halaman sumber lalu mengunjungi link yang diamati dan membaca judul tujuan. Cost-choice benar-benar membandingkan kandidat HTTPX/Playwright dan memilih HTTPX untuk status/judul. IDOR privat menghasilkan satu proof terverifikasi; kredensial kedaluwarsa tidak dianggap bukti akses privat.

Setiap run dibatasi 14.000 token, 300 detik, lima tool-call, dan enam pass. Seluruh ledger sama dengan jumlah usage provider, setiap keputusan yang diterima mempunyai review model terstruktur, referensi akhir valid, dan semua bundle lolos integritas. Pada run final terdapat 1 percobaan schema gagal dan 0 review semantik ditolak sebelum koreksi/stop. Model memakai konteks penutup lebih kecil ketika bukti tujuan sudah cukup (3 kasus); refleksi model tetap dilakukan.

### Token sebelum dan sesudah

| Kasus sejenis | Audit awal | Verifikasi akhir | Perubahan relatif |
|---|---:|---:|---:|
| dynamic-browser | 5,365 | 3,713 | 30.8% |
| cost-choice | 3,360 | 2,260 | 32.7% |
| idor-private | 3,224 | 3,088 | 4.2% |

Persentase positif berarti token lebih sedikit. Ini perbandingan deskriptif satu run per versi dengan port/path fixture acak dan sampling model; **bukan** benchmark berpasangan, ablation refleksi, atau bukti peningkatan kausal. Penggunaan token aktual harus dibedakan dari estimasi biaya marginal, bytes raw/structured, dan jumlah template. Kasus kredensial kedaluwarsa adalah tambahan tanpa baseline audit awal.

## Ketepatan pengujian dan deployment

Kode `.py/.yaml/.yml` pada `src`, `config`, `scripts`, dan `lab` tetap identik sepanjang uji model dan saat paket bukti dibuat. SHA256 gabungan: `690f72c45f67da85669d939d2500b8d02e57c07ed707d70427f44311a9ed66fb`. Hash per file tersedia di `source-hashes.json`; tests dan dokumen dilampirkan dalam patch. Pemeriksaan whitespace lulus dengan `cr-at-eol` karena file hasil edit Windows memakai CRLF; pemeriksaan trailing spaces/blank EOF tetap aktif. Hasil default yang menandai CR serta hasil CRLF-aware dicatat terpisah.

Uji regresi memock batas model/scanner agar kasus negatif dapat direproduksi. Acceptance dan integration menjalankan scanner/tool asli di fixture loopback. Empat run model memakai Qwen/Ollama asli. Pemeriksaan API sesudah restart memvalidasi graph aktif dan penolakan scope tanpa memanggil model/tool eksternal. Tidak ada scan produksi atau perubahan data aplikasi di luar fixture.

Saat pengembangan, uji nyata sempat menemukan kolom keputusan penutup kosong, koreksi keberhasilan navigasi yang terlalu umum, dan false positive OAST pada matcher discovery resmi. Instruksi/schema, feedback, serta klasifikasi diperbaiki sebelum run final. Satu assertion fixture kemudian diperbaiki agar memeriksa Nginx yang benar-benar dideteksi, bukan mengasumsikan WordPress. Rekaman percobaan lama tetap disimpan di server; paket verified berisi hasil akhir yang lulus.

## Perilaku yang perlu diketahui

- Nmap default tetap mencoba seluruh 65.535 port TCP pada host dalam scope. Angka konfigurasi tersebut bukan daftar port terbuka; UDP tidak termasuk. Acceptance ulang memakai port fixture, bukan mengulangi seluruh-port scan.
- Nuclei memilih dari katalog HTTP sesuai teknologi. Discovery awal dibatasi seed resmi. Template aktif tidak otomatis berjalan: operator mereview manifest exact dan menerbitkan izin `execute_manifest_once`. Tanpa izin, subset observasi/cakupan parsial dilaporkan atau run menunggu persetujuan.
- Izin terikat run/principal/target/manifest/TTL dan berlaku satu invocation manifest. Ini bukan batas satu request. Engine masih dapat mengecualikan file native; jumlah file executable bukan jaminan semua request dijalankan.
- GET/HEAD statis dan kelas observasi adalah kebijakan konservatif, bukan bukti bahwa setiap endpoint GET bebas efek. Perubahan katalog lokal manual tanpa memperbarui index tidak dijamin mengubah identitas katalog; daftar file eksplisit memakai hash isi.
- Review legacy tanpa objek typed tetap kompatibel dan diberi label controller-grounded. Model default Ollama chat wajib mengikuti schema typed. Klasifikasi tujuan otomatis mencakup navigasi, observasi layanan, otorisasi, dan penilaian keamanan umum; tujuan khusus dapat memakai `objective_kind` yang didukung. Ini belum pembukti semantik universal atas seluruh instruksi bebas.
- `scan_completed` menyatakan run selesai; lihat juga `objective_status`, coverage, temuan, errors dan stop_reason. Temuan Nuclei tetap unverified sampai ada proof terpisah. Token/cost diprioritaskan dengan heuristik manfaat, bukan memilih aksi termurah tanpa mempertimbangkan dampak.
- Belum ada autentikasi/refresh token umum untuk semua API, proof-of-impact/rollback umum, atau evaluasi lintas model dan baseline dengan pengulangan statistik. Itu tetap pekerjaan lanjutan I7/I8.

## Bukti dan pengulangan

Bukti final server: `/root/projects/adaptix/artifacts/remediation/20261015/verified/`. Backup awal remediasi: `artifacts/backups/product-focus-fix-20261015-010615.tar.gz`, ditambah backup per langkah. Tidak perlu restore seluruh proyek untuk membatalkan perubahan; review path yang hendak dikembalikan.

Perintah regresi dan acceptance:

```sh
cd /root/projects/adaptix
LITELLM_LOCAL_MODEL_COST_MAP=True /root/miniforge3/bin/python -m pytest -q
LITELLM_LOCAL_MODEL_COST_MAP=True /root/miniforge3/bin/python -m scripts.validate_iterations_1_6
```

Harness model dan integration, parameter generation, keputusan/refleksi, ledger, manifest/selection, hash, log serta bundle terpilih tersedia dalam `ADAPTIX_FIX_EVIDENCE_20261015.zip`. Signing key dan kredensial pengguna tidak disertakan. `ADAPTIX_FIX_PATCH_20261015.zip` berisi hanya perubahan terhadap snapshot sebelum remediasi; perubahan pengguna yang sudah ada sebelumnya tidak dijadikan patch baru.
