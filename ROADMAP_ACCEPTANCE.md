# Penyelesaian minimum roadmap Iterasi 1-6

Pekerjaan ini melengkapi Iterasi 1-6 pada satu loop adaptif. Iterasi 7 (proof-of-impact dan rollback) serta evaluasi komparatif/paper Iterasi 8 tidak dinyatakan selesai. Environment yang digunakan sesuai arahan operator adalah Linux Conda **base**, bukan environment baru. Scope dinamis tetap terikat signed grant dan target yang dipilih; CLI tidak menggunakan `--authorized`.

## Pemetaan penerimaan

| Iterasi | Implementasi dan bukti penerimaan |
| --- | --- |
| I1 | `AgentState`, satu graph, stop/error/scope paths; `workflow.mmd`; mock dua putaran dan scope denial dalam acceptance runner; checkpoint tersanitasi; regression tests. |
| I2 | Nmap adapter argumen terkontrol, timeout, XML mentah, inventory host/port/service/version/status/timestamp; parser malformed/down/closed/unknown/timeout diuji; fixture lab versioned dan resettable. |
| I3 | Nmap/HTTPX/Nuclei/Playwright; pemrosesan deterministik dan dedup dalam/antar batch dengan endpoint yang berbeda tetap terpisah; raw/structured bytes, jumlah kandidat, error rate, durasi, tool calls; acceptance menggabungkan keluaran tool nyata. |
| I4 | Structured action dan priority, registry/scope gate, pemilihan satu kandidat feasible lalu replan; context/token/time/tool/iteration budgets; cache exact input per run; retry model terukur; provider usage dan reservasi gagal dipisahkan dalam token ledger. Pengembangan pemilihan Nuclei memakai produk Nmap/teknologi HTTPX per origin, trusted tag mapping, native automatic fallback, serta audit pilihan pada state/report. |
| I5 | Candidate/verified/rejected/inconclusive dengan alasan; evidence request/response, expected/actual, langkah, asset, timestamp; signed verification record dengan hash, provenance, dan binding run; HTTP 200 tidak cukup; persetujuan exact action/run/principal untuk capability state-changing dan stop path diuji. |
| I6 | Fallback API runner berbasis HTTPX; dua identitas lab valid dikonfirmasi melalui `/whoami`; private-object ownership dinyatakan dalam ground truth; kasus rentan, protected, dan public; diff status/body, session context dan evidence tersanitasi; lab dapat diulang dan ditutup otomatis. |

## Menjalankan ulang

```sh
cd /root/projects/adaptix
source /root/miniforge3/etc/profile.d/conda.sh
conda activate base
python -m pytest -q
python -m scripts.validate_iterations_1_6 --live-model
```

Runner hanya membuka fixture sementara pada loopback dengan port yang dialokasikan sistem. Ia menjalankan adapter nyata, memeriksa pembatasan POST browser, menguji akses objek rentan/protected/public, membuat signed replay proof, menjalankan mock graph dua putaran dan scope-block path, kemudian menjalankan Qwen pada dua kasus IDOR. Urutan adapter dalam **runner validasi** menguji integrasi; urutan tersebut tidak menjadi pipeline agent produksi. `--live-model` opsional; tanpa flag ini adapter lab tetap nyata, sedangkan model foundation dimock.

Hasil disimpan di `artifacts/scans/acceptance-i1-i6-<timestamp>*`. Setiap bundle mempunyai report, raw output, recon, observations, keputusan, reflection, token ledger, approval audit, run config, evidence index dan checkpoint. Ringkasan acceptance dicetak di akhir. Rekaman mencakup versi tool, Python, model/digest Ollama, generation parameters, snapshot/hash lab, commit dasar dan hash source tree. Perubahan belum di-commit; commit dasar bukan representasi tunggal working tree saat ini.

```sh
python -m src.adaptix.evidence.audit --index artifacts/scans/<run-id>/evidence-index-bd3323c2704f.json
```

Gunakan path index dari output runner, bukan mengganti nama file dengan asumsi. Replay ini memeriksa integritas **tanpa** menjalankan tool/model kembali. Checkpoint adalah rekaman audit tersanitasi, bukan mekanisme otomatis melanjutkan aksi. Verifikasi HMAC dilakukan di worker dengan key lokal; key tidak diekspor.

## Skenario IDOR dari operator

```json
{
  "name": "order-access",
  "base_url": "http://LAB_HOST:LAB_PORT",
  "path_template": "/api/orders/{object_id}",
  "object_id": "42",
  "method": "GET",
  "owner_identity": {"name": "userA", "headers": {"Authorization": "Bearer OWNER_LAB_CREDENTIAL"}},
  "other_identity": {"name": "userB", "headers": {"Authorization": "Bearer OTHER_LAB_CREDENTIAL"}},
  "ground_truth": {"private": true, "identities_valid": true, "owner": "userA", "object_id": "42"}
}
```

Simpan sebagai elemen dalam array JSON. `ground_truth` adalah pernyataan operator berdasarkan lab yang diketahui, bukan kesimpulan model. Akun harus valid dan berbeda, serta objek benar-benar privat dan dimiliki akun owner. Hilangnya ground truth atau penggunaan identitas yang sama tidak menghasilkan `verified`. Respons yang berbeda tidak otomatis membuktikan maupun menolak IDOR. Kredensial disanitasi pada evidence; input skenario dan raw output worker tetap harus diperlakukan sebagai data privat.

```sh
python -m src.adaptix.main --target http://LAB_HOST:LAB_PORT/api/orders/42 \
  --instruction "Uji kontrol akses objek menggunakan dua akun lab, jelaskan bukti, lalu berhenti" \
  --idor-scenarios scenarios.json --planner-retries 1
```

Default model tetap `ollama_chat/qwen3:14b`. CLI mencoba maksimal satu retry tambahan; graph/API dapat mengatur `planner_retry_limit` 0-3. Setiap percobaan dikenai budget. Retry internal provider dimatikan untuk menjaga ledger. Cache hanya menyimpan keputusan yang lolos schema dengan konfigurasi/input yang persis sama, dan semua tindakan tetap divalidasi ulang sebelum eksekusi. Cache tidak menjamin hit pada observation/budget yang berubah dan tidak dibagikan lintas run.

`--model-context-tokens` (default 4096) membatasi konteks setiap keputusan, sedangkan `--token-budget` membatasi akumulasi token run. Batas konteks juga diterima graph/API sebagai `model_context_tokens`; konteks terlalu kecil menghentikan run sebelum memanggil provider. `--temperature` (default 0.2) direkam bersama parameter generasi. Setelah dua putaran berturut-turut tanpa kandidat yang dapat dieksekusi, run berhenti dengan `policy_rejections_exhausted` dan status `completed_partial`. Graph/API dapat mengatur `policy_replan_limit`. Aksi yang berhasil mereset hitungan; satu penolakan tetap memberi kesempatan model memperbaiki keputusan. Hasil tool tersimpan dievaluasi dalam reflection; evaluasi tidak membutuhkan pengulangan tool.

## Mode manual Burp / Postman

Adapter otomatis Burp dan importer koleksi Postman belum tersedia. Pengujian API yang dapat diulang memakai runner HTTPX dua identitas. Untuk review manual, operator dapat menjalankan fixture loopback dengan `FixtureLab`, memasukkan URL/port yang dicetak ke scope Burp, lalu mereplay GET objek yang sama menggunakan akun owner dan other melalui Repeater atau Postman. Ambil kedua request/response, waktu, endpoint, identitas, hash body, expected/actual behavior, serta referensi snapshot ground truth. Jangan memasukkan kredensial ke planner atau menyimpulkan IDOR dari HTTP 200 saja.

Gunakan tiga kontrol fixture: `/vulnerable/orders/42` menghasilkan akses privat oleh non-owner; `/protected/orders/42` menolak akun other; `/public/orders/42` adalah data publik dan tidak boleh diklaim sebagai IDOR. Simpan review sebagai `verification_method=manual_review` dengan reviewer, alasan, trace lengkap, dan result yang diperiksa operator. Interface worker `write_verification_record` menandatangani record sesuai run; `valid_proof` menolak hash, signature, atau run yang berbeda. Ini merupakan mode review manual, bukan klaim integrasi otomatis Burp/Postman.

## Policy dan batas implementasi

Registry menyatakan risiko operasi; model tidak bisa menyatakan sendiri bahwa aksi berisiko rendah. Capability `risk=state_change` berhenti dengan `human_approval_required` jika tidak ada izin manusia bertanda tangan yang sesuai run, principal, tool, target, TTL, dan change limit. Izin scope otomatis CLI tidak membuat persetujuan perubahan state. Interface issuer lokal: `python -m src.adaptix.security.action_policy --help`; CLI mendukung `--run-id` dan `--action-approval` untuk binding tepat. Handler masa depan harus menegakkan change limit; gate ini tidak menciptakan handler eksploitasi.

Browser observer membatasi request HTTP ke GET/HEAD dan scope yang diizinkan; POST dari skrip halaman diuji agar diblokir. IDOR menggunakan GET dan mereservasi dua request. Nuclei memilih template HTTP sesuai teknologi dengan discovery terbatas dalam snapshot terisolasi. Semua mode memakai manifest isi dan gate risiko; template aktif memerlukan izin persis SHA256 manifest dan `execute_manifest_once`. Subset observasi/cakupan parsial tercatat. Baseline dan katalog HTTP penuh dapat dikonfigurasi, tetapi katalog penuh tidak memberi izin otomatis template aktif. Verifier otomatis tersedia untuk akses objek privat; temuan lain memerlukan proof/review bertanda tangan dengan trace lengkap. HTTP status/severity/label tidak mengesahkan temuan.

Metrik raw/structured mengukur bytes output yang disimpan dan representasi state, bukan seluruh paket jaringan. Metadata evidence dapat menambah ukuran state. `tool_error_rate` adalah proporsi invocation outcomes yang mencatat kegagalan. Provider-reported tokens dipisahkan dari conservative reservation; estimasi context bytes tidak dipresentasikan sebagai billing token aktual. Touched scope berarti tindakan pernah dicoba, bukan semua vulnerability telah diperiksa. Bukti acceptance bukan benchmark efektivitas penelitian atau jaminan kesempurnaan.

## Dependency lock dan commit

`requirements.lock` sekarang hanya mencakup dependency closure proyek + test + LangGraph dev, dipin dari Linux base. Tidak berisi path build Conda lokal atau seluruh paket base. Untuk Python/platform lain, buat environment yang sesuai dan regenerasikan dengan `python -m scripts.lock_dependencies`. Lockfile ini mengunci versi, bukan digest wheel/model.

```sh
git diff --check
git diff --stat
git add src tests scripts lab pyproject.toml requirements.lock workflow.mmd \
  config/scope.yaml .gitignore INTEGRATION.md ADAPTIVE_AUDIT.md ROADMAP_ACCEPTANCE.md
git diff --cached --stat
git commit -m "Complete iteration 1-6 acceptance evidence and regression coverage"
```

Perintah commit di atas adalah panduan untuk operator; belum dijalankan. Periksa staged diff sebelum commit. Jangan stage `.env`, signing key, credentials, artifacts, atau `benchmarks/` yang merupakan pekerjaan sebelumnya. Tidak ada push GitHub. Backup sebelum perubahan ini tersedia di `/root/adaptix-backups/pre-i1-i6-completion-1791982582.tar.gz`.


## Konsistensi pelaporan IDOR

Hasil native IDOR sekarang masuk ke `verified_findings`, `rejected_findings`, atau `inconclusive_findings` dan penghitung Reflection. Tool menulis proof bertanda tangan yang terikat run; ringkasan memvalidasi signature, hash, endpoint, identitas dan hasil replay. Label `verified`, HTTP 200, atau `fixture_validated` tanpa proof tidak cukup. Hasil detail tetap tersedia di `idor_findings`. Bukti dari versi sebelum pembaruan ini tidak diubah; jalankan ulang pengujian untuk menghasilkan proof dan ringkasan baru.

Hasil native dan kandidat replay untuk endpoint serta pasangan identitas yang sama dihitung sekali. Template kerentanan lain serta pasangan identitas berbeda tetap terpisah. Penggabungan dihitung ulang setiap putaran tanpa menambahkan duplikat. Final report dan evidence bundle memakai klasifikasi yang sama.

## Perbaikan fokus produk, 2026-10-15

Temuan F1–F6 ditangani dalam `PRODUCT_FOCUS_FIX.md`: bukti terbaru sebelum pemadatan konteks, pengulangan Nuclei hanya jika profil relevan berubah, gate manifest, kemajuan sesuai tujuan/manfaat per token, refleksi terstruktur yang digrounding, dan acceptance yang menerima hasil adaptif tanpa match secara sah. Runner tidak mengharuskan kandidat/rejected Nuclei baseline pada mode adaptive. Raw/structured bytes tetap diukur tanpa memaksa kompresi.

Uji model nyata untuk link runtime, pilihan HTTPX/Playwright, IDOR privat, dan kredensial gagal dipisahkan dari acceptance adapter deterministik. Bukti tersebut berlaku pada skenario yang diuji. Iterasi 7 dan evaluasi komparatif Iterasi 8 tetap belum dinyatakan selesai; remediasi tidak menggantikan proof-of-impact/rollback maupun benchmark penelitian.

`reduction_percent` kini mencatat pengurangan ukuran yang bernilai nonnegatif. Jika metadata membuat bukti lebih besar, `expansion_percent`, `evidence_overhead_bytes` dan `size_comparison=expanded` menunjukkan penambahannya. Raw/structured bytes tetap nilai terukur. Persentase bernilai 0 ketika raw kosong; `size_comparison=no_raw_output` menandai bahwa rasio tidak dapat dihitung. Ini tidak mengukur kompresi konteks model atau seluruh paket jaringan.
