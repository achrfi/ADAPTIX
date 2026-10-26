# Audit penyebab tidak adanya temuan XSS terverifikasi

Audit dilakukan pada source dan laporan yang sudah tersimpan. Tidak ada koneksi
ke target, pemanggilan model, atau reproduksi eksploit pada audit ini. Source
produksi, policy, dan bukti lama tidak diubah. Inventaris source beserta hash
ada di `source-inventory.json`; metadata laporan di `run-metadata.json`.
Inventaris mencakup 132 file source/config/test/dokumen, termasuk 115 file Python
yang semuanya lolos parsing AST. Review manual berfokus pada routing CLI,
discovery, planner, policy scanner, kontrak bukti, koleksi kandidat, dan laporan;
ini bukan klaim review manual setiap baris atau pemeriksaan CVE dependensi.

## Kesimpulan utama

Run terbaru membuktikan recon dan ringkasan AI berjalan, **bukan bahwa aplikasi
sudah diuji terhadap XSS**. `main --local-recon` keluar melalui workflow
inventaris sebelum graph pentest adaptif. Jalur impor JSON ffuf juga merupakan
review-only. Keduanya tidak menghasilkan bukti validasi kerentanan. Tidak adanya
temuan pada mode ini berarti **belum diuji**, bukan **tidak rentan**.

Implementasi recon dan review tersebut memang ditambahkan pada pekerjaan
sebelumnya dengan batas ini. Angka sukses ffuf/Playwright/model dan jumlah tes
yang lulus tidak boleh dibaca sebagai keberhasilan pendeteksian XSS pada lab.

## Temuan prioritas

| ID | Prioritas | Temuan | Dampak dan bukti |
| --- | --- | --- | --- |
| D01 | P1: ekspektasi hasil | `--local-recon` tidak memasuki graph assessment | `main.py:91` langsung mendelegasikan ke CLI inventaris dan mengembalikan hasilnya. Graph di `local_inventory/workflow.py` hanya berisi ffuf, browser discovery, merge, summary, dan laporan. Tidak ada tahap verifikasi kerentanan. Ini penyebab langsung untuk run terbaru. |
| D02 | P1: review data, bukan pengujian | Impor ffuf menonaktifkan alat | `processing/ffuf.py:133` mengaktifkan review-only serta menonaktifkan baseline/scanner. `workflow/nodes.py:91` menolak eksekusi alat dalam mode itu; planner memakai katalog kosong dan `actions=[]`. Run impor nyata mempunyai enam observasi, satu panggilan AI, nol tool-call, nol kandidat, dan nol trace probe. |
| D03 | P1: kehilangan integritas bukti | Hasil browser yang inconclusive dapat menghapus kandidat lama | Pada `tools/playwright.py:326`, kondisi hasil yang tidak konklusif mengembalikan `candidates=[]`, termasuk ketika state sebelumnya sudah mempunyai kandidat. Batas eksekusi di `workflow/nodes.py:217` tidak menggabungkan kembali koleksi kandidat. Ini temuan statis tentang kemungkinan kehilangan data; tidak menjadi penyebab run recon yang memang tidak menjalankan `browser_test`. |
| D04 | P1: makna verified tidak konsisten | Istilah verifikasi independen berbeda antar jalur | `tools/nuclei.py:333` memberi `verification_method=nuclei_template_match`, `independently_verified=True`, dan status verified. `evidence/verification.py:206` memperlakukan kontrak itu sebagai confirmed tanpa evaluasi browser/replay terpisah. Nuclei memang mengevaluasi matcher secara independen dari pendapat model, tetapi itu bukan jenis bukti yang sama dengan validasi browser XSS. Label membutuhkan definisi yang konsisten; audit ini tidak menyatakan semua hasil Nuclei salah. |
| D05 | P2: jalur bukti tidak terlihat digunakan | Tidak ada aksi `browser_test` dalam laporan yang diperiksa | Rekap 3.073 file laporan memperlihatkan nol aksi `browser_test` dan tidak ada metering tool bernama itu. Jalur XSS independen di kode memerlukan bukti browser tersebut. Ini menunjukkan tidak tersedianya bukti eksekusi jalur itu dalam laporan yang diaudit; bukan bukti bahwa seluruh aplikasi bebas XSS. |
| D06 | P2: cakupan XSS terbatas | Kontrak browser bukan verifikator universal semua XSS | `CATEGORY_BASIS` di `evidence/verification.py:296` memetakan XSS ke kontrak browser-execution. Evaluator di baris 110 memeriksa jenis bukti eksekusi tertentu serta kontrol pembanding. Refleksi string/markup saja tetap inconclusive. Kategori yang memerlukan autentikasi, interaksi, penyimpanan, atau state aplikasi lain tidak terbukti hanya dari inventaris URL. |
| D07 | P2: pemetaan SPA bukan pengujian perilaku | Observer tidak menguji input aplikasi | `local_inventory/discovery.py:21` menghapus query/fragment dari URL inventaris. Route hash SPA dicatat terpisah; form dicatat sebagai `submitted=False`. Membaca DOM, link, screenshot, dan jaringan tidak membuktikan bagaimana input berbahaya diproses. |
| D08 | P2: sukses proses berbeda dari cakupan | Kriteria acceptance hanya menyelesaikan inventaris terbatas | `local_inventory/workflow.py:90` memeriksa respons root browser; baris 108 menilai status ffuf/browser/acceptance/AI. Schema laporannya tidak mempunyai hasil assessment XSS. HTTP 200, endpoint banyak, atau AI summary yang berhasil tidak memenuhi kontrak bukti kerentanan. |
| D09 | P2: keterbatasan pengetahuan model | AI hanya menerima sampel metadata | `local_inventory/workflow.py:25` mengirim sampai 32 detail endpoint tanpa body, query value, cookie, atau sesi. Mode impor menyampel delapan observasi. Model pada mode ini dirancang merangkum, bukan memvalidasi JavaScript atau alur aplikasi. |
| D10 | P2: validasi tes terbatas | Tes regresi tidak sama dengan discovery vulnerability end-to-end | `tests/test_adaptix_pipeline.py` secara eksplisit memakai scanner/model mock; `tests/conftest.py` mengganti tokenizer. Tes kontrak browser juga memeriksa trace fixture yang sudah disiapkan. Tes itu berguna untuk konsistensi program, tetapi tidak membuktikan model menemukan seluruh XSS nyata pada lab. |

P1 di atas menunjukkan prioritas untuk kejelasan hasil dan integritas data
proyek; bukan skor CVSS atau klaim adanya eksploit terhadap aplikasi target.

## Apa yang benar-benar terjadi pada run yang sudah divalidasi

| Bukti run | Hasil proses | Yang dibuktikan | Yang belum dibuktikan |
| --- | --- | --- | --- |
| `work/local-recon-runs/reference-live-20261024/report.json` | Success; 4.750 input ffuf, 10 halaman, 78 request, 86 catatan/72 respons | Inventaris lokal dan ringkasan AI selesai dalam batas run | Assessment atau validasi XSS/SQLi/kerentanan lain |
| `work/local-recon-runs/main-entry-check-20261024/report.json` | Success; smoke test 8 input, 2 halaman, 41 request, 35 respons | Routing entrypoint main ke recon bekerja | Penemuan kerentanan dari alur main adaptif |
| `work/ffuf-import-runs/20261023T155531Z-659e19/.../report-845e91831319.json` | Completed partial; 6 observasi impor, 1 panggilan model, 0 alat | JSON operator masuk ke state, observasi, dan laporan | Request pengujian atau verifikasi ke target |

Laporan inventaris bahkan tidak memiliki field `verified_findings`. Karena itu
hasilnya tidak semestinya diinterpretasikan sebagai pengukuran "nol kerentanan";
assessment memang tidak dilakukan oleh schema/workflow tersebut.

## Jalur pentest lama: hal yang membatasi interpretasi

Graph adaptif terpisah masih ada di `workflow/graph.py`, dengan baseline,
scanner, planner, eksekusi, dan verifikasi. Keberadaan kapabilitas di source
tidak berarti kapabilitas tersebut dipilih atau dijalankan pada sebuah run.

Policy Nuclei memilih family/template, memerlukan evaluasi kebijakan eksekusi,
dan mencatat batas waktu serta batas jumlah template. Konfigurasi default
scanner memakai mode adaptive. Katalog yang dipilih dan subset yang benar-benar
dieksekusi dapat berbeda. Hanya membaca nama tag `xss` di konfigurasi tidak
membuktikan bahwa pengujian XSS yang relevan pernah terjadi.

File `templates/http-response.yaml` secara eksplisit merupakan reachability
baseline, severity info, dengan matcher HTTP 200. Ia tidak mendeteksi kerentanan.
Temuan candidate yang tidak mempunyai bukti pendukung harus tetap inconclusive;
status HTTP dan severity bukan pengganti bukti.

Kontrak XSS yang lebih ketat mencegah refleksi biasa dilaporkan otomatis sebagai
XSS confirmed. Ini batas bukti yang benar. Keterbatasan cakupannya perlu
ditampilkan secara jujur; mengurangi tuntutan bukti hanya akan mengubah label,
bukan menghasilkan validasi yang lebih sah.

## Riwayat laporan: tidak semuanya kosong, tetapi bukan kumpulan bukti independen

Metadata 3.073 file laporan diperiksa. Dua adalah inventaris lokal dan dua
adalah review impor. Ada 56 file yang melaporkan setidaknya satu verified finding.
Rekap label tersimpan mencakup 18 BOLA/IDOR, satu SQL injection, 32
`potential_vulnerability`, dan tujuh tanpa kelas. Ini total kemunculan label
lintas file, **bukan jumlah kerentanan unik atau hasil yang diverifikasi ulang**.

Metode yang tertulis mencakup 34 match Nuclei, 17 deterministic replay, dan
tujuh tidak ditentukan. Sebagian artefak berasal dari fixture, mock, benchmark,
atau versi kode sebelumnya. Tidak ada label kelas XSS atau nama template XSS
pada subset verified yang direkap. Label umum `potential_vulnerability` juga
mengurangi ketepatan klasifikasi per kategori.

Stop reason yang sering tercatat: `no_new_actions` (1.565),
`policy_rejections_exhausted` (423), `context_budget_exhausted` (216),
`budget_exhausted` (211), `planning_failure_no_decision` (209), dan
`planner_unavailable` (165). Semua itu adalah keadaan eksekusi/perencanaan,
bukan hasil negatif bahwa XSS tidak ada. Kejadian tertentu harus dikaitkan
dengan run ID, versi source, dan artefak buktinya sebelum ditarik kesimpulan.

## Temuan proyek lain yang tetap relevan

Audit sebelumnya juga mencatat field opsi provider CLI yang tidak diteruskan
oleh schema graph, konsumsi approval sekali pakai yang belum ditegakkan,
penampungan output subprocess sebelum pemotongan, dan limiter yang belum
seragam lintas adapter. Detailnya ada pada bagian temuan awal `writeup.md`.
Hal-hal itu perlu diperlakukan sebagai isu proyek tersendiri, bukan dianggap
sebagai bukti bahwa run inventaris terbaru sudah mencoba dan gagal menguji XSS.

## Tindak lanjut yang tepat untuk mutu audit

1. Pisahkan status inventaris, status pengujian per kelas, dan status bukti.
   Kategori yang tidak diuji harus tercatat `not_tested`, bukan `not_vulnerable`.
2. Pertahankan ledger bukti dan kandidat ketika hasil lanjutan inconclusive;
   kehilangan data tidak boleh terlihat seperti tidak adanya temuan.
3. Bedakan `scanner_matched` dari bukti yang benar-benar diverifikasi independen.
4. Catat coverage dan alasan tidak diuji untuk setiap kelas, termasuk saat budget,
   scope, policy, prasyarat identitas, atau provider menghalangi pengumpulan bukti.
5. Ukur kualitas laporan terhadap fixture yang diketahui statusnya dan review
   bukti operator. Jumlah tes hijau atau banyaknya endpoint bukan ukuran recall
   deteksi kerentanan pada aplikasi lain.

Audit ini tidak menambahkan payload, melemahkan policy/kontrak bukti, atau
menyambungkan discovery ke eksekusi ofensif otonom. Ia menjelaskan kondisi kode
dan bukti yang tersedia. Status keamanan aplikasi target tetap belum dapat
disimpulkan dari dua run recon dan satu run review yang dibahas.
