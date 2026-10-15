# Cakupan Nmap dan Nuclei

Default `limits` di `config/scope.yaml`:

```yaml
nmap_ports: 'all'
nmap_timeout_seconds: 900
nuclei_templates: 'adaptive'
nuclei_timeout_seconds: 7200
```

Nmap mencoba **65.535 port TCP** melalui `-p 1-65535` pada host dalam scope. UDP tidak termasuk. Discovery tidak mengetahui port yang cocok dengan lab sebelumnya. Rentang tersebut adalah konfigurasi pemeriksaan, bukan daftar port terbuka; inventory berisi hasil observasi. Daftar port diringkas sebagai rentang dalam konteks model. Daftar/rentang khusus seperti `'22,80,443,8000-9000'` juga didukung. Timeout scanner dibatasi sisa budget run.

## Pemilihan teknologi

Mode `adaptive` menggunakan produk Nmap dan teknologi/webserver HTTPX pada origin yang dipilih, bukan nomor port saja. WordPress + Nginx menghasilkan profil `nginx,wordpress,wp` untuk template HTTP. Alias dipercaya berasal dari `config/nuclei.yaml`; teks observasi tidak langsung menjadi argumen. Bukti origin lain tidak ikut memilih template. Versi dinormalisasi untuk pencocokan produk; ini belum merupakan pencocokan rentang versi CVE.

Jika teknologi belum dikenal, discovery dibatasi dua seed resmi yang dikonfigurasi: `http/technologies/tech-detect.yaml` dan `http/technologies/favicon-detect.yaml`. Native automatic HTTP dijalankan dalam katalog snapshot terisolasi; `-as` tidak bisa menambahkan katalog terpasang. Matcher teknologi yang ada dalam peta alias dimasukkan kembali ke observasi HTTP. Profil relevan yang berubah mengizinkan scan baru pada URL yang sama; profil identik tetap diblokir. Discovery tanpa match adalah hasil sah, bukan bukti bebas kerentanan.

## Manifest dan izin template

Sebelum request, controller memeriksa isi dan SHA256 template lalu menyimpan artifact `nuclei-manifest`. Eksekusi memakai salinan byte persis melalui `-ud`, `-t`, konfigurasi kosong, dan `-ni`. Perubahan isi setelah persetujuan ditolak. Redirect/retry dimatikan. Katalog rumah dan konfigurasi pengguna tidak menjadi sumber template tambahan.

Template observasi otomatis harus memenuhi pemeriksaan konservatif: kelas observasi dikenal, GET/HEAD statis pada origin pilihan, tanpa body/raw/payload/flow/protokol tambahan, override identitas, atau OAST. Allowlist hash dapat memuat template yang direview operator; metode aktif tetap digate. Label GET sendiri bukan jaminan semua semantik endpoint bebas efek.

Template aktif, kelas vulnerability/intrusive, atau isi yang tidak bisa diperiksa memerlukan izin bertanda tangan yang mengikat run, principal, target, SHA256 manifest, TTL, dan `execute_manifest_once`. Campuran template dapat menjalankan subset observasi dahulu; report menyatakan `observation_subset` dan cakupan parsial. Jika semuanya digate, run berhenti `human_approval_required` dengan `manifest_ref`. Izin scope tidak menggantikan izin template aktif.

Sesudah mereview manifest, operator dapat menerbitkan izin lokal:

```sh
python -m src.adaptix.security.action_policy \
  --run-id RUN_ID --principal OPERATOR --tool nuclei --target EXACT_URL \
  --change-limit execute_manifest_once --manifest-sha256 EXACT_MANIFEST_SHA256 \
  --ttl-seconds 300
```

CLI menerima `--run-id`, `--principal`, dan `--action-approval PATH`. Model/API tidak menerbitkan izin. Satu izin berlaku sekali eksekusi daftar template, termasuk jika caller membersihkan attempted actions; bukan batas satu request. Perubahan template memerlukan manifest/izin baru. Timeout juga dibatasi TTL izin.

## Mode dan batas hasil

`adaptive` memilih sesuai teknologi. `default` membuat manifest katalog HTTP terpasang tanpa filter teknologi; gate isi/risiko tetap berlaku. `baseline` memilih template reachability proyek. Daftar path lokal juga didukung:

```yaml
nuclei_templates:
  - /root/nuclei-templates/http/exposures
  - /root/projects/adaptix/templates/http-response.yaml
```

Engine masih dapat mengecualikan file karena kompatibilitas/aturan native. `selected_count` dan `executable_count` menghitung file manifest, bukan menjamin setiap request berjalan. Setiap origin memiliki invocation dan budget terpisah. `nuclei_template_selections` merekam strategi, tags, coverage, status, jumlah template digate, dan referensi manifest.

Match tetap `candidate_unverified`; HTTP 200/severity bukan bukti kerentanan. Baseline mencocokkan endpoint persis; mode lain dapat menemukan path lain pada origin yang sama. Hasil host/port/scheme lain ditolak. Verifier terpisah atau review dengan proof autentik diperlukan untuk verified.

Rate/concurrency berasal dari scope config. Katalog besar dapat menghabiskan waktu; timeout menghasilkan hasil parsial. Baris JSONL lengkap tetap disimpan. Pembaruan katalog dilakukan terpisah; run memakai `-duc`. Konfigurasi luas tidak memaksa semua tool berjalan: planner memilih berdasarkan tujuan, bukti, manfaat per token, dan budget. Lihat `PRODUCT_FOCUS_FIX.md` untuk pengujian perbaikan.
