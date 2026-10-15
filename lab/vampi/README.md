# Lab VAmPI permanen dan siap pakai

Dipasang pada server SSH `ryrexz@172.31.154.203`, tanggal 15 Oktober 2026 (Asia/Bangkok). Direktori proyek: `/root/projects/adaptix`. Lab API berada di `http://127.0.0.1:18080` dari dalam server.

## Langsung menjalankan pengujian Adaptix

Setelah SSH, masuk sebagai root (`sudo -i`) lalu jalankan:

```sh
cd /root/projects/adaptix
./lab/vampi/labctl run
```

Perintah ini memastikan lab hidup, login dengan dua akun lab yang berbeda, memeriksa identitas melalui `/me`, menyiapkan token dan skenario objek privat, lalu menjalankan Adaptix dengan model lokal. Password/token tidak dicetak. Data lama tidak dihapus. Batas default pengujian: 14.000 token, 300 detik, empat tool-call, enam iterasi. Argumen tambahan CLI dapat diteruskan, misalnya `./lab/vampi/labctl run --token-budget 10000`.

Perintah tersebut sudah diuji dengan model nyata: **scan_completed**, satu temuan IDOR verified, tujuan tercapai, tanpa error, **2.269 token**, dan integritas bundle valid. Run bukti: `artifacts/scans/1bc5a57c5a39/`.

## Mengelola lab

```sh
./lab/vampi/labctl status    # Status container dan autostart
./lab/vampi/labctl start     # Hidupkan lab dan timer token
./lab/vampi/labctl prepare   # Perbarui login dan skenario saja
./lab/vampi/labctl backup    # Snapshot SQLite konsisten + konfigurasi/akun lab
./lab/vampi/labctl stop      # Hentikan lab dan timer
./lab/vampi/setup.sh         # Terapkan ulang setup yang sama, tanpa reset database
```

Setup memeriksa image dan database yang sudah ada, memasang unit systemd, mengaktifkan autostart, lalu menyiapkan login. Unit yang berbeda dari salinan proyek tidak ditimpa diam-diam. Image lokal sudah dipin dan tersedia tanpa perlu pull dari internet.

Layanan `adaptix-vampi.service` dan `adaptix-vampi-refresh.timer` aktif serta enabled. Docker dan layanan SSH yang sudah ada juga enabled. Timer memperbarui token setiap 15 menit; token berlaku satu jam. `labctl run` selalu login kembali sebelum pengujian, sehingga tidak bergantung pada token lama.

**Autostart berlaku ketika lingkungan Linux/WSL dan Docker mulai berjalan.** Komputer Windows tidak direboot dalam pengujian ini; Windows tidak dikonfigurasi untuk menyalakan WSL sendiri. Konfigurasi boot, restart container, dan pembuatan ulang container sudah diperiksa.

## Mengakses API melalui browser komputer sendiri

Jalankan pada terminal komputer sendiri dan biarkan koneksinya terbuka:

```sh
ssh -N -L 18080:127.0.0.1:18080 ryrexz@172.31.154.203
```

Kemudian buka `http://127.0.0.1:18080`. Lab tetap dipublikasikan pada loopback server; tidak dibuka ke seluruh jaringan. Jika port 18080 komputer sendiri sedang digunakan, ganti sisi kiri tunnel menjadi 18081 dan buka port tersebut.

## Lokasi berkas

| Isi | Lokasi di server |
|---|---|
| Compose, helper, unit dan panduan | `/root/projects/adaptix/lab/vampi/` |
| Database permanen | `/root/projects/adaptix/artifacts/labs/vampi/data/database/database.db` |
| Akun lab privat, mode 0600 | `/root/projects/adaptix/artifacts/labs/vampi/accounts.json` |
| Skenario bertoken yang diperbarui | `/root/projects/adaptix/artifacts/labs/vampi/scenarios.json` |
| Target | `/root/projects/adaptix/artifacts/labs/vampi/target.txt` |
| Manifest ownership dan image | `/root/projects/adaptix/artifacts/labs/vampi/manifest.json` |
| Backup | `/root/projects/adaptix/artifacts/labs/vampi/backups/` |
| Pemeriksaan persistensi dan run nyata | `/root/projects/adaptix/artifacts/labs/vampi/verification/` |

Berkas kompatibilitas `artifacts/idor-vampi-target.txt` dan `artifacts/idor-vampi-scenarios.json` juga diperbarui otomatis. Untuk menjalankan instruksi kustom dengan CLI lama, jalankan `labctl prepare` terlebih dahulu. Jangan memasukkan password/token ke instruksi model.

Database di-bind ke penyimpanan host, sehingga pembuatan ulang container tidak menghapusnya. Uji sudah membuat container baru dengan ID berbeda dan membuktikan fingerprint seluruh tabel pengguna/buku tetap sama. Data lama dipertahankan; hanya akun dan objek khusus lab yang ditambahkan. Persiapan ulang terbukti tidak mengubah isi database yang sudah sesuai.

Backup migrasi ada di `artifacts/labs/vampi/backups/migration-20261015-075456/`. `image.tar.gz` menyimpan image lokal untuk pemulihan offline. Snapshot terbaru berawalan `state-` berisi database SQLite konsisten dan `configuration.tar.gz` (konfigurasi serta akun lab). Container lama dipertahankan dalam keadaan berhenti sebagai `vampi-lab-pre-persistent-20261015-075456`. Backup mengandung data/akun lab dan disimpan privat; tidak dimasukkan ke Git.

## Pemeriksaan singkat

```sh
systemctl status adaptix-vampi.service --no-pager
systemctl list-timers adaptix-vampi-refresh.timer --no-pager
docker logs --tail 40 vampi-lab
journalctl -u adaptix-vampi-refresh.service -n 20 --no-pager
```

Jika akun atau kepemilikan objek lab diubah melalui pengujian, persiapan dapat menolak melanjutkan daripada mengganti data secara diam-diam. Periksa log dan data lab sebelum memulihkan snapshot. Endpoint VAmPI `/createdb` mereset database; helper tidak memanggilnya.

Setup ini menambahkan lingkungan lab dan helper; kode inti agent Adaptix tidak diubah. Hasil setup tidak mengubah status penyelesaian Iterasi 7–8.
