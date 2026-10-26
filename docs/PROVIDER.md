# Menggunakan provider lain (base URL + API key)

Adaptix memakai **LiteLLM**, jadi provider apa pun yang punya endpoint
OpenAI-compatible bisa dipakai tanpa mengubah kode. Yang menentukan provider
adalah **prefix model string**.

## Cara tercepat

```bash
cd /root/projects/adaptix
cp .env.example .env          # sekali saja
nano .env                     # isi tiga baris di bawah
```

```dotenv
ADAPTIX_LLM_MODEL=openai/gpt-4o-mini
ADAPTIX_API_BASE=https://api.openai.com/v1
ADAPTIX_API_KEY=sk-...
ADAPTIX_MODEL_CONTEXT_TOKENS=32768
ADAPTIX_LLM_TIMEOUT=120
```

Lalu **selalu** verifikasi dulu sebelum run panjang:

```bash
.venv/bin/python -m src.adaptix.main --check-model
```

Kalau `PASS`, baru jalankan asesmen:

```bash
.venv/bin/python -m src.adaptix.main \
  --target http://127.0.0.1:3000 \
  --instruction "Uji akses kontrol dan injeksi pada target lab" \
  --time-budget 3600 --tool-call-budget 60
```

Atau pakai pembungkus yang melakukan preflight otomatis:

```bash
./scripts/use-provider.sh --verify-only          # cek saja
./scripts/use-provider.sh --target http://127.0.0.1:3000 --time-budget 3600
```

## Tanpa file .env (satu kali jalan)

```bash
ADAPTIX_LLM_MODEL=openai/gpt-4o-mini \
ADAPTIX_API_BASE=https://api.openai.com/v1 \
ADAPTIX_API_KEY=sk-... \
.venv/bin/python -m src.adaptix.main --check-model
```

Variabel environment asli **selalu menang** atas `.env`, jadi override per
perintah aman.

## Contoh provider

| Provider | `ADAPTIX_LLM_MODEL` | `ADAPTIX_API_BASE` |
|---|---|---|
| OpenAI | `openai/gpt-4o-mini` | *(kosongkan)* |
| Anthropic | `anthropic/claude-sonnet-4` | *(kosongkan)* |
| Google | `gemini/gemini-2.5-pro` | *(kosongkan)* |
| OpenRouter | `openrouter/deepseek/deepseek-chat` | `https://openrouter.ai/api/v1` |
| Azure | `azure/<deployment>` | `https://<res>.openai.azure.com` |
| 9router (lokal) | `openai/<model>` | `http://127.0.0.1:20128/v1` |
| vLLM / LM Studio | `openai/<model>` | `http://127.0.0.1:8000/v1` |
| Ollama (lokal) | `ollama_chat/qwen3:14b` | `http://127.0.0.1:11434` |

Untuk gateway OpenAI-compatible, prefix tetap `openai/` dan `api_base` menunjuk
ke gateway — LiteLLM memakai protokol OpenAI ke URL itu.

## Apa yang diperiksa `--check-model`

Satu panggilan murah (satu prompt, tanpa scan, tanpa artefak) yang menjawab lima
kegagalan yang sebelumnya baru ketahuan setelah 40 menit:

| Gejala | Yang dilaporkan |
|---|---|
| Key salah / kedaluwarsa | `AuthenticationError` |
| Base URL salah atau port mati | `ConnectionError` / `InternalServerError` |
| Model id tidak ada | error provider apa adanya |
| Model reasoning menghabiskan budget | `reasoning_content` terisi, `content` kosong |
| Prompt memenuhi window | `headroom_tokens` < 512 |
| Output bukan JSON | "response was not a JSON object" |

Key **selalu di-redact** (`<redacted>`) dari output dan tidak pernah masuk
checkpoint atau laporan.

## Jebakan yang sudah ditangani

**Model reasoning.** Kalau `reasoning_content` panjang tapi `content` kosong
dengan `finish_reason=length`, model menghabiskan kuota untuk berpikir. Naikkan
`ADAPTIX_MODEL_CONTEXT_TOKENS` (bukan cuma `--max-tokens`) atau pakai model
non-reasoning.

**Window terlalu sempit.** Prompt 7.8k di window 8k menyisakan ~390 token,
padahal satu keputusan butuh ~520. Selalu set `ADAPTIX_MODEL_CONTEXT_TOKENS`
sesuai kemampuan asli model (32k+ untuk model hosted).

**Throughput.** Model lokal di hardware ini butuh **>300 detik** untuk satu
keputusan di envelope 8k. Model hosted menjawab dalam 5-15 detik — perbedaannya
bukan IQ, tapi jumlah langkah yang bisa diselesaikan dalam budget. Inilah alasan
utama pindah ke API key.

**Budget "unlimited".** Budget tak terbatas pada provider berbayar ditolak
kecuali Anda menambahkan `--confirm-unlimited-remote`. Ini sengaja: mencegah
tagihan tak terduga.

## Wajib: `--check-model` sebelum run panjang

Satu panggilan murah yang membuktikan provider bisa benar-benar memutuskan. Kalau
`PASS`, baru jalankan asesmen:

```bash
.venv/bin/python -m src.adaptix.main --check-model
```

Perintah ini mengirim **satu request berbentuk planner** memakai skema
`PlannerDecision` yang asli, lalu memeriksa:

- koneksi, autentikasi, dan keberadaan model
- apakah balasan memuat objek JSON yang valid terhadap skema
- apakah model menghabiskan kuota untuk `reasoning_content` (starvation)
- apakah sisa window cukup untuk satu keputusan (`headroom_tokens`)
- apakah provider benar-benar menghormati `max_tokens`

Kegagalan yang dulu baru ketahuan setelah 40 menit sekarang ketahuan dalam
belasan detik.

## Model id butuh prefix provider LiteLLM

Base URL gateway adalah endpoint OpenAI-compatible, jadi prefix-nya `openai/`:

```dotenv
# benar
ADAPTIX_LLM_MODEL=openai/autoapp/minimax-m3
ADAPTIX_API_BASE=http://localhost:20128/v1

# salah - id tidak bisa diresolusi
ADAPTIX_LLM_MODEL=autoapp/minimax-m3
```

Kalau gateway Anda benar-benar menegakkan JSON Schema, tambahkan
`ADAPTIX_NATIVE_JSON=on`. Default-nya `json_object` untuk semua gateway, karena
pengalaman lapangan: gateway **menerima** `json_schema` lalu tidak menegakkan
apa pun, sehingga fallback tidak pernah aktif dan model bebas melanggar skema.

## Model reasoning: matikan, jangan dinaikkan

Model reasoning bisa menghabiskan seluruh kuota outputnya untuk `reasoning_content`
dan mengembalikan `content` kosong. Set:

```dotenv
ADAPTIX_REASONING_EFFORT=none
```

Kalau tetap kosong, itu bukan salah konfigurasi Anda: gateway kadang mengabaikan
setelan ini secara intermiten. Planner akan mengulang dengan allowance kecil
(`ProviderStarvation`) tanpa memotong amplop output dan tanpa memakai jatah retry
Anda. Setiap percobaan tetap dihitung penuh terhadap budget token, jadi
`ADAPTIX_TOKEN_BUDGET` perlu ruang.

## Kalau provider mengabaikan `max_tokens`

Beberapa gateway memotong keras di nilai tetap (mis. 2048) apa pun yang diminta.
`--check-model` memberi peringatan bila completion melebihi permintaan. Planner
menyelamatkan keputusan yang terpotong: aksi yang sudah selesai ditulis tetap
dipakai, bukan dibuang. Yang tidak diselamatkan adalah JSON lengkap yang melanggar
skema — itu tetap ditolak dan diulang, supaya aturan keamanan tidak bisa dilewati.

## Memilih model di gateway

Kalau gateway mengekspos banyak model (9router: 175), ukur dulu. Metode yang
dipakai di sini: ambil prompt planner asli dari checkpoint, kirim N kali ke setiap
kandidat, hitung berapa yang menghasilkan keputusan valid.

Contoh hasil nyata (8 percobaan, prompt 36 KB):

| model | valid | kosong | invalid | rata-rata |
|---|---|---|---|---|
| `openai/autoapp/minimax-m3` | 5/8 | 2 | 1 | 16.5 s |
| `openai/autoapp/glm-5.2` | 1/8 | 7 | 0 | 12.5 s |
| `openai/autoapp/glm-5.3` | 1/4 | 3 | 0 | 11.6 s |

Rute agregator (`autoapp/*`) memilih backend per request, jadi sifatnya bervariasi.
Model yang paling sedikit menghasilkan balasan kosong adalah pilihan terbaik,
bukan yang paling pintar di atas kertas.

## Budget token adalah batas sebenarnya

Prompt planner berukuran ~28 K token per panggilan. Satu retry starvation dihitung
penuh (~30 K). Dengan `ADAPTIX_TOKEN_BUDGET=600000` dan nol temuan, run berhenti
setelah 11 iterasi sementara **1317 detik dari 2100 masih tersisa**. Jika ingin
lebih banyak langkah, naikkan budget token; jika ingin lebih murah, perkecil
payload observasi.


The final report narrative is written by the configured model using only the
run's recorded report JSON. Disable it with `--no-report-model`; findings, evidence and
the deterministic assessment sections are unchanged either way.
