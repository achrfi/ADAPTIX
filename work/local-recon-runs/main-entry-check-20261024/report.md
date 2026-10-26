# Local recon inventory

Status: success

| Stage | Status |
| --- | --- |
| ffuf | success |
| playwright | success |
| acceptance | success |
| ai | success |

HTTP status alone is not proof of a distinct route or vulnerability.

| Method | Path | Status | Sources |
| --- | --- | --- | --- |
| GET | / | [200] | playwright_link, playwright_network |
| GET | /api/Challenges/ | [200] | playwright_network |
| GET | /api/Quantitys/ | [200] | playwright_network |
| GET | /assets/i18n/en.json | [200] | playwright_network |
| GET | /assets/public/images/JuiceShop_Logo.png | [200] | playwright_network |
| GET | /assets/public/images/products/apple_juice-1x.avif | [200] | playwright_network |
| GET | /assets/public/images/products/apple_pressings-1x.avif | [200] | playwright_network |
| GET | /assets/public/images/products/artwork2-1x.avif | [200] | playwright_network |
| GET | /assets/public/images/products/banana_juice-1x.avif | [200] | playwright_network |
| GET | /assets/public/images/products/basil_smoothie-1x.avif | [200] | playwright_network |
| GET | /assets/public/images/products/berry_juice-1x.avif | [200] | playwright_network |
| GET | /assets/public/images/products/braga-1x.avif | [200] | playwright_network |
| GET | /assets/public/images/products/carrot_juice-1x.avif | [200] | playwright_network |
| GET | /assets/public/images/products/dragonfruit_juice-1x.avif | [200] | playwright_network |
| GET | /assets/public/images/products/eggfruit_juice-1x.avif | [200] | playwright_network |
| GET | /assets/public/images/products/elderflower_cordial-1x.avif | [200] | playwright_network |
| GET | /assets/public/images/products/fruit_press-1x.avif | [200] | playwright_network |
| GET | /assets/public/images/products/grape_juice-1x.avif | [200] | playwright_network |
| GET | /assets/public/images/products/green_smoothie-1x.avif | [200] | playwright_network |
| GET | /assets/public/images/products/permafrost-1x.avif | [200] | playwright_network |
| GET | /chunk-1qQQGal7.js | [200] | playwright_network |
| GET | /chunk-Cv2YgWUq.js | [200] | playwright_network |
| GET | /chunk-DBPdFzgj.js | [200] | playwright_network |
| GET | /main.js | [200] | playwright_network |
| GET | /media/material-icons-LEZCGFVT.woff2 | [200] | playwright_network |
| GET | /polyfills.js | [200] | playwright_network |
| GET | /redirect | [500] | playwright_link, playwright_network |
| GET | /rest/admin/application-configuration | [200] | playwright_network |
| GET | /rest/admin/application-version | [200] | playwright_network |
| GET | /rest/languages | [200] | playwright_network |
| GET | /rest/products/search | [200] | playwright_network |
| GET | /robots.txt | [200] | ffuf |
| GET | /rolldown-runtime-BoHGiXSq.js | [200] | playwright_network |
| GET | /scripts.js | [200] | playwright_network |
| GET | /styles.css | [200] | playwright_network |

## AI review

Inventaris lokal HTTP terbatas pada 35 endpoint yang teramati di localhost:3000. Data berasal dari sumber tidak terpercaya (ffuf, playwright) dan hanya mencatat respons HTTP 200 atau 500 tanpa membuktikan kerentanan. Inventaris mencakup halaman utama, file aset statis (gambar, JS, font), serta beberapa rute API; tiga detail endpoint dihilangkan.

- Hanya mencakup inventaris lokal yang teramati (tidak ada cakupan aplikasi lengkap).
- Status HTTP 200 tidak membuktikan bahwa rute tersebut berbeda atau aman.
- Tidak dapat mengeksekusi alat atau memverifikasi kerentanan secara aktif.
