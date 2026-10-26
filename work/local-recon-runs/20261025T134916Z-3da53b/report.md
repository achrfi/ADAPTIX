# Local recon inventory

Status: success

Assessment status: not_tested — local inventory mode runs no scanner, no payload checks and no browser validation; vulnerability assessment is not performed here

| Stage | Status |
| --- | --- |
| ffuf | success |
| playwright | success |
| acceptance | success |
| ai | disabled |

HTTP status alone is not proof of a distinct route or vulnerability.
No vulnerability assessment was performed in this mode, so zero findings here means "not tested", not "not vulnerable".

| Method | Path | Status | Sources |
| --- | --- | --- | --- |
| GET | / | [200] | playwright_link, playwright_network |
| GET | /.well-known/security.txt | [200] | ffuf |
| GET | /Video | [200] | ffuf |
| GET | /api/Challenges/ | [200] | playwright_network |
| GET | /api/Quantitys/ | [200] | playwright_network |
| GET | /assets | [301] | ffuf, playwright_network |
| GET | /assets/ | [200] | playwright_network, redirect_reference |
| GET | /assets/chunk-1qQQGal7.js | [200] | playwright_network |
| GET | /assets/chunk-Cv2YgWUq.js | [200] | playwright_network |
| GET | /assets/chunk-DBPdFzgj.js | [200] | playwright_network |
| GET | /assets/i18n/en.json | [200] | playwright_network |
| GET | /assets/main.js | [200] | playwright_network |
| GET | /assets/polyfills.js | [200] | playwright_network |
| GET | /assets/public/css/roboto.css | [200] | playwright_network |
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
| GET | /assets/rolldown-runtime-BoHGiXSq.js | [200] | playwright_network |
| GET | /assets/scripts.js | [200] | playwright_network |
| GET | /chunk-1qQQGal7.js | [200] | playwright_network |
| GET | /chunk-Cv2YgWUq.js | [200] | playwright_network |
| GET | /chunk-DBPdFzgj.js | [200] | playwright_network |
| GET | /ftp | [200] | ffuf, playwright_link, playwright_network |
| GET | /ftp/ | [200] | playwright_link, playwright_network |
| GET | /ftp/acquisitions.md | [] | playwright_link |
| GET | /ftp/announcement_encrypted.md | [] | playwright_link |
| GET | /ftp/coupons_2013.md.bak | [] | playwright_link |
| GET | /ftp/eastere.gg | [] | playwright_link |
| GET | /ftp/encrypt.pyc | [] | playwright_link |
| GET | /ftp/incident-support.kdbx | [] | playwright_link |
| GET | /ftp/legal.md | [] | playwright_link |
| GET | /ftp/package-lock.json.bak | [] | playwright_link |
| GET | /ftp/package.json.bak | [] | playwright_link |
| GET | /ftp/quarantine | [200] | playwright_link, playwright_network |
| GET | /ftp/quarantine/juicy_malware_linux_amd_64.url | [] | playwright_link |
| GET | /ftp/quarantine/juicy_malware_linux_arm_64.url | [] | playwright_link |
| GET | /ftp/quarantine/juicy_malware_macos_64.url | [] | playwright_link |
| GET | /ftp/quarantine/juicy_malware_windows_64.exe.url | [] | playwright_link |
| GET | /ftp/suspicious_errors.yml | [] | playwright_link |
| GET | /main.js | [200] | playwright_network |
| GET | /media | [301] | ffuf, playwright_network |
| GET | /media/ | [200] | playwright_network, redirect_reference |
| GET | /media/chunk-1qQQGal7.js | [200] | playwright_network |
| GET | /media/chunk-Cv2YgWUq.js | [200] | playwright_network |
| GET | /media/chunk-DBPdFzgj.js | [200] | playwright_network |
| GET | /media/main.js | [200] | playwright_network |
| GET | /media/material-icons-LEZCGFVT.woff2 | [200] | playwright_network |
| GET | /media/polyfills.js | [200] | playwright_network |
| GET | /media/rolldown-runtime-BoHGiXSq.js | [200] | playwright_network |
| GET | /media/scripts.js | [200] | playwright_network |
| GET | /polyfills.js | [200] | playwright_network |
| GET | /promotion | [200] | ffuf, playwright_network |
| GET | /redirect | [500] | playwright_link, playwright_network |
| GET | /rest/admin/application-configuration | [200] | playwright_network |
| GET | /rest/admin/application-version | [200] | playwright_network |
| GET | /rest/languages | [200] | playwright_network |
| GET | /rest/products/search | [200] | playwright_network |
| GET | /robots.txt | [200] | ffuf |
| GET | /rolldown-runtime-BoHGiXSq.js | [200] | playwright_network |
| GET | /scripts.js | [200] | playwright_network |
| GET | /security.txt | [200] | ffuf |
| GET | /styles.css | [200] | playwright_network |
| GET | /vendor/beercss/beer.min.css | [200] | playwright_network |
| GET | /vendor/beercss/beer.min.js | [200] | playwright_network |
| GET | /vendor/fontsource-roboto/300.css | [200] | playwright_network |
| GET | /vendor/fontsource-roboto/400.css | [200] | playwright_network |
| GET | /vendor/fontsource-roboto/500.css | [200] | playwright_network |
| GET | /vendor/fontsource-roboto/700.css | [200] | playwright_network |
| GET | /vendor/fontsource-roboto/files/roboto-latin-400-normal.woff2 | [200] | playwright_network |
| GET | /vendor/fontsource-roboto/files/roboto-latin-500-normal.woff2 | [200] | playwright_network |
| GET | /vendor/material-icons/material-icons.css | [200] | playwright_network |
| GET | /vendor/material-icons/material-icons.woff2 | [200] | playwright_network |
| GET | /video | [200, 206] | ffuf, playwright_network |
