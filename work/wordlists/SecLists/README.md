# Vendored SecLists wordlist

`common.txt` is a verbatim copy of the installed SecLists package's
`Discovery/Web-Content/common.txt`. Source: Daniel Miessler and contributors,
<https://github.com/danielmiessler/SecLists>.

- Installed package: `2025.3-0kali1`.
- 4,750 entries, 38,500 bytes.
- SHA-256: `74400ab9b9948c411afdf68adf5e49079801450068350cd801d0aa8fe7588d5a`.
- The installed package's copyright/license notice is preserved in `COPYRIGHT`.
- Exact provenance is recorded in `manifest.json`; this is not a claim to be the latest upstream revision.

The local integration harness uses eight existing entries from this file and
verifies its checksum first. The full list is preserved for provenance. The
harness accepts no remote target and does not submit the full list to a service.
