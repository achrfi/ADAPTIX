#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ "$(id -u)" -ne 0 ]; then exec sudo "$0" "$@"; fi
test -s "$ROOT/artifacts/labs/vampi/data/database/database.db"
test -s "$ROOT/lab/vampi/image.lock"
docker image inspect "$(cat "$ROOT/lab/vampi/image.lock")" >/dev/null
for unit in adaptix-vampi.service adaptix-vampi-refresh.service adaptix-vampi-refresh.timer; do
  source="$ROOT/lab/vampi/$unit"
  destination="/etc/systemd/system/$unit"
  if [ -e "$destination" ] && ! cmp -s "$source" "$destination"; then
    printf '%s\n' "Unit berbeda dari salinan proyek: $destination. Review perubahan lokal sebelum menggantinya." >&2
    exit 1
  fi
  install -m 644 "$source" "$destination"
done
systemctl daemon-reload
systemctl enable --now docker.service adaptix-vampi.service adaptix-vampi-refresh.timer
systemctl enable ssh.service
exec "$ROOT/lab/vampi/labctl" prepare
