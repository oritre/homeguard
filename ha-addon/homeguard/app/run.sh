#!/bin/sh
# One-time import: files dropped in /share/homeguard_import are copied into /data.
IMP=/share/homeguard_import
if [ -f "$IMP/config.json" ]; then
  echo "Importing HomeGuard data from $IMP"
  [ -f /data/homeguard.db ] && mv /data/homeguard.db /data/homeguard.db.bak
  cp "$IMP/config.json" /data/config.json
  [ -f "$IMP/homeguard.db" ] && cp "$IMP/homeguard.db" /data/homeguard.db
  mv "$IMP" "/share/homeguard_imported_$(date +%Y%m%d%H%M%S)"
fi
exec python /app/homeguard_server.py run --config /data/config.json
