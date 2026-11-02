#!/bin/sh
# Tor container entrypoint.
# Enables the vanguards control port only when CONTROL_PASSWORD is set,
# so the same image works with and without vanguards.
set -e

TORRC=/var/lib/tor/torrc
cp /etc/tor/torrc "$TORRC"

if [ -n "$CONTROL_PASSWORD" ]; then
  HASH=$(tor --hash-password "$CONTROL_PASSWORD" | tail -n 1)
  cat >> "$TORRC" <<EOF

# --- vanguards control port (appended by entrypoint) ---
ControlPort 0.0.0.0:9051
HashedControlPassword $HASH
EOF
  echo "[entrypoint] vanguards control port enabled"
else
  echo "[entrypoint] no CONTROL_PASSWORD set - running without vanguards control port"
fi

exec tor -f "$TORRC"
