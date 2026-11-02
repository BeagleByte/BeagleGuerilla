#!/bin/sh
# Vanguards container entrypoint.
# Connects to the tor container's control port over the internal network.
set -e

export PATH=/opt/vanguards-venv/bin:$PATH

exec vanguards \
  --control_ip "${CONTROL_HOST:-tor-hidden-service}" \
  --control_port "${CONTROL_PORT:-9051}" \
  --control_pass "${VANGUARDS_PASSWORD:-}" \
  --loglevel "${LOGLEVEL:-NOTICE}"
