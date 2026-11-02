FROM debian:trixie-slim

# Vanguards: full vanguards protections for the Tor hidden service.
# (layer2/layer3 pinning, bandguards, rendguard, logguard)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/mikeperry-tor/vanguards /opt/vanguards \
 && python3 -m venv /opt/vanguards-venv \
 && /opt/vanguards-venv/bin/pip install --no-cache-dir setuptools \
 && /opt/vanguards-venv/bin/pip install --no-cache-dir stem \
 && /opt/vanguards-venv/bin/pip install --no-cache-dir /opt/vanguards

COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
