FROM debian:trixie-slim

# Vanguards: full vanguards protections for the Tor hidden service.
# (layer2/layer3 pinning, bandguards, rendguard, logguard)
#
# Uses the BeagleByte fork: upstream (mikeperry-tor/vanguards) still ships a
# Python 2 import fallback that crashes on Python >= 3.12 with
# "No module named ConfigParser". Fork fixes it (configparser.ConfigParser).
# Pinned to the known-good commit.
ARG VANGUARDS_REPO=https://github.com/BeagleByte/vanguards
ARG VANGUARDS_COMMIT=7b8d516a65f73f2a572df6c72a249a1896854616

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN git clone "$VANGUARDS_REPO" /opt/vanguards \
 && cd /opt/vanguards \
 && git checkout "$VANGUARDS_COMMIT" \
 && python3 -m venv /opt/vanguards-venv \
 && /opt/vanguards-venv/bin/pip install --no-cache-dir setuptools \
 && /opt/vanguards-venv/bin/pip install --no-cache-dir stem \
 && /opt/vanguards-venv/bin/pip install --no-cache-dir /opt/vanguards

COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
