FROM debian:trixie-slim

# Install system dependencies
RUN apt-get update && apt-get install -y apt-transport-https wget gnupg2 ca-certificates tor python3 python3-pip python3-venv build-essential ufw

RUN ufw allow out 80/tcp
RUN ufw allow out 5000/tcp

RUN wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --dearmor |  tee /usr/share/keyrings/deb.torproject.org-keyring.gpg >/dev/null

RUN echo "deb [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org trixie main" | tee /etc/apt/sources.list.d/tor.list

RUN apt-get update && apt-get install -y tor

# Set working directory
WORKDIR /var/lib/tor

COPY torrc /etc/tor/torrc


EXPOSE 80
USER debian-tor
CMD ["tor", "-f", "/etc/tor/torrc"]
# Expose ports

