# Vanguards Integration — What Was Done

> Change summary for BeagleGuerilla, the Docker-based Tor hidden service.
> Date: 2026-11-02

## Overview

Added optional **Vanguards** protection for the hidden service, switchable
via Docker Compose profiles, plus three fixes discovered along the way.

Vanguards defends the onion service against **guard discovery attacks** — the
attack class that Sybil relay floods enable. It pins layer2/layer3 relays,
so an adversary observing circuits learns only disposable middle relays
instead of the precious guard node.

```
WITHOUT vanguards (default):          WITH vanguards (--profile vanguards):

  tor ── internal net ── flask          tor ── internal net ── flask
   │                                     │
   │ (no control port)                   └── control port :9051 (password)
   └── internet (Tor network)                └── internal net ── vanguards
```

## Changes

### New files

| File | Purpose |
| --- | --- |
| `tor-entrypoint.sh` | Tor container entrypoint. Appends `ControlPort` + `HashedControlPassword` to the torrc **only when** `CONTROL_PASSWORD` is set — same image runs with and without vanguards. |
| `vanguards/Dockerfile` | Builds a Debian image with Python, stem, and [mikeperry-tor/vanguards](https://github.com/mikeperry-tor/vanguards). |
| `vanguards/entrypoint.sh` | Connects vanguards to tor via the control port (`--control_ip tor-hidden-service --control_port 9051 --control_pass`). |

### Modified files

| File | Change |
| --- | --- |
| `docker-compose.yml` | Added `vanguards` service under `profiles: ["vanguards"]`; added `tor_data` + `vanguards_state` volumes; bound flask to `127.0.0.1` only. |
| `Dockerfile` | Wired in `tor-entrypoint.sh` as ENTRYPOINT. |
| `torrc` | Added `Log notice stdout` — tor logs are now captured by `docker compose logs` (file log kept as well). |
| `app/app.py` | Fixed `/auto-refresh` to render `refresh_example.html` (was `page.html` → 500). |
| `README.md` | Rewritten with start/use instructions. |

## Bugs fixed along the way

1. **Onion keys were not persisted.** `/var/lib/tor` lived inside the
   container; every rebuild generated a **new onion address**. Now stored in
   the `tor_data` volume. ⚠️ Back this volume up — losing it loses the
   address.
2. **Flask was published on public port 80** (`80:5000`), serving the hidden
   service's content in cleartext to the internet. Now `127.0.0.1:5000`
   (SSH-tunnel debugging only).
3. **`/auto-refresh` returned 500** — template name mismatch.

## How the toggle works

- **Tor side:** the entrypoint only adds `ControlPort 0.0.0.0:9051` +
  `HashedControlPassword` (generated at boot via `tor --hash-password`) when
  `CONTROL_PASSWORD` is non-empty. Otherwise the control port never opens.
- **Vanguards side:** the service is defined under the `vanguards` profile,
  so `docker compose up` never starts it; only
  `docker compose --profile vanguards up` does.
- Both containers read the same password from `TOR_CONTROL_PASSWORD`
  (default: `change-me-tor-control` — set your own on the VPS).

## Security notes

- The control port binds `0.0.0.0` *inside* the container, but only the
  `internal` docker network (tor, flask, vanguards) can reach it. Nothing is
  published to the host.
- Tor warns that a non-local ControlPort is reachable — expected here; the
  hashed password is the compensating control.
- The control protocol itself is unencrypted: that is why it stays on the
  internal network and behind a password.

## Validation performed

- Entrypoint-generated config accepted by a real tor (`tor --verify-config`)
- Booted tor with the generated config and reproduced vanguards' exact stem
  auth flow (`authenticate()` → `MissingPassword` → password auth) — succeeded
- `sh -n` on both entrypoint scripts
- YAML + semantic checks on `docker-compose.yml`
- Vanguards CLI flags verified against the current
  `mikeperry-tor/vanguards` source (`--control_ip`, `--control_port`,
  `--control_pass`, `--loglevel`, `VANGUARDS_STATE`)
