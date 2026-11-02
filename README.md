# BeagleGuerilla 🧅

Docker-based Tor hidden service with an example Flask app.
Optional Vanguards protection against guard discovery attacks.

See [VANGUARDS.md](VANGUARDS.md) for the full change log.

---

## Requirements

- Docker with Compose plugin (`docker compose`)
- Nothing else — everything runs in containers

## Quick start (without vanguards)

```bash
docker compose up -d
```

That's it. Two containers start: `tor-hidden-service` and `flask`.

### Get your onion address

```bash
docker compose exec tor-hidden-service cat /var/lib/tor/hidden_service/hostname
# → xyzabc...onion
```

Open it in **Tor Browser**: `http://xyzabc...onion`

### Check it's healthy

```bash
docker compose ps
docker compose logs -f tor-hidden-service
docker compose logs -f flask
```

### Logs

All three containers log to stdout, so `docker compose logs` is the one
place to look:

```bash
docker compose logs -f                        # follow everything at once
docker compose logs -f tor-hidden-service     # tor: bootstrapping, circuits
docker compose logs -f flask                  # web requests
docker compose logs -f vanguards              # layer2/layer3 pinning, guards
```

Tor *additionally* writes a log file inside its container:

```bash
docker compose exec tor-hidden-service tail -f /var/log/tor/tor.log
```

### Stop / restart

```bash
docker compose stop          # keep containers + volumes
docker compose down          # remove containers (volumes survive!)
docker compose restart       # restart everything
```

> ⚠️ `docker compose down` does **not** delete your onion keys — they live in
> the `tor_data` volume. `docker compose down -v` **would** delete them and
> give you a brand-new onion address. Don't do that unless you mean it.

## With vanguards (guard-discovery protection) 🛡️

```bash
export TOR_CONTROL_PASSWORD='your-strong-password'
docker compose --profile vanguards up -d
```

Now three containers run. Verify vanguards connected:

```bash
docker compose logs -f vanguards
# → "Vanguards 0.3.1 connected to Tor 0.4.9.x using stem 1.8.x"
```

Stop it without removing the profile setup:

```bash
docker compose --profile vanguards down
```

## Using the service

| Route | What it serves |
| --- | --- |
| `/` | index page |
| `/content` | simple text endpoint |
| `/auto-refresh` | auto-refreshing example page |

The Flask port is bound to `127.0.0.1:5000` on the host **on purpose** —
it must never be public, otherwise the hidden service's content is reachable
in cleartext and the onion is pointless. Debug locally via SSH tunnel:

```bash
ssh -L 5000:127.0.0.1:5000 user@vps   # then browse http://127.0.0.1:5000
```

## Backups (important!)

```bash
# onion keys — losing these means a NEW onion address
docker run --rm -v beagleguerilla_tor_data:/data -v "$PWD":/backup \
  alpine tar czf /backup/tor_data_backup.tar.gz -C /data .

# vanguards state — pinned guards (optional but nice)
docker run --rm -v beagleguerilla_vanguards_state:/data -v "$PWD":/backup \
  alpine tar czf /backup/vanguards_state_backup.tar.gz -C /data .
```

## Customizing

- **torrc** — edit `./torrc`, then:
  ```bash
  docker compose build tor-hidden-service && docker compose up -d
  ```
- **App code** — edit files in `./app`, then:
  ```bash
  docker compose build flask && docker compose up -d
  ```
- **Vanguards settings** — defaults are sane (vanguards, bandguards,
  rendguard, logguard all enabled). Tune via `LOGLEVEL` env in
  `docker-compose.yml`.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Onion site unreachable | `docker compose logs tor-hidden-service` — look for `Bootstrapped 100%` |
| Flask 500 on `/auto-refresh` | fixed (template name), rebuild: `docker compose build flask` |
| Vanguards loops "connection closed" | password mismatch between containers — both read `TOR_CONTROL_PASSWORD`; set and `docker compose --profile vanguards up -d --force-recreate` |
| New onion address after rebuild | you deleted `tor_data` volume or ran `down -v` — restore from backup |
