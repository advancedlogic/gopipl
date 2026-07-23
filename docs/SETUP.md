# PIPL — setup guide

Getting from a fresh clone to peers chatting. Three paths, shortest first:

1. [Local demo](#1-local-demo-one-machine) — several peers on one machine, no TLS.
2. [Multiple machines over TLS](#2-multiple-machines-over-tls) — the real deployment.
3. [A public server with a CA certificate](#3-a-public-server-with-a-ca-certificate) — when the server has a hostname.

Everything here is copy-pasteable. For what each command *means*, see the
[user manual](MANUAL.md); for why it is built this way, [design.md](design.md).

---

## 0. Build

```sh
go build -o bin/ ./cmd/...
```

Produces `bin/pipl` (the client) and `bin/pipl-server` (the coordination
server). With `make`, `make build` does the same.

> **Windows note.** An open `pipl` window locks `bin/pipl.exe`, so a
> rebuild can silently keep the old binary. Close any client first, or use
> `make run-*` / `go run`, which compile from source every time.

---

## 1. Local demo (one machine)

The fastest way to see it work. No TLS needed — everything stays on
loopback. Each peer is a separate `-home` directory.

**Terminal 1 — the server** (leave it running):

```sh
bin/pipl-server -data ./server/directory.json -blobs ./server/blobs
```

`-data` keeps the identity directory across restarts; `-blobs` keeps
relayed messages. Skipping them works too, but you lose both on restart.

**Terminals 2 and 3 — two peers:**

```sh
bin/pipl -home ./peers/alice        # terminal 2
bin/pipl -home ./peers/bob          # terminal 3
```

Each asks for a handle on first run (type `alice`, `bob`). Then in the UI:

- alice presses **`n`**, names the conversation, leaves the folder blank
  (uses the relay), picks bob with `space`, `enter`. She gets an invite
  code — press **`i`** anytime to show it again.
- bob presses **`J`**, pastes the invite code, `enter`.

Type in either window; it appears in the other within ~2 seconds.

Prefer flags? Same thing without the UI:

```sh
bin/pipl -home ./peers/alice conv new  -name team -with bob      # prints an invite
bin/pipl -home ./peers/bob   conv join -name team -invite pipl1:…
bin/pipl -home ./peers/alice send -conv team "hello"
bin/pipl -home ./peers/bob   recv -conv team -follow
```

With `make`: `make run-server`, then `make run-alice`, `make run-bob`.

---

## 2. Multiple machines over TLS

For peers on different computers, the server needs a real address and
**TLS**, so a network observer can't read the metadata (who talks to whom,
message sizes and timing). TLS does **not** protect message content — that
is already end-to-end encrypted — so a self-signed certificate pinned by
fingerprint is the right fit, and needs no certificate authority.

### 2a. On the server machine — create the certificate once

```sh
bin/pipl-server \
    -addr 0.0.0.0:8737 \
    -tls-self-signed -tls-dir ./server/tls \
    -tls-fingerprint-file ./server/pin.txt \
    -data ./server/directory.json -blobs ./server/blobs
```

On first run this generates `./server/tls/cert.pem` + `key.pem` and writes
the fingerprint to `./server/pin.txt`. It logs:

```
TLS: self-signed, generated, cached in ./server/tls
  clients must pin: 2675053cd7dc1fee4c6c0028f847d867e2c52c944d8af73b017eed80697e674c
```

**`-tls-dir` is what makes the certificate survive restarts** — the same
fingerprint is reused, so peers pin it once and never need to re-pin.
Without it the cert is regenerated on every start and pinned clients would
reject the server after a restart.

`make run-server-tls` runs exactly this (with `-tls-dir ./server/tls`).

> Keep `./server/tls/key.pem` private — it is the server's TLS private key.
> On a Unix host, `chmod 600 server/tls/key.pem` after copying it there;
> Go writes it 0600 already, but a copy may not preserve that.

Copy the fingerprint out of `./server/pin.txt`. Peers need it, and they
should **verify it out of band** (read it over the phone, etc.) the same
way they verify each other's identity fingerprints.

### 2b. On each peer machine — pin the fingerprint at init

```sh
bin/pipl -home ./peers/alice init -handle alice \
    -server https://SERVER-ADDRESS:8737 \
    -tls-pin 2675053cd7dc1fee4c6c0028f847d867e2c52c944d8af73b017eed80697e674c
```

Replace `SERVER-ADDRESS` with the server's hostname or IP, and the pin with
the one from `./server/pin.txt`. From here everything is identical to the
local demo — create/join by invite, send, revoke — just over TLS. The pin
is stored, so later commands need only `-server` (already in config) and no
`-tls-pin`.

The desktop app takes the same server URL and pin in its first-run setup
screen.

---

## 3. A public server with a CA certificate

If the server has a real hostname and a certificate from a CA (e.g. Let's
Encrypt), use it directly — no pinning, because clients trust it through
the system roots:

```sh
bin/pipl-server -addr 0.0.0.0:443 \
    -tls-cert /etc/letsencrypt/live/chat.example.com/fullchain.pem \
    -tls-key  /etc/letsencrypt/live/chat.example.com/privkey.pem \
    -data ./server/directory.json -blobs ./server/blobs
```

Peers then just point at it:

```sh
bin/pipl -home ./peers/alice init -handle alice -server https://chat.example.com
```

---

## What ends up on disk

| Path | What | Commit it? |
|---|---|---|
| `peers/<name>/` | a peer's identity keys, conversations, revocation keys | **never** (gitignored) |
| `server/tls/` | the server's TLS cert **and private key** | **never** (gitignored) |
| `server/pin.txt` | the cert fingerprint (not secret, but noise) | no (gitignored) |
| `server/directory.json` | the identity phonebook | no (gitignored) |
| `server/blobs/` | relayed ciphertext | no (gitignored) |
| `bin/` | built binaries | no (gitignored) |

All of the above are already in `.gitignore`.

---

## When something's wrong

A few failures come up during setup; the [manual's troubleshooting
section](MANUAL.md#11-troubleshooting) covers them, but the setup-specific
ones:

- **"unknown handle X" / "no valid member key"** — almost always the server
  lost its directory (run it with `-data`) or a peer isn't registered. Run
  `pipl register` on the peer, and make sure the server has `-data`.
- **A peer was re-created and now can't be added** — the creator has a
  stale pin of the old identity. On the creator's side: `pipl unpin
  -handle X`, then re-create the conversation. A handle already taken on
  the server can't be reused; pick a fresh one.
- **TLS: "certificate fingerprint mismatch"** — the pin doesn't match the
  server's current cert. Either you copied the wrong pin, or the server was
  restarted **without** `-tls-dir` and generated a new cert. Use `-tls-dir`
  so the cert is stable, and re-copy the pin from `./server/pin.txt`.
- **"connection refused" over https** — the server is running plain HTTP
  (no `-tls-*` flag) but the peer used `https://`, or vice-versa. Match
  them.
