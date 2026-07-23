# PIPL Chat — v0.4 prototype

Peer-to-peer chat where **every message is an encrypted, signed file**. It
lives either in a folder both peers can reach (a Dropbox/Drive folder works
as-is — the backend is just files) or on a server that stores ciphertext it
cannot decrypt. The sender keeps per-object private keys and can **revoke or
hide** any message at any time. The server holds **no keys and no
plaintext** — a public-identity directory, "something changed" pings, and
optionally the encrypted blobs themselves.

**New here? Read the [user manual](docs/MANUAL.md).** This README is the
short tour; the manual covers each task, the keybindings, and what the
guarantees actually are. See [design.md](docs/design.md) for the
architecture and threat model, [STATUS.md](docs/STATUS.md) for what is and
isn't finished.

All cryptography is Go standard library. The only external dependencies are
the terminal-UI libraries, and none of them touch key material.

## Layout

```
cmd/pipl-server/   keyless coordination server (identity directory + SSE notifications)
cmd/pipl/          peer client — interactive UI by default, flags for scripting
internal/tui/      Bubble Tea front end (rendering + input only)
internal/chat/     headless engine: send/receive/revoke — shared by UI and flags
internal/object/   the PIPL object container: header (with key slots) | ciphertext | signature
internal/grant/    grant files (sealed or group-encrypted) + member-key files
internal/identity/ long-term identity keys + sealed boxes (X25519/HKDF/AES-GCM)
internal/store/    filesystem backend (atomic writes, conversation layout)
internal/state/    local state: ~/.pipl (or $PIPL_HOME)
internal/api/      client for the server API
demo.sh            3 peers: group + separate sends, revoke/hide/unhide
demo-recipients.sh 4 peers: per-message recipient subsets + hard revoke
```

## Quick start

```sh
go build -o bin/ ./cmd/...
./demo.sh              # every revocation mode
./demo-recipients.sh   # per-message recipient selection
```

### No shared folder needed

A conversation created without `-dir` relays through the server, which
stores ciphertext it cannot decrypt. Peers join with a pasted invite code
and need nothing else in common:

```sh
bin/pipl-server -blobs ./server/blobs &     # -blobs = survive restarts

bin/pipl -home ./peers/alice conv new -name team -with bob,carol
# -> invite: pipl1:eyJpIjoi...

bin/pipl -home ./peers/bob conv join -name team -invite pipl1:eyJpIjoi...
```

Without `-blobs` the relay keeps everything in memory and a restart loses
it; the server prints a warning saying so.

Revoke, hide and unhide all work this way: the server verifies each
object's signature, so only its owner can rewrite or delete it. An invite
carries **no key** — access still requires a member key sealed to your
identity, so a stolen code reads nothing. `./demo-relay.sh` proves the
whole flow, including that everything the server holds is ciphertext.

### Interactive UI

Run `pipl` with no arguments. Each instance is a separate peer, selected by
`-home` — so several terminals on one machine chat with each other:

```sh
bin/pipl-server &                          # enables live updates

bin/pipl -home ./peers/alice               # terminal 1
bin/pipl -home ./peers/bob                 # terminal 2
bin/pipl -home ./peers/carol               # terminal 3
```

`-home DIR` works on every command and holds that peer's keys and state.
Any path does — relative, absolute, or `~/.pipl-alice`. It overrides
`$PIPL_HOME` (still supported) and defaults to `~/.pipl`. The conversation
list shows the handle and directory, so you can always tell which window
is which.

First run asks for a handle. Then:

- **`n`** — new conversation: name, shared folder, and a member picker
  (`space` toggles). This is how you create a group.
- **`J`** — join a conversation someone created you into, by folder.
- **`enter`** — open it.

Inside a conversation, `tab` cycles between three panes:

```
┌──────────────────────────────────┐┌──────────────┐
│ 09:14 alice  morning all         ││ recipients   │
│ 09:15 you    deploy slipped      ││  [x] bob     │
│                  → bob, carol    ││  [x] carol   │
│                                  ││› [ ] dave    │
│                                  ││              │
│                                  ││ per-recipient│
│                                  ││ keys         │
└──────────────────────────────────┘└──────────────┘
› message
```

- **message** — type and `enter` to send
- **recipients** — `space` toggles who this message goes to, `a` selects
  everyone. The panel always names the audience model in force.
- **history** — `↑`/`↓` to select a message, then `h` hide, `u` unhide,
  `r` revoke the highlighted recipient

### Flags (same engine, for scripting)

```sh
A="-home ./peers/alice"
B="-home ./peers/bob"

bin/pipl $A init -handle alice
bin/pipl $A conv new -name chat -dir ./peers/shared -with bob,carol
bin/pipl $B conv join -name chat -dir ./peers/shared

bin/pipl $A send -conv chat "hello"                # whole roster: group key
bin/pipl $A send -conv chat -to bob "just for bob" # subset: per-recipient keys
bin/pipl $B recv -conv chat -follow                # live feed

bin/pipl $A revoke -conv chat -object <id> -from bob
bin/pipl $A hide   -conv chat -object <id>
bin/pipl $A unhide -conv chat -object <id>
```

### On Windows (PowerShell)

`-home` takes any path, so nothing needs environment variables. Relative
paths work — keeping the peers beside the repo is the easiest way to try
several at once (`peers/` is gitignored):

```powershell
.\bin\pipl-server.exe                        # terminal 1

.\bin\pipl.exe -home .\peers\alice           # terminal 2
.\bin\pipl.exe -home .\peers\bob             # terminal 3
.\bin\pipl.exe -home .\peers\carol           # terminal 4
```

Use `.\peers\shared` as the conversation folder. Quote any path containing
spaces. The TUI needs a real terminal (Windows Terminal renders it best);
the `.sh` demo scripts need Git Bash.

`peers/` holds identity private keys and the per-object signing keys that
are the revocation authority — it is gitignored, and should stay that way.

Without a server (`pipl init -server ""`), everything still works: `recv
-follow` polls the folder instead of listening for pings.

## How access control works

**Objects and layers.** Each message is one file: a signed container whose
header carries **key slots** (LUKS-style) — the layer key encrypted once per
audience access key. Revocation is *superencryption*: the owner wraps the
existing ciphertext in a new signed layer (plaintext is never touched — one
encrypt pass) with slots only for the keys that should still work. Wrapping
is reversible: peeling a layer restores the previous audience.

**Two audience models**, chosen per message by who you select:

- **Whole roster** (default): every conversation member shares one group key,
  distributed once as sealed `.mkey` files when the conversation is created.
  A group message costs **one slot and one grant file regardless of group
  size**. Revoking a single member of a group means rotating the group key
  (`conv rekey`, on the roadmap) — or just `hide` the object from everyone.
- **A subset** (`-to bob,carol`, or unticking someone in the UI): each
  recipient gets a personal access key via their own sealed grant. One slot
  per recipient, and **members outside the subset get no slot at all** — the
  exclusion is cryptographic, not a display convention. Any recipient can
  then be **hard-revoked alone**: the owner re-wraps with slots for the
  others, who keep their original grants untouched. No re-granting, ever.

Selecting a subset is exactly the old `-separate` mode, chosen
automatically: per-message recipient selection is only possible with
per-recipient keys. `-separate` still exists to force personal keys for a
send that happens to go to everyone.

**Revocation modes:**

- `revoke -from X` — hard revoke one recipient of a per-recipient send (wrap
  + slots for the rest; nothing re-granted).
- `hide` / `unhide` — wrap with **zero** slots: invisible to everyone, all
  grants inert; unhide peels the layer and every old grant works again.
- `revoke -all` — delete the object and all grants (permanent).
- `revoke -from X -soft` — just delete X's grant file (weak: a cached
  access key still opens the slot).

## Honest limitations (by design, stated loudly)

- Revocation cannot un-share: someone who already read a message may have
  copied it. The CLI says so on every revoke.
- On sync backends with version history (Dropbox/Drive), old file versions
  may remain fetchable by a revoked peer who kept their old access key —
  hard revoke is best-effort there. Owner-controlled storage (plain disk,
  S3 without versioning) gives full-strength revocation.
- Slot count leaks audience size, and message length leaks (no padding
  yet). Folder conversations also expose member handles in
  `pipl-conv.json`; relay conversations carry the roster in the invite
  code instead. Dummy slots and padding would close these.
- Identity lookup is trust-on-first-use; verify fingerprints out of band.
- Wrap layers accumulate one per revocation; a future `compact` op can
  flatten long chains.

## Prototype crypto notes

All cryptography is standard library: AES-256-GCM for content, slots, and
group-encrypted grants (design doc specifies XChaCha20-Poly1305 secretstream
for large media — swap later), and X25519 + HKDF-SHA256 + AES-GCM sealed
boxes (design doc specifies libsodium `crypto_box_seal` — swap for
cross-language clients). Marked with NOTE comments at both sites.

The sealed-box wire format is pinned by a golden vector in
`internal/identity/identity_test.go`: changing the KDF salt or info string
silently breaks interop with existing peers, and round-trip tests cannot
see it. The UI dependencies (Bubble Tea, Bubbles, Lipgloss) are the only
external modules, and none of them touch key material.

## Next (per design doc roadmap)

`conv rekey` (group key rotation = per-member revocation for whole-roster
sends) · Dropbox/S3 backends, Lambda deployment · payload padding ·
multi-device identity.
