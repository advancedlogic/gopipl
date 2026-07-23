# PIPL — user manual

PIPL is a chat where every message is an encrypted file, and the person
who sent it keeps the power to take it back.

This manual is task-first: how to run it, then how to do each thing, then
what the guarantees actually are. For *why* it is built this way see
[design.md](design.md); for what is and isn't finished see
[STATUS.md](STATUS.md).

---

## Contents

1. [The idea in one minute](#1-the-idea-in-one-minute)
2. [Install and run](#2-install-and-run)
3. [Your identity](#3-your-identity)
4. [Starting a conversation](#4-starting-a-conversation)
5. [Sending and reading](#5-sending-and-reading)
6. [Choosing who gets a message](#6-choosing-who-gets-a-message)
7. [Taking a message back](#7-taking-a-message-back)
8. [The interactive UI](#8-the-interactive-ui)
9. [Command reference](#9-command-reference)
10. [What PIPL does and does not protect](#10-what-pipl-does-and-does-not-protect)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. The idea in one minute

Most chat apps keep your messages on a server that can read them. PIPL
doesn't have one.

Instead, **each message is an encrypted file**. It sits either in a folder
both people can reach (a Dropbox folder, a network share) or on a PIPL
server that stores it without being able to decrypt it. Alongside each
message is a tiny sealed envelope holding the key, addressed to each
recipient.

Three consequences worth understanding up front:

- **Nobody in the middle can read anything.** Not the PIPL server, not
  Dropbox, not whoever runs the machine the folder is on. They see
  encrypted blobs with random names.
- **The sender keeps control after sending.** Because the message is a
  file the sender still owns, they can rewrite it later so a particular
  person can no longer open it. That's what `revoke` and `hide` do.
- **There are no accounts or passwords.** Your identity is a keypair on
  your machine. The server maps names to public keys and nothing more.

---

## 2. Install and run

You need Go 1.24+.

```sh
go build -o bin/ ./cmd/...
```

That produces two programs:

| | |
|---|---|
| `bin/pipl` | you — the client, where all encryption happens |
| `bin/pipl-server` | the coordination server (see below) |

### Do I need the server?

It does two things: it's a **phonebook** (mapping `bob` to bob's public
key) and a **doorbell** (telling your client something changed so it
refreshes instantly). It can also **relay** encrypted messages for peers
with no shared folder.

Run it once, in its own terminal, and leave it:

```sh
bin/pipl-server
```

You can skip it if peers share a folder *and* have each other's keys
already — but for anything normal, run it.

### See it work before using it

Three scripts run everything end to end and check the results:

```sh
./demo.sh              # revoke, hide, unhide
./demo-recipients.sh   # sending to a subset of a group
./demo-relay.sh        # no shared folder at all
```

On Windows these need Git Bash. They're the fastest way to see what PIPL
claims to do actually happening.

---

## 3. Your identity

Your keys live in one directory, chosen with `-home`:

```sh
bin/pipl -home ./peers/alice init -handle alice
```

This generates your keypair, saves it, and registers the **public** half
with the server. Your private keys never leave the directory.

`-home` is how you run several people on one machine — one directory each.
Every command takes it:

```sh
bin/pipl -home ./peers/alice send -conv team "hello"
bin/pipl -home ./peers/bob   recv -conv team
```

Any path works: relative (`./peers/alice`), absolute, or `~/.pipl-alice`.
Omit it and PIPL uses `~/.pipl`. On Windows use PowerShell-safe quoting for
paths with spaces.

> **That directory is your identity.** Copying it copies you; losing it
> loses your ability to revoke anything you've sent. It is gitignored for
> a reason.

### Fingerprints

When you first encounter someone, PIPL prints:

```
pinned bob (fingerprint 66eb037c4f85b241) — verify out of band
```

It remembers those keys and will **refuse** them if they ever change. The
fingerprint is there so you can confirm through another channel ("read me
your fingerprint") that you got bob's real keys and not something a
malicious server substituted. Checking it is optional but it's the one
manual step that closes a real attack.

---

## 4. Starting a conversation

Two ways, differing only in where the encrypted files live.

### Without a folder (simplest)

```sh
bin/pipl -home ./peers/alice conv new -name team -with bob,carol
```

Prints an invite code:

```
invite: pipl1:eyJpIjoiNDN0M3h3bW5mNHBjcXhvN3Y0cnpjdGNydj...
```

Send that to bob and carol however you like — email, Slack, read it aloud.
They run:

```sh
bin/pipl -home ./peers/bob conv join -name team -invite pipl1:eyJpIjoi...
```

Messages relay through the server as ciphertext it can't read.

**The invite is not a password.** It names the conversation and who's in
it; it contains no key. Someone who steals it learns the roster and
nothing else — they still can't read a single message, because the actual
key arrives sealed to each member's identity. Lost the code? Reprint it:

```sh
bin/pipl -home ./peers/alice conv invite -name team
```

### With a shared folder

If everyone can reach the same folder — a Dropbox/OneDrive folder, a
network share — put the conversation there with `-dir`:

```sh
bin/pipl -home ./peers/alice conv new -name team -dir ~/Dropbox/team -with bob,carol
bin/pipl -home ./peers/bob   conv join -name team -dir ~/Dropbox/team
```

The path differs per machine; each person gives their own.

### Which should I use?

| | folder | relay |
|---|---|---|
| setup | everyone needs the same folder | paste one code |
| server needed | no | yes |
| if the server dies | unaffected | conversation unreachable |
| server compromise reveals | nothing (it holds nothing) | ciphertext + metadata |

**Folder is the stronger choice** when you have one, because the server
holds nothing at all. Relay is far easier to start. Both encrypt
identically — the difference is who stores the ciphertext.

`-name` is just your local label. Call it `team` while bob calls it
`work-chat`; it's the same conversation.

---

## 5. Sending and reading

```sh
bin/pipl -home ./peers/alice send -conv team "morning all"
# sent 3flhjrpg33mmdy5mu3dbibrkhq
```

That ID is the message's name. You'll need it to revoke or hide later, so
keep it if you think you might.

```sh
bin/pipl -home ./peers/bob recv -conv team
# [11:30] alice: morning all  (3flhjrpg33mmdy5mu3dbibrkhq)

bin/pipl -home ./peers/bob recv -conv team -follow    # stay open, live
```

Reading is a search, not a lookup: your client tries every sealed envelope
in the conversation, finds the ones it can open, and decrypts the messages
those unlock. Anything you have no key for is silently skipped — which is
why a revoked message simply stops appearing rather than showing an error.

---

## 6. Choosing who gets a message

By default a message goes to everyone in the conversation. To send to some
of them:

```sh
bin/pipl -home ./peers/alice send -conv team -to bob,carol "not for dave"
```

Dave cannot read this. Not "dave's client hides it" — **there is no key
for dave anywhere in that message.** He can inspect every file involved
and get nothing.

This changes how the message is encrypted, and the difference matters
later:

| | whole roster (default) | a subset (`-to`) |
|---|---|---|
| key | one shared group key | a personal key per recipient |
| cost | one envelope, any group size | one envelope each |
| revoke one person later? | **no** (needs group rekey, not built) | **yes** |

So: **if you might want to un-send to one person, use `-to`.** With a
whole-roster message your only options are hiding it from everyone or
deleting it.

Use `-separate` to get per-recipient keys while still sending to everyone —
useful when you expect to revoke someone later.

---

## 7. Taking a message back

Only the sender can do any of this — you hold the key that lets the file
be rewritten. Someone else trying gets:

```
you do not own object pbi7oonov6mjq5w5uph2hwgjra (only the sender can do this)
```

### Revoke one person (subset messages only)

```sh
bin/pipl -home ./peers/alice revoke -conv team -object <id> -from carol
```

Carol can no longer read it. **Everyone else is untouched** — nobody gets
re-sent a key, nobody notices. Under the hood the message is re-locked
with keys for everyone except carol.

On a whole-roster message you'll get:

```
object ... went to the whole group under one shared key: revoking one member
needs a group-key rotation (roadmap) — send to a subset of recipients for
individually revocable messages, or hide it from everyone
```

That's the tradeoff from §6, showing up.

### Hide from everyone, reversibly

```sh
bin/pipl -home ./peers/alice hide   -conv team -object <id>
bin/pipl -home ./peers/alice unhide -conv team -object <id>
```

Hide makes a message unreadable to all recipients. Unhide brings it back
for exactly the people who could read it before — nothing is re-sent. Good
for "I shouldn't have posted that" when you may want it back.

### Delete permanently

```sh
bin/pipl -home ./peers/alice revoke -conv team -object <id> -all
```

The message and all its keys are deleted. Not reversible.

### The weak one

```sh
bin/pipl -home ./peers/alice revoke -conv team -object <id> -from carol -soft
```

Deletes carol's envelope but not her access — if her client already
fetched the key, she can still read it. Only useful against someone who
never came online. Prefer plain `revoke`.

### What revocation cannot do

**It cannot un-share.** If carol already read the message, she may have
screenshotted it, copied it, or remembered it. Revoking stops future
access through PIPL; it cannot reach into her head or her disk. The tool
says so every time you revoke, deliberately.

There's a subtler one: **on Dropbox/Drive-style storage with version
history**, a revoked person who kept their old key might fetch an old
version of the file and read it. Revocation is best-effort there. It's
full-strength on storage where old versions aren't retained (a plain
folder, S3 without versioning) or through the relay.

---

## 8. The interactive UI

Run `pipl` with no command:

```sh
bin/pipl -home ./peers/alice
```

Needs a real terminal. On Windows, Windows Terminal renders it best; it
won't work piped or in an output pane.

**First run** asks for a handle — same as `init`.

**Conversation list:**

| key | |
|---|---|
| `↑` `↓` or `k` `j` | move |
| `enter` | open |
| `n` | new conversation |
| `J` | join (paste an invite code, or a folder path) |
| `q` | quit |

When creating, leave the folder blank to use the relay. Pick members with
`space` after `tab`bing to the member list.

**Inside a conversation**, `tab` cycles three panes:

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

- **message box** — type, `enter` sends
- **recipients** — `space` toggles who gets it, `a` selects everyone,
  `i` shows the invite code. The panel always tells you which encryption
  mode you're about to use: `group key` or `per-recipient keys`.
- **history** — `↑`/`↓` to pick a message, then `h` hide, `u` unhide,
  `r` revoke the recipient currently highlighted in the recipients pane

`esc` goes back, `ctrl+c` quits.

The recipients pane is the important one: it shows, before you press
enter, exactly who will be able to read what you're about to send.

---

## 9. Command reference

Every command takes `-home DIR`.

```
pipl                                      interactive UI

pipl init   -handle NAME [-server URL]    create your identity

pipl conv new  -name N -with H,H [-dir D] start a conversation
                                          (no -dir = relay + invite code)
pipl conv join -name N (-invite C|-dir D) join one
pipl conv invite -name N                  reprint the invite code

pipl send -conv N [-to H,H] MESSAGE...    send ( -to = subset )
          [-separate]                     per-recipient keys for everyone
pipl recv -conv N [-follow]               read ( -follow = live )

pipl revoke -conv N -object ID -from H    revoke one person
            [-soft]                       ...weak: only deletes their envelope
pipl revoke -conv N -object ID -all       delete for everyone
pipl hide   -conv N -object ID            hide from everyone (reversible)
pipl unhide -conv N -object ID            restore
```

`pipl-server [-addr HOST:PORT] [-data FILE]` — defaults to
`127.0.0.1:8737`. `-data` persists the phonebook across restarts.

---

## 10. What PIPL does and does not protect

**Protected:**

- Message contents, from the server, the storage provider, and anyone who
  gets at the files. Everything on disk and on the wire is ciphertext.
- Who can read each message, enforced by cryptography rather than by the
  UI — excluded people have no key.
- Rewriting a message: only the sender can. The server checks a signature
  it can verify but never forge.
- Someone impersonating a contact whose keys you've already seen — PIPL
  refuses changed keys.

**Not protected:**

- **Anything already read.** Copies exist. Revocation cannot recall them.
- **Who is talking to whom, and when.** The server and the storage
  provider see handles, timing, sizes, and message counts. Message
  *length* leaks too — padding isn't implemented yet.
- **Availability.** A relay server can refuse to serve or delete blobs
  (it cannot read or alter them). Folder conversations don't depend on it.
- **A recipient choosing to leak.** Anyone you send to can copy and
  re-share. No cryptography prevents that.
- **Your `-home` directory.** It is not encrypted at rest. Whoever gets
  it becomes you.
- **The first contact with a new person**, unless you check the
  fingerprint out of band.

**Not finished** (see STATUS.md): revoking one member of a whole-roster
message; relay blobs survive only until the server restarts; message
padding; multi-device.

---

## 11. Troubleshooting

**"no valid member key for you"** — usually a stale `pipl-server` still
holding the port, serving an old phonebook, so the keys don't match. Check
for a leftover process:

```powershell
Get-Process pipl-server -ErrorAction SilentlyContinue | Stop-Process -Force
```

Otherwise: you weren't included when the conversation was created, or
you're pointing at the wrong folder.

**"identity for X changed ... refusing"** — the keys you have for X don't
match what the server now says. Either X reinstalled, or something is
wrong. Confirm their fingerprint through another channel; only then delete
their entry from `peers.json` in your home directory to re-pin.

**"you do not own object ..."** — only the sender can revoke or hide.

**"...went to the whole group under one shared key"** — you're trying to
revoke one person from a whole-roster message. Use `hide`, or send with
`-to` next time (§6).

**Messages not appearing** — check both sides use the same conversation
(the `-name` may differ, the folder or invite must match), that the server
is running if it's a relay conversation, and that the sender included you.
`-follow` refreshes on a change; without a server it polls every 2s.

**TUI looks broken** — needs a real terminal. Use Windows Terminal, or
fall back to the flag commands, which do everything the UI does.

**`-server ""` doesn't work in PowerShell** — it strips the empty string.
Just omit the flag.

**Where's my stuff?** Your `-home` directory: `identity.json` (your keys),
`conversations.json` (conversations and group keys), `owned.json` (the
keys that let you revoke what you sent), `peers.json` (pinned contacts).
