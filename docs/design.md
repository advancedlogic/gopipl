# PIPL Chat — Design Document

**Project:** PIPL (Public Image, Private Life)
**Date:** 2026-07-23
**Status:** v0.1 draft, amended through v0.3 (§11) and reconciled with the
implementation
**Server language:** Go

> **How to read this.** §§1–10 are the original v0.1 design and are kept
> as written. §11 records the amendments adopted since, and **A1/A2/A3
> supersede parts of §3, §5 and §6** — where that happens, the affected
> section carries an inline "as built" note pointing here. Blockquoted
> notes throughout mark where the code deliberately differs from the
> original plan, or where a described feature is not yet implemented.
> `docs/STATUS.md` tracks shorter-lived detail.

---

## 1. Vision

A peer-to-peer chat system in which **every object — a text message, an image, an audio clip, a video, a file — is a single encrypted file on a filesystem**. That filesystem can be a local disk, a Dropbox or Google Drive folder, an S3 bucket, or anything else that stores and syncs files. The storage layer is never trusted: it only ever sees ciphertext and random filenames.

Each object carries its own cryptographic key material, and the sender (the *owner* of the object) retains unilateral control: they can revoke access to any object, at any time, without asking a server or the recipients for permission.

The server is deliberately minimal. It never stores or sees keys, plaintext, or content. It exists only for coordination: helping peers find each other, notifying them that something new arrived, and optionally relaying small encrypted packets when peers don't share a storage backend. It runs as a single Go binary locally, or serverless on AWS Lambda, or on an ordinary instance.

## 2. Core concepts

**Object.** The unit of everything: one message, one photo, one voice note, one file attachment. One object = one file on the storage backend. Objects are immutable ciphertext from the storage layer's point of view; only the owner can rewrite one (by rotating its keys).

**Owner.** The peer who created the object. The owner holds the object's **private key** and is the only party who can sign, update, or revoke it.

**Read capability.** What recipients hold. In the discussion that led to this document we called it "the object's public key," and structurally that is what it is — but it must be understood as a *bearer capability*: **possession of the read capability is what grants access**, so it is public only among the authorized recipients, never actually published. It contains everything needed to locate, verify, and decrypt one object.

**Identity.** Each peer has a long-term identity keypair (X25519 for encryption, Ed25519 for signatures), generated on the client and never shared. Identities are how capabilities are delivered confidentially peer-to-peer.

**Conversation.** A folder on the storage backend containing object files. A chat between peers is just an agreed folder that both can reach (a shared Dropbox folder, a shared Drive folder, a bucket prefix).

## 3. The key model — formalizing "recipients hold the public key"

The guiding intuition: *the owner's client holds both halves of the object's keypair; recipients hold only the public half; the server never stores any key.* This document formalizes that intuition into a construction that is cryptographically sound, because the naive reading — "encrypt with the private key, decrypt with the public key" — is textbook RSA signing misused as encryption and must not be implemented literally.

Each object gets, at creation time:

- **An object signing keypair** (Ed25519): `obj_sign_priv` / `obj_sign_pub`. The private half never leaves the owner's client. This is the object's *write and revocation authority*.
- **A random content key** `K` (256-bit symmetric), used once to encrypt the object's payload with XChaCha20-Poly1305 (secretstream mode for large payloads, so audio/video encrypt and decrypt in chunks without loading everything in memory).

The **read capability** distributed to recipients is the tuple:

```
cap = { object_id, version, K, obj_sign_pub, location_hint }
```

> **As built (A2, §11):** the capability carries an *access key* rather
> than the content key `K` directly:
>
> ```
> cap = { object_id, access_key, obj_sign_pub }
> ```
>
> The access key opens a key slot in each layer header, which yields that
> layer's key. The indirection is what makes revocation survivable without
> re-granting: wrapping an object changes the layer key, but a recipient's
> access key — and therefore their capability — stays valid, so only the
> revoked party's slot disappears. `version` lives in the object header and
> `location_hint` is implied by the conversation folder.

This *is* "the public side of the object" from the owner's perspective — verification key plus content key — packaged as one opaque token. It maps exactly onto the intended model:

| Intuition | Formalization |
|---|---|
| Owner holds private + public key | Owner holds `obj_sign_priv` + the capability |
| Recipients hold the public key | Recipients hold the capability (`K` + `obj_sign_pub`) |
| Server never stores keys | Capabilities travel only peer-to-peer, encrypted to recipient identities |
| Revoke by owner's sole decision | Owner rotates `K` (and optionally the keypair) and rewrites the file |

The asymmetry does real work: recipients can **read and verify** but can never **mint, modify, or rotate** the object — any rewritten object file must carry a valid Ed25519 signature under `obj_sign_pub`, which only the owner can produce. Storage backends and servers, holding neither half, can do nothing at all.

## 4. Object file format

One object = one file, named by a random 128-bit ID (base32), revealing nothing. A simple length-prefixed container:

```
+--------------------------------------------------+
| magic "PIPL" | format version (u16)              |
+--------------------------------------------------+
| header length (u32) | header (canonical JSON)    |
+--------------------------------------------------+
| ciphertext (XChaCha20-Poly1305 secretstream)     |
+--------------------------------------------------+
| Ed25519 signature over (header ‖ ciphertext hash)|
+--------------------------------------------------+
```

The header is *inside the trust boundary* (signed) but *outside the encryption* only where necessary; it contains:

```json
{
  "object_id": "…",
  "key_version": 3,
  "content_type_enc": "…",   // content type, encrypted — not visible to storage
  "created_at_enc": "…",     // logical timestamp, encrypted
  "conversation_id": "…",    // random, meaningless to outsiders
  "obj_sign_pub": "…",
  "prev_object": "…"         // optional hash-link to previous message for ordering
}
```

Anything an outside observer shouldn't learn (content type, real timestamps, sender) lives encrypted under `K` inside the payload or in `_enc` header fields. Payloads are padded to size buckets (4 KiB / 64 KiB / 1 MiB / …) so message length leaks less.

> **As built.** The header carries two fields this schema predates —
> `slots` (the layer key encrypted once per audience access key, A2) and
> `wrapped` (marking a superencryption layer whose plaintext is a complete
> inner object file, A1) — and the whole header is bound to the ciphertext
> as AEAD associated data, so editing it breaks decryption even for a
> holder of the layer key. Sender and timestamp live in the encrypted
> payload as intended, but `content_type_enc` / `created_at_enc` are not
> yet implemented as separate encrypted header fields, and **payload
> padding is not implemented** — so message length still leaks. Both are
> tracked for v0.6.

`prev_object` gives each conversation a lightweight hash chain: clients can detect reordering or deletion by the storage provider, and derive a consistent message order without trusting file timestamps.

## 5. Granting access

Capabilities are delivered **peer-to-peer, through the same storage layer**, so the server stays keyless:

1. Owner creates the object file in the conversation folder.
2. For each recipient, the owner writes a small **grant file**: the capability, sealed to the recipient's identity key (X25519 sealed box), signed by the owner's identity key. Grant files live in the same folder under random names, or — when peers share no storage — travel as an opaque blob through the server's relay (the server sees only a sealed box addressed to an identity fingerprint; it cannot open it and stores it only transiently).
3. The server (if running) pings the recipient: "something new in conversation X." The recipient syncs, opens their grant file, caches the capability locally, decrypts the object.

Group chat is the same mechanism repeated: one object file, N grant files. (Scaling grant fan-out for large groups is an open question, §10.)

> **Refined by A2/A3 (§11).** Fan-out is now per *audience model*, not per
> recipient: a whole-roster message costs one grant file regardless of
> group size (everyone opens the same slot with the conversation group
> key, distributed once as sealed member-key files at membership time).
> Only a subset send pays one sealed grant per recipient — which is the
> price of being able to revoke them individually. Step 2 above therefore
> describes the subset case; the group case writes a single grant
> encrypted under the group key.

## 6. Revocation

Revocation is the owner unilaterally rewriting the object so that outstanding capabilities stop working. Two tiers:

**Soft revoke — stop distribution.** Owner deletes the recipient's grant file. A recipient who never fetched their grant loses access. Cheap, weak: anyone who already holds the capability is unaffected.

**Hard revoke — rotate.** Owner generates a fresh `K'` (and a fresh signing keypair if desired), re-encrypts the payload, bumps `key_version`, re-signs, and **overwrites the object file in place**. New grant files go to the still-authorized recipients; old ones are deleted. Every previously issued capability now decrypts nothing, because the ciphertext it matched no longer exists at that path. Sync (Dropbox/Drive) propagates the rewritten file to everyone automatically. Full revocation (audience = nobody) is the same operation with zero new grants — or simply deleting the file.

> **Superseded by A1/A2 (§11), which is what the code implements.** Hard
> revoke does *not* decrypt and re-encrypt: the owner wraps the existing
> ciphertext in a new signed layer whose key slots open only for the
> remaining audience. This is one encrypt pass over ciphertext the owner
> never has to open, it is reversible (hide/unhide), and — because each
> surviving recipient keeps their original access key — **no one is
> re-granted**. Read §6 for the guarantees and the version-history caveat,
> which are unchanged; read §11 for the mechanism.

### What revocation can and cannot do — stated honestly

No cryptographic design can un-share information. The precise guarantees:

- Revocation **prevents future access** through the system. It does **not** erase copies: a recipient who already decrypted may have saved the plaintext, screenshotted it, or photographed the screen. This is a law of physics, not an implementation gap; the UI must never imply otherwise.
- **Provider version history is the real adversary of hard revoke.** Dropbox and Drive retain old file versions. A revoked recipient who kept their old capability and can reach the provider's version history can fetch the *old* ciphertext and decrypt it. Mitigations, in order of strength: use storage where the owner controls history purging (own S3 bucket with versioning off, local/self-hosted sync); treat shared-history backends as "soft revoke only" in the security model; rely on the practical barrier that revoked peers typically lose folder-sharing access simultaneously (dropping both the new file *and* the history). The design must be honest that on consumer sync backends, hard revoke is best-effort.
- **Revocation latency = sync latency.** On a sync backend, propagation takes seconds to minutes and is eventually consistent. A window exists; it is small and bounded, and shrinks to near-zero when the server relay is the transport.

## 7. The server (Go)

Design rule: **the server holds no keys, no plaintext, no capabilities, and no durable content.** Compromising the server yields metadata at worst (which identity fingerprints talk, when). Everything below is optional — two peers sharing a Dropbox folder can chat with no server at all, at the cost of slower discovery.

Roles:

- **Rendezvous / directory.** Maps a user handle to identity public keys and current reachability. Trust-on-first-use with key-fingerprint verification out of band; the server can lie only by presenting a wrong key, which fingerprint checks catch.
- **Notification.** "Conversation X changed" pings so clients don't poll storage. WebSocket locally; API Gateway WebSockets + DynamoDB for connection state on AWS.
- **Sealed-blob relay (optional).** Transient mailbox for grant files and small objects when peers share no storage backend. Store-and-forward of opaque sealed boxes, deleted on delivery or TTL.
- **Blob relay (optional, later).** Same idea for large objects; or presigned-URL brokering into peers' own buckets.

Implementation shape: a single static Go binary — `net/http` + `nhooyr.io/websocket`, storage behind a small interface (in-memory / bbolt locally; DynamoDB on AWS). The same handler core mounts on Lambda via `aws-lambda-go` for the HTTP + WebSocket API, or runs as-is on an instance behind a load balancer. Go's crypto needs here are minimal by design — signature verification for API auth at most — precisely because the server is keyless.

Client-side crypto (owner and recipients) uses libsodium-compatible primitives: `golang.org/x/crypto` (curve25519, ed25519, chacha20poly1305) for a Go client; the same primitives exist in every mainstream language for future clients.

> **As built.** Notifications are **Server-Sent Events**, not WebSockets:
> the pings are one-way and contentless ("conversation X changed"), so SSE
> covers the requirement with plain `net/http` and no dependency, and
> maps more simply onto Lambda. The directory is a JSON file plus an
> in-memory map rather than bbolt/DynamoDB. The **sealed-blob relay is not
> implemented** — peers currently need a shared folder to exchange grants,
> which is the main gap between this section and reality (v0.4).
>
> Client crypto is Go standard library, not `x/crypto`: AES-256-GCM for
> content, slots and group-encrypted grants, and a hand-rolled sealed box
> (X25519 + HKDF-SHA256 + AES-GCM) in place of libsodium
> `crypto_box_seal`. Both are marked with NOTE comments at the swap
> points. The sealed-box construction is a wire format that
> cross-language clients would have to match exactly, so it is pinned by a
> golden-vector test — changing its KDF salt or info string silently
> breaks interop and no round-trip test can detect it.

## 8. Storage backend abstraction

```go
type Store interface {
    Put(ctx context.Context, path string, r io.Reader) error   // atomic replace
    Get(ctx context.Context, path string) (io.ReadCloser, error)
    Delete(ctx context.Context, path string) error
    List(ctx context.Context, prefix string) ([]Entry, error)
    Watch(ctx context.Context, prefix string) (<-chan Event, error) // may be poll-based
}
```

> **As built.** Only the local filesystem is implemented, and not yet
> behind this interface: `internal/store` exposes concrete functions
> (`WriteAtomic`, `ObjectPath`, `GrantPath`, `ListGrantFiles`, …) over a
> conversation-folder layout. `Watch` does not exist — clients learn about
> changes from server SSE pings, falling back to a 2-second folder poll
> when no server is configured. Introducing the `Store` interface is
> prerequisite work for the Dropbox/S3 backends (v0.5). The atomicity rule
> below *is* honored: every object rewrite goes through `WriteAtomic`
> (temp file + rename), which is what makes in-place hard revoke safe.

Backends: local filesystem (fsnotify for Watch), Dropbox API, Google Drive API, S3. Notes per backend:

- **Atomicity:** hard revoke must replace the object file atomically (write temp + rename locally; single PUT on object stores) so no reader ever sees a torn file.
- **Conflicts:** only the owner ever writes an object file, which eliminates most sync conflicts by construction. Grant files are single-writer too. Conversation-level indexes are avoided entirely (ordering comes from the `prev_object` hash chain).
- **History:** see §6 — backend choice determines hard-revoke strength; the client should surface this ("this conversation lives on Dropbox: revoke is best-effort").

## 9. Threat model summary

| Adversary | Sees | Can do | Defense |
|---|---|---|---|
| Storage provider | Ciphertext, random names, sizes, timing | Withhold/reorder/restore old versions | Encryption, padding, hash chain detects tampering; history caveat §6 |
| Server operator | Identity fingerprints, traffic timing — **and, for relay-backed conversations, the ciphertext itself** (A5) | Deny service, present wrong identity keys, withhold or delete relayed blobs; **cannot** read, forge or alter one | Keyless design; TOFU + fingerprint verification; per-object signature checks on every relay write; server optional for folder-backed conversations |
| Revoked recipient | Old plaintext they already saw | Keep copies; mine provider history | Honest UI; rotation; owner-controlled history where possible |
| Network observer | TLS traffic to storage/server | Traffic analysis | Standard TLS; padding; (onion routing out of scope v1) |
| Malicious recipient | Everything shared with them | Re-share content | Out of scope — unsolvable by cryptography |

Non-goals for v0.1: forward secrecy per message (per-object keys already limit blast radius; a ratchet can layer on later), anonymity against traffic analysis, deniability.

## 10. Open questions

1. **Group scale.** N grant files per object is fine for small groups; for large ones, a per-conversation key epoch (rotated on membership change, MLS-style) would replace per-object fan-out. Decide when groups >20 matter.
   *Largely resolved by A2/A3 (§11):* the key epoch exists, so a
   whole-roster message is one grant at any group size, and only subset
   sends pay per-recipient fan-out — bounded by the subset, not the
   roster. What remains open is the **rotation** half: `conv rekey` is
   unbuilt, so a member cannot yet be revoked from a group-keyed message
   (v0.4). Until then the client steers users to a subset send when they
   expect to revoke someone, or to `hide` for everyone.
2. **Multi-device.** Same identity on phone + laptop means syncing identity private keys between devices (QR-code pairing?) or a device-key hierarchy.
3. **Capability caching policy.** Clients must cache capabilities locally (grants may be revoked); how that cache is encrypted at rest on the client.
4. **Storage quota & garbage collection.** Who prunes old conversations; tombstones for deleted objects.
5. **Abuse.** Revocation is also a tool for message-unsend UX ("delete for everyone") — worth designing the UI language around what it truly guarantees.
   *Partly settled:* every revoke and hide in the client states that
   revocation cannot un-share, and the composer names the audience model
   in force so the user knows, before sending, whether individual
   revocation will be possible. Treated as a product requirement, not
   polish — see the ground rules in `CLAUDE.md`.
6. **Metadata in the conversation marker.** `pipl-conv.json` sits
   unencrypted in the shared folder with the member handles in it, and
   slot count leaks audience size (A2). An encrypted roster plus dummy
   slots would close both; neither is built.

## 11. Amendments (adopted during v0.1 prototyping)

**A1 — Revocation by superencryption (Antonio, 2026-07-23).** Instead of
decrypt-and-re-encrypt, the owner *wraps the existing ciphertext* in a new
signed encryption layer. One encrypt pass, plaintext never touched, and
reversible: peeling the layer restores the previous audience ("hide/unhide"
semantics — visibility can be suspended and restored without re-granting).
The version-history caveat of §6 applies unchanged; layers accumulate one
per wrap, flattened by an occasional compaction re-encrypt.

**A2 — Key slots and two audience models (Antonio, 2026-07-23).** Each
layer's header carries key slots (LUKS-style): the layer key encrypted once
per audience *access key*. Two audience models per message: a **group**
shares one access key — one slot and one grant regardless of group size
(the group key is distributed once per epoch as sealed member-key files);
a **separate send** mints a personal access key per recipient — one slot
each, making any recipient hard-revocable alone by re-wrapping with slots
for the rest, with no re-granting of the others. This resolves open
question §10.1: per-member revocation inside a group is group-key rotation
(a new epoch), which re-keys membership without touching individual
objects. Cost: slot count leaks audience size (mitigable with dummy slots).

**A3 — Per-message recipient selection (Antonio, 2026-07-23).** The two
audience models of A2 are no longer a mode the sender sets explicitly; they
follow from *who the sender picks* for a given message. Within one
conversation:

- **whole roster** → the shared group key: one slot, one grant file, any
  group size (unchanged from A2);
- **a subset** → per-recipient access keys: one slot and one sealed grant
  each, and **members outside the subset get no slot at all**.

Exclusion is therefore cryptographic rather than a display convention: an
omitted member who scans every grant file in the folder still finds no slot
their access key opens. Each chosen recipient remains individually
hard-revocable per A2, by re-wrapping with slots for the rest.

The rule is forced, not chosen: per-message recipient selection is only
expressible with per-recipient keys, because a single shared group key
cannot distinguish members. A subset send *is* A2's separate send, selected
automatically. The explicit "separate" flag survives only to force personal
keys for a message that happens to go to everyone (useful when the sender
expects to revoke someone later).

Consequence for the interface: the client must always show which audience
model a send will use, since the two differ in what revocation will later be
possible — a group-keyed message cannot have one member revoked without a
group-key rotation (§10.1), while a subset send can. A nil recipient list
means "everyone"; an empty one means "nobody" and must be refused, never
silently widened to the roster.

**A4 — Two front ends, one engine (2026-07-23).** The client is an
interactive terminal UI (Bubble Tea) with the flag-driven commands retained
for scripting and demos. Both are thin: all send/receive/revoke logic lives
in a single headless engine (`internal/chat`), so the two interfaces cannot
diverge on anything security-relevant. Front ends may not perform
cryptography or reach into key material. This is the first departure from
standard-library-only dependencies; the constraint was an artifact of the
sandbox the prototype was written in, and no external module touches key
material.

**A5 — The relay is durable, not store-and-forward (2026-07-23).** §7
specifies the sealed-blob relay as a *transient* mailbox, "deleted on
delivery or TTL", preserving the rule that the server holds no durable
content. Building it revealed that this is incompatible with the project's
central feature: **revocation works by rewriting a stored object**, so a
blob deleted on delivery can never be revoked, hidden, or unhidden. It
would also mean no scrollback and no second device. The relay is therefore
durable — the server stores ciphertext until the owner deletes it.

The keyless invariant is untouched: the server holds no key, no plaintext
and no capability, and cannot decrypt anything it stores. What it gains is
an authorization duty, discharged without any secret:

- The first write of an object ID records the Ed25519 signing key from
  that object's own signed header.
- Every later write must verify under the *same* key. Only the owner holds
  the private half, so only the owner can rewrite an object — the network
  equivalent of the filesystem's write permission.
- Deletion requires a signature over a domain-separated challenge
  (`pipl/relay/delete/v1:<object-id>`), so a signature cannot be replayed
  from another context or against another object.

Sealed grants carry no server-verifiable author, so they are append-only
and their deletion is authorized only by knowing the random blob ID. That
is the same exposure a shared folder gives anyone who can list it, and
soft revoke is documented as the weak tier regardless (§6).

Honest cost of the change: the threat model in §9 shifts. A compromised
server now yields **ciphertext plus metadata** (who talks to whom, when,
message sizes and count) rather than metadata alone, and it becomes an
availability dependency for folderless conversations — it can withhold or
delete blobs, though it cannot forge or read one. Peers who share a folder
still need no server at all, and that remains the stronger configuration.
The v0.1 "no durable content" promise survives only for folder-backed use.

**A6 — Invite codes (2026-07-23).** A folderless conversation has nowhere
to put the marker of §5, so its facts (conversation ID, creator, roster)
travel as a pasteable code instead. An invite is **not** a capability and
carries no key: access still requires a member-key blob sealed to the
joiner's identity and signed by the creator, so a stolen invite reveals
only the roster — metadata the server and storage provider already hold —
and reads nothing. Folder conversations also emit one, as a convenience
that carries the folder path as a hint.

## 12. Roadmap

Status as built; see `docs/STATUS.md` for detail and known shortcuts.

- **v0.1 — done.** Object encode/decode + sign/verify, local-filesystem
  Store, CLI `send` / `recv` / `revoke`. Peers sharing a folder.
- **v0.2 — done.** Rendezvous + notification server (single binary, SSE
  rather than WebSocket — sufficient for one-way change pings and simpler
  to mount on Lambda). Superencryption revocation and key slots (A1, A2):
  `hide` / `unhide`, per-recipient hard revoke.
- **v0.3 — done.** Interactive UI over a shared engine (A4);
  per-message recipient selection (A3); unit tests for the object, grant
  and identity layers, with the sealed-box wire format pinned by a golden
  vector.
- **v0.4 — done.** The blob relay (§7, amended by A5): peers with no
  shared folder chat through the server, which stores ciphertext it
  cannot decrypt and authorizes rewrites by signature. Joining is an
  invite code (A6). Revoke, hide and unhide all work over the network.
- **v0.5 (next).** `conv rekey` — group-key epoch rotation, which is what
  closes §10.1 for group-keyed messages. Then relay persistence (blobs
  are in-memory today, so a server restart loses them).
- **v0.6.** Dropbox / S3 backends behind the §8 `Store` interface, with
  hard-revoke semantics validated against provider version history (§6);
  Lambda deployment.
- **v0.7.** Multi-device pairing (§10.2); dummy slots and payload padding
  (§4); a `compact` operation to flatten long wrap chains (A1).

Deviations from the original plan worth noting: the server arrived with
SSE instead of WebSockets, and the relay is durable rather than
store-and-forward (A5, with the threat-model consequences recorded there).
Relay blobs live in memory, so a server restart loses them — a storage
backend, not a protocol, concern. AEAD is AES-256-GCM throughout rather
than the XChaCha20-Poly1305 secretstream of §3/§4; that swap matters when
large media payloads land, since streaming is what secretstream buys.
