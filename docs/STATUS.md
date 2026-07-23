# PIPL prototype — status (2026-07-23)

## v0.3 (current)

Interactive Bubble Tea front end, plus per-message recipient selection.

- `pipl` with no arguments opens the UI; every flag subcommand still
  works. Both front ends call `internal/chat`, a headless engine holding
  the send/receive/revoke logic, so they cannot drift on anything
  security-relevant.
- **Per-message recipient subsets**: within one conversation, a message
  goes to the whole roster (shared group key) or to a chosen subset
  (per-recipient keys, one slot each). Excluded members get no slot, so
  exclusion is cryptographic. `-to bob,carol` on the CLI, or the
  recipient panel in the UI. Verified by `demo-recipients.sh`.
- The UI surfaces which audience model a send will use, TOFU
  fingerprints on first contact, and the honest-limitation notices.

Stdlib-only no longer holds: Bubble Tea / Bubbles / Lipgloss are
dependencies. No external module touches key material.

## v0.2

Two design amendments (Antonio), both implemented and verified end-to-end
by `demo.sh`:

1. **Revocation by superencryption**: the owner wraps the existing
   ciphertext in a new signed layer — no decrypt, one pass, reversible.
   Enables `pipl hide` / `pipl unhide`: hide = wrap with zero key slots
   (all grants inert); unhide = peel the layer (all old grants valid
   again, no re-granting).
2. **Key slots + two audience models**: each layer header carries the
   layer key encrypted per audience access key (LUKS-style slots).
   Group send (default) = one shared group key (distributed once as
   sealed `.mkey` files at conversation creation) = one slot + one grant
   file, any group size. Separate send (`-separate`) = personal access
   key per recipient = per-recipient hard revoke by re-wrapping with
   slots for the rest — the others' grants are never touched.

Demo (3 peers) verifies: group + separate sends, no plaintext on disk,
revoking carol alone (bob unaffected, zero re-grants), hide/unhide round
trip, live `recv -follow` via SSE. See `docs/design.md` §11 for the
amendment rationale.

## Stack

Go 1.24, standard library only (no external modules — written in a
sandbox without module-proxy access; feel free to introduce x/crypto).
Keyless server (identity directory with TOFU + SSE notifications).
CLI: `init` / `conv new` / `conv join` / `send [-separate]` /
`recv [-follow]` / `revoke [-soft|-all]` / `hide` / `unhide`.

## Known prototype shortcuts (flagged with NOTE comments in code)

- AES-256-GCM everywhere; design doc specifies XChaCha20-Poly1305
  secretstream for large media (`internal/object/object.go`).
- Homegrown stdlib sealed box (X25519 + HKDF-SHA256 + AES-GCM); design
  doc specifies libsodium `crypto_box_seal` for cross-language clients
  (`internal/identity/identity.go`).
- Slot count leaks audience size; member handles visible in
  `pipl-conv.json` (dummy slots / encrypted roster later).
- `internal/{object,grant,identity}` have unit tests (`go test ./...`,
  ~82-86% statement coverage); `internal/tui` covers the recipient-
  selection and setup logic. `internal/{state,store,api}` and the flag
  commands are still covered only by the demo scripts.
- The UI's `unhide` picks the first hidden object in the conversation
  rather than letting you choose, because hidden messages are (by
  design) invisible in the history list.
- `conv rekey` is still missing, so revoking one member of a
  whole-roster send is not possible — the UI says so and points at
  hide or a subset send.

## Next steps (in rough priority order)

1. `conv rekey` — group key epoch rotation = per-member revocation for
   group sends (reseal new key to remaining members; new objects use the
   new epoch; optionally wrap old objects to cut the removed member).
2. Server grant relay — sealed-blob mailbox so peers without a shared
   folder can exchange grants/objects (design doc §7).
3. Dropbox/S3 Store backends behind internal/store interface; validate
   hard-revoke semantics against provider version history.
4. Lambda deployment of the server (handlers are stdlib http, designed
   to mount behind aws-lambda-go).
5. Dummy slots + payload padding; `compact` op to flatten long wrap
   chains; tests for the CLI/state/store layers.
