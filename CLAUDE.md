# PIPL — context for Claude Code

P2P chat where every object (message) is an encrypted, signed file on a
shared filesystem; the sender retains per-object revocation power; the
server is keyless (identity directory + notifications only).

Read these first:

- `docs/design.md` — full architecture and threat model. §3 (key model),
  §6 (revocation) and §11 (amendments: superencryption + key slots) are
  the core; the code implements exactly these.
- `docs/STATUS.md` — what is done, known shortcuts, prioritized next steps.
- `README.md` — build, CLI usage, demo.

Ground rules that matter when extending:

- The server must NEVER see keys, plaintext, or capabilities. All crypto
  stays in `internal/{chat,object,grant,identity}`.
- `internal/chat` is the single engine behind both front ends (the Bubble
  Tea UI in `internal/tui` and the flag commands in `cmd/pipl`). Put
  security-relevant logic there, never in a front end, so the two cannot
  drift.
- Revocation is wrap-based (superencryption), never decrypt-and-re-encrypt.
  Access is governed by key slots in the layer header. Keep both invariants.
- Object files are rewritten only via `store.WriteAtomic`.
- Honest-limitation messaging (revocation cannot un-share; version-history
  caveat) is a product feature — don't remove it from CLI or UI output.
  The UI must also keep naming which audience model a send will use.
- A nil recipient list means "everyone" (group key); an empty one means
  "nobody" and must never be sent. Use `everyoneSelected`/`noneSelected`
  rather than testing for nil — conflating them once caused a
  deselect-all to send to the whole roster.
- External deps are fine (the stdlib-only origin was a sandbox artifact),
  but nothing outside `internal/` should touch key material. x/crypto or
  libsodium bindings are welcome — swap points flagged with NOTE comments.

Verify changes with:

    go build ./... && go vet ./... && go test ./... && ./demo.sh && ./demo-recipients.sh

The demos assert the security-relevant behaviors (no plaintext on disk,
per-recipient revoke without re-granting, hide/unhide round trip,
cryptographic exclusion of non-recipients). The sealed-box wire format is
pinned by a golden vector — if you change the KDF, read the comment on
`TestSealedBoxFormatIsStable` before regenerating it.
