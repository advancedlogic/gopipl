#!/usr/bin/env bash
# End-to-end demo: three peers (alice, bob, carol), a shared folder as the
# storage backend, and the keyless coordination server.
#
# Shows both audience models:
#   group send    — everyone shares ONE group key: one slot, one grant file
#   separate send — per-recipient access keys: each recipient revocable
#                   on their own, with NO re-granting of the others
set -euo pipefail

ROOT=$(mktemp -d)
trap 'kill $SERVER_PID 2>/dev/null || true; rm -rf "$ROOT"' EXIT
cd "$(dirname "$0")"

echo "== build =="
go build -o "$ROOT/bin/" ./cmd/...
PIPL="$ROOT/bin/pipl"

echo
echo "== start keyless server =="
"$ROOT/bin/pipl-server" -addr 127.0.0.1:8737 &
SERVER_PID=$!
sleep 0.5

alice() { PIPL_HOME="$ROOT/alice" "$PIPL" "$@"; }
bob()   { PIPL_HOME="$ROOT/bob"   "$PIPL" "$@"; }
carol() { PIPL_HOME="$ROOT/carol" "$PIPL" "$@"; }
SHARED="$ROOT/shared"

echo
echo "== identities =="
alice init -handle alice
bob   init -handle bob
carol init -handle carol

echo
echo "== group conversation over a shared folder =="
alice conv new  -name chat -dir "$SHARED" -with bob,carol
bob   conv join -name chat -dir "$SHARED"
carol conv join -name chat -dir "$SHARED"

echo
echo "== GROUP send: one slot + one grant file, any group size =="
OID1=$(alice send -conv chat "hello group (one shared key)" | awk '{print $2}')
sleep 0.1

echo "== SEPARATE send: per-recipient keys =="
OID2=$(alice send -conv chat -separate "sensitive: sent with per-recipient keys" | awk '{print $2}')
echo "object ids: group=$OID1 separate=$OID2"
echo "grant files in folder: $(ls "$SHARED/grants/" | grep -c '\.grant$') (1 group + 3 separate)"

echo
echo "== bob and carol both read =="
bob   recv -conv chat
carol recv -conv chat

echo
echo "== nothing on disk is plaintext =="
if grep -rq "hello group" "$SHARED"; then
  echo "FAIL: plaintext found in shared folder"; exit 1
else
  echo "OK: no plaintext anywhere in the shared folder"
fi

echo
echo "== alice revokes CAROL from the separate send (bob keeps his original grant) =="
alice revoke -conv chat -object "$OID2" -from carol

echo
echo "== carol reads (separate message must be gone for her) =="
carol recv -conv chat
echo "== bob reads (still sees it — his grant was never touched) =="
bob recv -conv chat

echo
echo "== alice HIDES the group message (wrap with zero slots) =="
alice hide -conv chat -object "$OID1"
echo "== bob reads (hidden message gone) =="
bob recv -conv chat

echo
echo "== alice UNHIDES it (peels the layer; everyone's grants work again) =="
alice unhide -conv chat -object "$OID1"
echo "== bob reads (message is back, nothing was re-granted) =="
bob recv -conv chat
echo "== carol reads (group message back for her too; separate one still revoked) =="
carol recv -conv chat

echo
echo "== demo complete =="
