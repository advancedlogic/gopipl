#!/usr/bin/env bash
# NO SHARED FOLDER. Peers exchange everything through the server's blob
# relay, which stores ciphertext it cannot decrypt. Joining is a pasted
# invite code — no path to agree on.
#
# The server verifies each object's signature, so only an object's owner
# can rewrite or delete it: revocation still works over the network.
set -euo pipefail

ROOT=$(mktemp -d)
trap 'kill $SERVER_PID 2>/dev/null || true; rm -rf "$ROOT"' EXIT
cd "$(dirname "$0")"
PORT=8739
SRV="http://127.0.0.1:$PORT"

echo "== build =="
go build -o "$ROOT/bin/" ./cmd/...

echo
echo "== start server (identity directory + notifications + blob relay) =="
if curl -s -o /dev/null --max-time 1 "$SRV/v1/identities/_probe" 2>/dev/null; then
  echo "FAIL: something is already listening on 127.0.0.1:$PORT — stop it first" >&2
  exit 1
fi
"$ROOT/bin/pipl-server" -addr "127.0.0.1:$PORT" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 0.5
kill -0 "$SERVER_PID" 2>/dev/null || { echo "FAIL: server did not start" >&2; exit 1; }

p() { "$ROOT/bin/pipl" -home "$ROOT/$1" "${@:2}"; }

echo
echo "== four identities =="
for u in alice bob carol dave; do p $u init -handle $u -server "$SRV" >/dev/null; echo "  $u"; done

echo
echo "== alice starts a conversation with NO -dir =="
OUT=$(p alice conv new -name team -with bob,carol,dave 2>&1)
echo "$OUT" | head -1 | sed 's/^/  /'
CODE=$(echo "$OUT" | tail -1)
echo "  invite: ${CODE:0:48}..."

echo
echo "== the others join with the code alone =="
for u in bob carol dave; do p $u conv join -name team -invite "$CODE" 2>/dev/null | sed 's/^/  /'; done

echo
echo "== no folder exists anywhere: only per-peer state dirs =="
find "$ROOT" -maxdepth 1 -mindepth 1 -type d | sed "s|$ROOT|  |"

echo
echo "== messages =="
p alice send -conv team "hello over the relay" 2>/dev/null | sed 's/^/  /'
# A genuine SUBSET of the roster (not dave) => per-recipient keys, so any
# one of them can be revoked alone.
OID=$(p alice send -conv team -to bob,carol "bob+carol only, no folder involved" 2>/dev/null | awk '/^sent/{print $2}')

echo
for u in bob carol dave; do echo "--- $u ---"; p $u recv -conv team 2>/dev/null | sed 's/^/    /'; done

fail=0
check() { if [ "$1" = "$2" ]; then echo "  OK: $3"; else echo "  FAIL: $3"; fail=1; fi }
sees() { p "$1" recv -conv team 2>/dev/null | grep -c "$2"; }

echo
echo "== assertions =="
check "$(sees bob 'bob+carol only')" 1 "bob reads the subset message"
check "$(sees carol 'bob+carol only')" 1 "carol reads the subset message"
check "$(sees dave 'bob+carol only')" 0 "dave is cryptographically excluded"
check "$(sees dave 'hello over the relay')" 1 "dave still reads the group message"

echo
echo "== is plaintext visible to the server? =="
# Pull every blob the relay holds for this conversation and grep it.
CONV=$(grep -o '"id": *"[^"]*"' "$ROOT/alice/conversations.json" | head -1 | cut -d'"' -f4)
BLOBS=$(curl -s "$SRV/v1/blobs/$CONV")
echo "  relay holds $(echo "$BLOBS" | grep -o '"id"' | wc -l) blobs for this conversation"
DUMP="$ROOT/dump"; : > "$DUMP"
for id in $(echo "$BLOBS" | grep -o '"id":"[^"]*"' | cut -d'"' -f4); do
  curl -s "$SRV/v1/blobs/$CONV/$id" >> "$DUMP"
done
if grep -q "bob+carol only" "$DUMP" || grep -q "hello over the relay" "$DUMP"; then
  echo "  FAIL: plaintext readable from the relay"; fail=1
else
  echo "  OK: everything the server holds is ciphertext"
fi

echo
echo "== alice hard-revokes CAROL — over the network, with no folder =="
echo "   (the server accepts the rewrite only because it verifies alice's"
echo "    object signature; nobody else could replace this object)"
p alice revoke -conv team -object "$OID" -from carol 2>&1 | head -1 | sed 's/^/  /'
check "$(sees carol 'bob+carol only')" 0 "carol hard-revoked over the relay"
check "$(sees bob   'bob+carol only')" 1 "bob unaffected — zero re-grants"

echo
echo "== hide / unhide over the relay =="
p alice hide -conv team -object "$OID" 2>&1 | sed 's/^/  /'
check "$(sees bob 'bob+carol only')" 0 "hidden object unreadable"
p alice unhide -conv team -object "$OID" 2>&1 | sed 's/^/  /'
check "$(sees bob 'bob+carol only')" 1 "unhide restored access, nothing re-granted"

echo
echo "== relay storage survives a server restart (-blobs) =="
# The relay is memory-only unless -blobs is given. Restart the server with
# persistence on and confirm a conversation — and a revocation — outlive it.
kill $SERVER_PID 2>/dev/null || true
sleep 0.4
BLOBS="$ROOT/blobs"
"$ROOT/bin/pipl-server" -addr "127.0.0.1:$PORT" -blobs "$BLOBS" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 0.5
# Everything from before was memory-only, so start fresh on the new store.
p alice conv new -name durable -with bob >/dev/null 2>&1
DCODE=$(p alice conv invite -name durable)
p bob conv join -name durable -invite "$DCODE" >/dev/null 2>&1
p alice send -conv durable "written to disk" >/dev/null 2>&1
DOID=$(p alice send -conv durable "then hidden" 2>/dev/null | awk '/^sent/{print $2}')
p alice hide -conv durable -object "$DOID" >/dev/null 2>&1

kill $SERVER_PID 2>/dev/null || true
sleep 0.4
"$ROOT/bin/pipl-server" -addr "127.0.0.1:$PORT" -blobs "$BLOBS" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 0.6

dsees() { p "$1" recv -conv durable 2>/dev/null | grep -c "$2"; }
check "$(dsees bob 'written to disk')" 1 "message survived the server restart"
check "$(dsees bob 'then hidden')"     0 "hide survived the restart (revocation not undone)"

echo
if [ "$fail" -eq 0 ]; then echo "== all assertions passed =="; else echo "== FAILURES ABOVE =="; exit 1; fi
