#!/usr/bin/env bash
# Per-message recipient selection: within ONE conversation, a message can
# go to the whole roster (shared group key) or to a chosen subset
# (per-recipient keys). Members outside the subset get no key slot, so the
# exclusion is cryptographic, not a UI convention.
set -euo pipefail

ROOT=$(mktemp -d)
trap 'kill $SERVER_PID 2>/dev/null || true; rm -rf "$ROOT"' EXIT
cd "$(dirname "$0")"

echo "== build =="
go build -o "$ROOT/bin/" ./cmd/...
PIPL="$ROOT/bin/pipl"

echo
echo "== start keyless server =="
# See demo.sh: a leftover server on this port would serve a stale identity
# directory and make this demo fail confusingly.
if curl -s -o /dev/null --max-time 1 http://127.0.0.1:8738/v1/identities/_probe 2>/dev/null; then
  echo "FAIL: something is already listening on 127.0.0.1:8738 — stop it first" >&2
  exit 1
fi
"$ROOT/bin/pipl-server" -addr 127.0.0.1:8738 >/dev/null 2>&1 &
SERVER_PID=$!
sleep 0.5
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "FAIL: server did not start" >&2; exit 1
fi

alice() { PIPL_HOME="$ROOT/alice" "$PIPL" "$@"; }
bob()   { PIPL_HOME="$ROOT/bob"   "$PIPL" "$@"; }
carol() { PIPL_HOME="$ROOT/carol" "$PIPL" "$@"; }
dave()  { PIPL_HOME="$ROOT/dave"  "$PIPL" "$@"; }
SHARED="$ROOT/shared"
SRV=http://127.0.0.1:8738

echo
echo "== four identities =="
for u in alice bob carol dave; do
  PIPL_HOME="$ROOT/$u" "$PIPL" init -handle $u -server $SRV >/dev/null
  echo "  $u"
done

echo
echo "== one conversation, four members =="
alice conv new  -name team -dir "$SHARED" -with bob,carol,dave >/dev/null 2>&1
for u in bob carol dave; do
  PIPL_HOME="$ROOT/$u" "$PIPL" conv join -name team -dir "$SHARED" >/dev/null 2>&1
done
echo "  team: alice, bob, carol, dave"

echo
echo "== message 1: to EVERYONE (one shared group key) =="
alice send -conv team "morning all" 2>/dev/null

echo
echo "== message 2: to BOB + CAROL only (per-recipient keys) =="
OID=$(alice send -conv team -to bob,carol "bob+carol only: the deploy slipped" 2>/dev/null | awk '{print $2}')

echo
echo "== who can read what =="
for u in bob carol dave; do
  echo "--- $u ---"
  PIPL_HOME="$ROOT/$u" "$PIPL" recv -conv team 2>/dev/null | sed 's/^/    /'
done

echo
echo "== assertions =="
fail=0
for u in bob carol; do
  if PIPL_HOME="$ROOT/$u" "$PIPL" recv -conv team 2>/dev/null | grep -q "deploy slipped"; then
    echo "  OK: $u (a chosen recipient) can read the subset message"
  else
    echo "  FAIL: $u should have been able to read it"; fail=1
  fi
done
if PIPL_HOME="$ROOT/dave" "$PIPL" recv -conv team 2>/dev/null | grep -q "deploy slipped"; then
  echo "  FAIL: dave read a message he was excluded from"; fail=1
else
  echo "  OK: dave has no key slot — cryptographically excluded"
fi
if grep -rq "deploy slipped" "$SHARED"; then
  echo "  FAIL: plaintext found in the shared folder"; fail=1
else
  echo "  OK: no plaintext anywhere in the shared folder"
fi

echo
echo "== alice revokes CAROL from message 2 (bob keeps his original grant) =="
alice revoke -conv team -object "$OID" -from carol 2>/dev/null | sed 's/^/  /'

echo
echo "--- carol ---"
carol recv -conv team 2>/dev/null | sed 's/^/    /'
echo "--- bob (unchanged, never re-granted) ---"
bob recv -conv team 2>/dev/null | sed 's/^/    /'

if carol recv -conv team 2>/dev/null | grep -q "deploy slipped"; then
  echo "  FAIL: carol still reads it after revocation"; fail=1
else
  echo "  OK: carol hard-revoked"
fi
if bob recv -conv team 2>/dev/null | grep -q "deploy slipped"; then
  echo "  OK: bob unaffected — zero re-grants"
else
  echo "  FAIL: bob lost access when carol was revoked"; fail=1
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "== all assertions passed =="
else
  echo "== FAILURES ABOVE =="; exit 1
fi
