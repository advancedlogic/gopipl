package chat

import (
	"strings"
	"testing"

	"github.com/antonio/pipl/internal/identity"
	"github.com/antonio/pipl/internal/state"
)

func TestUnpin(t *testing.T) {
	dir := t.TempDir()
	me, err := identity.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	st := &state.State{Home: dir}
	if err := me.Save(st.IdentityPath()); err != nil {
		t.Fatal(err)
	}
	env := &Env{St: st, ID: me}

	// Pin a peer, then a re-created version with different keys.
	bobV1, _ := identity.New("bob")
	if err := st.PinPeer(bobV1.Public()); err != nil {
		t.Fatal(err)
	}
	bobV2, _ := identity.New("bob") // same handle, new keys
	if err := st.PinPeer(bobV2.Public()); err == nil {
		t.Fatal("TOFU should have refused bob's changed keys while v1 is pinned")
	}

	// Unpin drops v1 and reports its fingerprint.
	fp, ok, err := env.Unpin("bob")
	if err != nil || !ok {
		t.Fatalf("Unpin: ok=%v err=%v", ok, err)
	}
	if fp != bobV1.Public().Fingerprint() {
		t.Fatalf("reported fingerprint %s, want the dropped v1 %s", fp, bobV1.Public().Fingerprint())
	}

	// Now the new bob pins cleanly.
	if err := st.PinPeer(bobV2.Public()); err != nil {
		t.Fatalf("after unpin, v2 should pin: %v", err)
	}

	// Unpinning an unknown handle is a no-op, not an error.
	if _, ok, err := env.Unpin("nobody"); err != nil || ok {
		t.Fatalf("unpin unknown: ok=%v err=%v, want false/nil", ok, err)
	}
	// Refuse to unpin yourself.
	if _, _, err := env.Unpin("alice"); err == nil {
		t.Fatal("Unpin should refuse to forget your own identity")
	}
}

// When a member is listed but no member key opens for them — the stale-pin
// case the user hit — the error must name the cause and the fix, not just
// say "no valid member key".
func TestJoinDiagnosesStalePinMismatch(t *testing.T) {
	dir := t.TempDir()

	// The joiner's real identity.
	me, err := identity.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	st := &state.State{Home: dir}
	if err := me.Save(st.IdentityPath()); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveConfig(state.Config{}); err != nil {
		t.Fatal(err)
	}
	env := &Env{St: st, ID: me}

	// A conversation that lists alice as a member, but whose only member
	// key was sealed to a DIFFERENT alice (simulate: no key sealed to us at
	// all, which is what a stale pin produces). Relay-less, folder-based so
	// the test needs no server.
	convDir := t.TempDir()
	m := Marker{ID: "conv1", Creator: "linus", Members: []string{"alice", "linus"}}

	// Pin a "linus" creator so the lookup succeeds.
	linus, _ := identity.New("linus")
	if err := st.PinPeer(linus.Public()); err != nil {
		t.Fatal(err)
	}

	_, err = env.join("simple", convDir, m, nil)
	if err == nil {
		t.Fatal("expected join to fail with no member key")
	}
	msg := err.Error()
	// The message must point at the real cause and the fix.
	for _, want := range []string{"listed as a member", "older copy", "re-create"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error does not mention %q:\n%s", want, msg)
		}
	}
}
