package chat

import (
	"strings"
	"testing"

	"github.com/antonio/pipl/internal/identity"
	"github.com/antonio/pipl/internal/state"
)

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
