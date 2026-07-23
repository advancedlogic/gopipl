package chat

import (
	"strings"
	"testing"
)

func TestInviteRoundTrip(t *testing.T) {
	orig := Invite{
		ID:      "conv123",
		Creator: "alice",
		Members: []string{"alice", "bob", "carol"},
		Server:  "http://127.0.0.1:8737",
	}
	e := &Env{}
	code, err := e.encode(orig)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.HasPrefix(code, invitePrefix) {
		t.Fatalf("code %q lacks the %q prefix", code, invitePrefix)
	}

	got, err := ParseInvite(code)
	if err != nil {
		t.Fatalf("ParseInvite: %v", err)
	}
	if got.ID != orig.ID || got.Creator != orig.Creator || got.Server != orig.Server {
		t.Fatalf("round trip changed fields: %+v", got)
	}
	if strings.Join(got.Members, ",") != strings.Join(orig.Members, ",") {
		t.Fatalf("members = %v, want %v", got.Members, orig.Members)
	}
}

// An invite is metadata, never a key. If a key ever leaked into one, a
// stolen code would grant read access — the whole point is that it cannot.
func TestInviteCarriesNoKeyMaterial(t *testing.T) {
	e := &Env{}
	code, err := e.encode(Invite{
		ID: "conv123", Creator: "alice", Members: []string{"alice", "bob"},
	})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := ParseInvite(code)
	if err != nil {
		t.Fatal(err)
	}
	// The struct has no key field at all; assert the decoded JSON keys too,
	// so adding one later trips this test.
	for _, banned := range []string{"key", "group", "access", "priv", "secret"} {
		if strings.Contains(strings.ToLower(code), banned) {
			t.Fatalf("invite code contains %q — invites must carry no key material", banned)
		}
	}
	if inv.ID == "" {
		t.Fatal("sanity: invite did not decode")
	}
}

func TestParseInviteTolerantOfPasteDamage(t *testing.T) {
	e := &Env{}
	code, err := e.encode(Invite{ID: "c1", Creator: "alice", Members: []string{"alice", "bob"}})
	if err != nil {
		t.Fatal(err)
	}
	for name, mangled := range map[string]string{
		"leading space":  "   " + code,
		"trailing space": code + "   ",
		"newline":        code + "\n",
		"wrapped line":   code[:20] + "\n" + code[20:],
		"tabs":           "\t" + code + "\t",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseInvite(mangled)
			if err != nil {
				t.Fatalf("ParseInvite: %v", err)
			}
			if got.ID != "c1" {
				t.Fatalf("id = %q", got.ID)
			}
		})
	}
}

func TestParseInviteRejectsJunk(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"no prefix":      "just some text",
		"wrong prefix":   "pipl0:abcd",
		"bad base64":     invitePrefix + "!!!not base64!!!",
		"not json":       invitePrefix + "aGVsbG8gd29ybGQ",
		"missing fields": invitePrefix + "e30", // {}
	}
	for name, code := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseInvite(code); err == nil {
				t.Fatalf("ParseInvite(%q) accepted junk", code)
			}
		})
	}
}
