package chat

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/antonio/pipl/internal/state"
)

// Invite is what one peer hands another so they can join a conversation:
// the same facts a folder marker carries, in a form you can paste into a
// chat window.
//
// An invite is NOT a secret and NOT a capability. It names a conversation
// and its roster; it contains no key. Access still requires a member-key
// blob sealed to your identity and signed by the creator, so someone who
// steals an invite learns only who is talking — the same metadata the
// server and the storage provider already see — and can read nothing.
type Invite struct {
	ID      string   `json:"i"`
	Creator string   `json:"c"`
	Members []string `json:"m"`
	// Server is the relay a folderless conversation lives on, recorded so
	// the joiner can tell they need one (and which).
	Server string `json:"s,omitempty"`
	// Dir is set only for folder-backed conversations, as a hint. The
	// joiner may override it: the path is almost always different on
	// another machine.
	Dir string `json:"d,omitempty"`
}

const invitePrefix = "pipl1:"

// Invite builds the code for a conversation this peer can already reach.
func (e *Env) Invite(convName string) (string, error) {
	conv, err := e.Conversation(convName)
	if err != nil {
		return "", err
	}
	return e.inviteFor(conv)
}

func (e *Env) inviteFor(conv state.Conversation) (string, error) {
	inv := Invite{
		ID:      conv.ID,
		Creator: conv.Creator,
		Members: conv.Members,
		Dir:     conv.Dir,
	}
	if conv.Dir == "" {
		inv.Server = e.Cfg.Server
	}
	return e.encode(inv)
}

// encode serializes an invite to its pasteable form.
func (e *Env) encode(inv Invite) (string, error) {
	data, err := json.Marshal(inv)
	if err != nil {
		return "", err
	}
	return invitePrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// ParseInvite decodes a code produced by Invite. Whitespace is tolerated
// because these get copied through chat clients and terminals.
func ParseInvite(code string) (Invite, error) {
	code = strings.TrimSpace(code)
	// Tolerate a pasted line that wrapped.
	code = strings.Join(strings.Fields(code), "")
	if !strings.HasPrefix(code, invitePrefix) {
		return Invite{}, fmt.Errorf("not a pipl invite code (should start with %q)", invitePrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, invitePrefix))
	if err != nil {
		return Invite{}, fmt.Errorf("malformed invite code: %w", err)
	}
	var inv Invite
	if err := json.Unmarshal(raw, &inv); err != nil {
		return Invite{}, fmt.Errorf("malformed invite code: %w", err)
	}
	if inv.ID == "" || inv.Creator == "" || len(inv.Members) == 0 {
		return Invite{}, fmt.Errorf("invite code is missing required fields")
	}
	return inv, nil
}
