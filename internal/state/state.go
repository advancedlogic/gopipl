// Package state manages the CLI's local state directory ($PIPL_HOME,
// default ~/.pipl): identity keys, server config, known conversations,
// pinned peer identities (TOFU), and — for objects this peer owns — the
// private key material that makes revocation possible.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/antonio/pipl/internal/identity"
)

type Config struct {
	Server string `json:"server,omitempty"`
	// ServerCertPin, when set, is the hex SHA-256 of the server's TLS
	// certificate. The client trusts only that certificate — TOFU for the
	// transport, so a self-signed server needs no CA. Empty means system
	// roots (a CA-issued cert) or plain HTTP.
	ServerCertPin string `json:"server_cert_pin,omitempty"`
}

type Conversation struct {
	Name       string   `json:"name"`
	ID         string   `json:"id"`
	Dir        string   `json:"dir"`
	Creator    string   `json:"creator"`
	Members    []string `json:"members"`
	GroupKey   []byte   `json:"group_key,omitempty"` // shared by all members (epoch 1)
	LastObject string   `json:"last_object,omitempty"`
}

// OwnedObject is the owner-side record of an object: the private signing
// key (rotation authority), current content key, and where each
// recipient's grant file lives. This never leaves the owner's machine.
type OwnedObject struct {
	ObjectID       string `json:"object_id"`
	ConversationID string `json:"conversation_id"`
	KeyVersion     int    `json:"key_version"`
	// LayerKeys is the outermost-first chain of layer keys (the owner
	// can always open every layer directly, without slots).
	LayerKeys   [][]byte `json:"layer_keys"`
	ObjSignPriv []byte   `json:"obj_sign_priv"`
	// Mode is "group" (audience shares the conversation group key, one
	// slot) or "separate" (per-recipient access keys, one slot each).
	Mode string `json:"mode"`
	// AccessKeys: separate mode only — each recipient's personal access
	// key for this object (handle -> key). Removing a handle here and
	// re-wrapping with slots for the rest IS revocation; nobody else
	// needs a new grant.
	AccessKeys map[string][]byte `json:"access_keys,omitempty"`
	GrantFiles map[string]string `json:"grant_files"` // handle (or "*group*") -> grant filename
	Hidden     bool              `json:"hidden,omitempty"`
}

type State struct{ Home string }

// override is set by the -home flag. It wins over $PIPL_HOME so a peer can
// be selected per command invocation, which matters when several peers run
// on one machine (and is far less error-prone than an environment variable
// that silently persists into the next command).
var override string

// SetHome directs all subsequent Open calls at dir. An empty string clears
// the override and restores $PIPL_HOME / the default.
func SetHome(dir string) { override = dir }

// Home reports the directory Open would use, without creating it.
func Home() (string, error) {
	if override != "" {
		return override, nil
	}
	if env := os.Getenv("PIPL_HOME"); env != "" {
		return env, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".pipl"), nil
}

func Open() (*State, error) {
	home, err := Home()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	return &State{Home: home}, nil
}

func (s *State) IdentityPath() string { return filepath.Join(s.Home, "identity.json") }

func (s *State) LoadConfig() (Config, error) {
	return readJSON(filepath.Join(s.Home, "config.json"), Config{})
}
func (s *State) SaveConfig(c Config) error {
	return writeJSON(filepath.Join(s.Home, "config.json"), c)
}

func (s *State) Conversations() (map[string]Conversation, error) {
	return readJSON(filepath.Join(s.Home, "conversations.json"), map[string]Conversation{})
}
func (s *State) SaveConversations(m map[string]Conversation) error {
	return writeJSON(filepath.Join(s.Home, "conversations.json"), m)
}

func (s *State) Owned() (map[string]OwnedObject, error) {
	return readJSON(filepath.Join(s.Home, "owned.json"), map[string]OwnedObject{})
}
func (s *State) SaveOwned(m map[string]OwnedObject) error {
	return writeJSON(filepath.Join(s.Home, "owned.json"), m)
}

func (s *State) Peers() (map[string]identity.PublicIdentity, error) {
	return readJSON(filepath.Join(s.Home, "peers.json"), map[string]identity.PublicIdentity{})
}

// PinPeer records a peer identity, trust-on-first-use. If the handle is
// already pinned with different keys, this is a TOFU violation: refuse
// rather than silently accept a possibly-lying server.
func (s *State) PinPeer(p identity.PublicIdentity) error {
	peers, err := s.Peers()
	if err != nil {
		return err
	}
	if existing, ok := peers[p.Handle]; ok {
		if !existing.Equal(p) {
			return fmt.Errorf("identity for %q changed (fingerprint %s -> %s): refusing (verify out of band, then remove peers.json entry to re-pin)",
				p.Handle, existing.Fingerprint(), p.Fingerprint())
		}
		return nil
	}
	peers[p.Handle] = p
	return writeJSON(filepath.Join(s.Home, "peers.json"), peers)
}

// UnpinPeer forgets a pinned identity so the next contact re-pins from the
// server. Returns the dropped identity so a caller can show which
// fingerprint is being discarded — deliberately removing trust is exactly
// when the fingerprint matters. ok is false if the handle was not pinned.
func (s *State) UnpinPeer(handle string) (dropped identity.PublicIdentity, ok bool, err error) {
	peers, err := s.Peers()
	if err != nil {
		return identity.PublicIdentity{}, false, err
	}
	p, ok := peers[handle]
	if !ok {
		return identity.PublicIdentity{}, false, nil
	}
	delete(peers, handle)
	if err := writeJSON(filepath.Join(s.Home, "peers.json"), peers); err != nil {
		return identity.PublicIdentity{}, false, err
	}
	return p, true, nil
}

func readJSON[T any](path string, def T) (T, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return def, nil
	}
	if err != nil {
		return def, err
	}
	out := def
	if err := json.Unmarshal(data, &out); err != nil {
		return def, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
