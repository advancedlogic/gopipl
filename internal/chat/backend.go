package chat

import (
	"os"
	"sort"

	"github.com/antonio/pipl/internal/api"
	"github.com/antonio/pipl/internal/state"
	"github.com/antonio/pipl/internal/store"
)

// backend is where a conversation's encrypted files actually live. Two
// implementations: a shared folder (peers with common storage) and the
// server's blob relay (peers with none). Both handle identical ciphertext
// — the choice changes only transport, never what is encrypted or who can
// read it, so all the security-relevant logic above this is shared.
type backend interface {
	// PutObject writes or replaces an object. Replacement is how
	// revocation works, so a backend must authorize it: the folder does so
	// with file permissions, the relay by verifying the object signature.
	PutObject(objectID string, data []byte) error
	GetObject(objectID string) ([]byte, error)
	DeleteObject(objectID string, sig []byte) error

	PutGrant(name string, data []byte) error
	// DeleteGrant removes a grant blob (soft revoke). Missing is not an
	// error — the outcome the caller wanted already holds.
	DeleteGrant(name string) error
	// Grants lists every grant blob; recipients trial-open all of them.
	Grants() ([]grantBlob, error)
	// MemberKeys lists sealed .mkey blobs (group-key distribution).
	MemberKeys() ([]grantBlob, error)
}

// grantBlob is one sealed blob plus the name it is stored under, so a
// caller can delete it later (soft revoke).
type grantBlob struct {
	Name string
	Data []byte
}

// backendFor picks the transport for a conversation. A conversation with
// no Dir is relay-backed.
func (e *Env) backendFor(conv state.Conversation) (backend, error) {
	if conv.Dir != "" {
		return folderBackend{dir: conv.Dir}, nil
	}
	if e.Cl == nil {
		return nil, errNoTransport{conv.Name}
	}
	return relayBackend{cl: e.Cl, convID: conv.ID}, nil
}

type errNoTransport struct{ name string }

func (e errNoTransport) Error() string {
	return "conversation " + e.name + " has no shared folder and no server configured: " +
		"set a server (pipl init -server URL) or give the conversation a folder"
}

// ---- shared folder ---------------------------------------------------------

type folderBackend struct{ dir string }

func (f folderBackend) PutObject(objectID string, data []byte) error {
	return store.WriteAtomic(store.ObjectPath(f.dir, objectID), data)
}

func (f folderBackend) GetObject(objectID string) ([]byte, error) {
	return os.ReadFile(store.ObjectPath(f.dir, objectID))
}

// DeleteObject ignores sig: on a filesystem, write access is the
// authorization. The relay needs a signature because anyone can reach it.
func (f folderBackend) DeleteObject(objectID string, _ []byte) error {
	err := os.Remove(store.ObjectPath(f.dir, objectID))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (f folderBackend) PutGrant(name string, data []byte) error {
	return store.WriteAtomic(store.GrantPath(f.dir, name), data)
}

func (f folderBackend) DeleteGrant(name string) error {
	err := os.Remove(store.GrantPath(f.dir, name))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (f folderBackend) Grants() ([]grantBlob, error) {
	return f.read(store.ListGrantFiles)
}

func (f folderBackend) MemberKeys() ([]grantBlob, error) {
	return f.read(store.ListMemberKeyFiles)
}

func (f folderBackend) read(list func(string) ([]string, error)) ([]grantBlob, error) {
	paths, err := list(f.dir)
	if err != nil {
		return nil, err
	}
	out := make([]grantBlob, 0, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue // vanished mid-scan: not our problem, skip
		}
		out = append(out, grantBlob{Name: filepathBase(p), Data: data})
	}
	return out, nil
}

func filepathBase(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}

// ---- server blob relay -----------------------------------------------------

type relayBackend struct {
	cl     *api.Client
	convID string
}

func (r relayBackend) PutObject(objectID string, data []byte) error {
	return r.cl.PutObject(r.convID, objectID, data)
}

func (r relayBackend) GetObject(objectID string) ([]byte, error) {
	return r.cl.GetBlob(r.convID, objectID)
}

func (r relayBackend) DeleteObject(objectID string, sig []byte) error {
	err := r.cl.DeleteObject(r.convID, objectID, sig)
	if err == os.ErrNotExist {
		return nil
	}
	return err
}

func (r relayBackend) PutGrant(name string, data []byte) error {
	return r.cl.PutGrant(r.convID, name, data)
}

func (r relayBackend) DeleteGrant(name string) error {
	err := r.cl.DeleteGrant(r.convID, name)
	if err == os.ErrNotExist {
		return nil
	}
	return err
}

func (r relayBackend) Grants() ([]grantBlob, error) {
	return r.fetch(".grant")
}

func (r relayBackend) MemberKeys() ([]grantBlob, error) {
	return r.fetch(".mkey")
}

// fetch pulls every grant-kind blob and filters by name suffix, mirroring
// how the folder backend distinguishes .grant from .mkey.
func (r relayBackend) fetch(suffix string) ([]grantBlob, error) {
	entries, err := r.cl.ListBlobs(r.convID)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	var out []grantBlob
	for _, e := range entries {
		if e.Kind != "grant" || !hasSuffix(e.ID, suffix) {
			continue
		}
		data, err := r.cl.GetBlob(r.convID, e.ID)
		if err != nil {
			continue
		}
		out = append(out, grantBlob{Name: e.ID, Data: data})
	}
	return out, nil
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
