package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Persistence: blobs on disk so a server restart does not lose a
// conversation.
//
// Layout, one directory per conversation so listing is a readdir and no
// index file can drift out of sync with reality:
//
//	<dir>/<conversation-id>/<blob-id>       the ciphertext, verbatim
//	<dir>/<conversation-id>/<blob-id>.meta  kind, signing key, timestamp
//
// The sidecar carries what the bytes alone cannot tell the server. For an
// object that is chiefly SignPub, and it is security-relevant: it is the
// key every later write must match, so if it were lost on restart the
// first writer after reboot would silently inherit the right to rewrite
// someone else's object. It is re-derivable from the object header, but
// storing it keeps the rule in one place rather than two.
//
// Writes are atomic (temp file + rename) so a crash mid-write leaves the
// previous version intact rather than a truncated one — the same property
// WriteAtomic gives the filesystem backend, and for the same reason:
// revocation replaces an object in place.

// meta is the sidecar record for one blob.
type meta struct {
	Kind      Kind      `json:"kind"`
	SignPub   []byte    `json:"sign_pub,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// OpenStore returns a Store backed by dir, loading whatever is already
// there. An empty dir gives a memory-only store, which is what the tests
// and a throwaway server want.
func OpenStore(dir string) (*Store, error) {
	s := NewStore()
	if dir == "" {
		return s, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("relay store: %w", err)
	}
	s.dir = dir
	if err := s.load(); err != nil {
		return nil, fmt.Errorf("relay store: %w", err)
	}
	return s, nil
}

// load reads every persisted blob back into memory. A blob whose sidecar
// is missing or unreadable is skipped rather than failing startup: one
// damaged file should not take the whole server down, and the peer that
// owns it can always write it again.
func (s *Store) load() error {
	convs, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, ce := range convs {
		if !ce.IsDir() {
			continue
		}
		convID := ce.Name()
		files, err := os.ReadDir(filepath.Join(s.dir, convID))
		if err != nil {
			continue
		}
		for _, fe := range files {
			name := fe.Name()
			if fe.IsDir() || strings.HasSuffix(name, ".meta") || strings.HasPrefix(name, ".tmp-") {
				continue
			}
			b, err := s.readBlob(convID, name)
			if err != nil {
				s.skipped = append(s.skipped, filepath.Join(convID, name)+": "+err.Error())
				continue
			}
			s.put(b) // in-memory only; already on disk
		}
	}
	return nil
}

func (s *Store) readBlob(convID, id string) (*Blob, error) {
	base := filepath.Join(s.dir, convID, id)
	data, err := os.ReadFile(base)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(base + ".meta")
	if err != nil {
		return nil, fmt.Errorf("missing sidecar: %w", err)
	}
	var m meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("corrupt sidecar: %w", err)
	}
	if m.Kind != KindObject && m.Kind != KindGrant {
		return nil, fmt.Errorf("unknown blob kind %q", m.Kind)
	}
	// An object's authority must be intact, or we would be unable to
	// enforce who may rewrite it.
	if m.Kind == KindObject && len(m.SignPub) == 0 {
		return nil, errors.New("object sidecar carries no signing key")
	}
	return &Blob{
		ID: id, Kind: m.Kind, ConversationID: convID,
		Data: data, SignPub: m.SignPub, UpdatedAt: m.UpdatedAt,
	}, nil
}

// persist writes a blob and its sidecar. Called with the store locked.
func (s *Store) persist(b *Blob) error {
	if s.dir == "" {
		return nil
	}
	dir := filepath.Join(s.dir, b.ConversationID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(meta{Kind: b.Kind, SignPub: b.SignPub, UpdatedAt: b.UpdatedAt})
	if err != nil {
		return err
	}
	// Sidecar first: a blob without one is skipped on load, which is
	// recoverable. A sidecar without a blob would be a phantom entry.
	base := filepath.Join(dir, b.ID)
	if err := writeAtomic(base+".meta", raw); err != nil {
		return err
	}
	return writeAtomic(base, b.Data)
}

// forget removes a blob's files. Missing files are not an error: the
// caller's intent (that it be gone) already holds.
func (s *Store) forget(convID, id string) {
	if s.dir == "" {
		return
	}
	base := filepath.Join(s.dir, convID, id)
	os.Remove(base)
	os.Remove(base + ".meta")
	// Drop the conversation directory once empty, so a deleted
	// conversation does not leave a trail of empty folders.
	os.Remove(filepath.Join(s.dir, convID))
}

// writeAtomic writes via temp file + rename, so a reader never sees a
// half-written blob and a crash cannot corrupt the previous version.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// Skipped reports blobs that could not be loaded at startup, so the
// operator learns about damage instead of silently serving less than was
// stored.
func (s *Store) Skipped() []string { return s.skipped }
