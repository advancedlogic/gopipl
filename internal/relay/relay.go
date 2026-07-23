// Package relay implements the server-side blob store: durable storage
// for ciphertext the server cannot read, so peers who share no filesystem
// can still exchange objects and grants.
//
// The server stays keyless. It never holds a decryption key, never sees
// plaintext, and never sees a capability — a blob is opaque bytes with an
// ID. What it CAN do is verify authorship, which is what makes in-place
// revocation safe over a network:
//
//   - The first write of an object ID records that object's Ed25519
//     public signing key, taken from the object's own signed header.
//   - Every later write of that ID must carry a valid signature under the
//     SAME key. Only the owner holds the private half, so only the owner
//     can rewrite or delete an object — exactly the guarantee the
//     filesystem backend got from file permissions.
//
// This verification needs no secret: signature checking is a public
// operation. A compromised server can still delete or withhold blobs
// (availability), but it cannot forge, read, or alter one undetectably.
package relay

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/antonio/pipl/internal/object"
)

// Kind distinguishes the two blob families. Grants are sealed to an
// identity and carry no owner signature the server can check, so they are
// append-only; objects are signed and therefore rewritable by their owner.
type Kind string

const (
	KindObject Kind = "object"
	KindGrant  Kind = "grant"
)

// Blob is one stored item. Data is opaque ciphertext.
type Blob struct {
	ID             string
	Kind           Kind
	ConversationID string
	Data           []byte
	// SignPub is the object's public signing key, learned from the first
	// write and enforced on every later one. Empty for grants.
	SignPub   []byte
	UpdatedAt time.Time
}

var (
	ErrNotFound = errors.New("no such blob")
	// ErrNotOwner means a write carried a signature that does not match
	// the key established by the first write of that object ID.
	ErrNotOwner = errors.New("object is owned by a different signing key")
)

// Store is an in-memory blob store, safe for concurrent use.
//
// Durability note: this prototype keeps blobs in memory, so a restart
// loses them. That is a storage-backend concern, not a protocol one —
// swapping in bbolt, S3, or DynamoDB changes nothing above this
// interface, because the authorization rule travels with the blob.
type Store struct {
	mu    sync.RWMutex
	blobs map[string]*Blob
	// byConv indexes blob IDs per conversation so a peer can list what it
	// should try to open, without the server knowing what any of it says.
	byConv map[string]map[string]struct{}
}

func NewStore() *Store {
	return &Store{
		blobs:  map[string]*Blob{},
		byConv: map[string]map[string]struct{}{},
	}
}

// PutObject stores or replaces an object blob after verifying that the
// bytes are a well-formed, correctly signed PIPL object, and that the
// signer matches whoever first claimed this ID.
//
// The server parses only the public header and checks the signature; it
// cannot open a key slot or read the payload.
func (s *Store) PutObject(convID, id string, data []byte) error {
	if convID == "" || id == "" {
		return errors.New("conversation and object id are required")
	}
	d, err := object.Decode(data)
	if err != nil {
		return fmt.Errorf("not a PIPL object: %w", err)
	}
	if d.Header.ObjectID != id {
		return fmt.Errorf("object id %q does not match its header (%q)", id, d.Header.ObjectID)
	}
	if d.Header.ConversationID != convID {
		return errors.New("object header names a different conversation")
	}
	signPub := d.Header.ObjSignPub
	if len(signPub) != ed25519.PublicKeySize {
		return errors.New("object header carries no usable signing key")
	}
	// Self-consistency: the object must verify under the key it advertises.
	// This alone proves nothing about identity — the next check does.
	if err := d.Verify(ed25519.PublicKey(signPub)); err != nil {
		return fmt.Errorf("object signature invalid: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.blobs[id]; ok {
		// Rewrites (revocation, hide/unhide) must come from the same
		// signing key that created the object. This is the whole
		// authorization model, and it needs no account or password.
		if string(existing.SignPub) != string(signPub) {
			return ErrNotOwner
		}
	}
	s.put(&Blob{
		ID: id, Kind: KindObject, ConversationID: convID,
		Data: data, SignPub: signPub, UpdatedAt: time.Now().UTC(),
	})
	return nil
}

// PutGrant stores a sealed grant blob. Grants are opaque sealed boxes
// with no server-verifiable author, so they are append-only: an existing
// ID may not be overwritten. Grant IDs are random, so collisions do not
// occur in practice; refusing replacement removes the possibility of one
// peer clobbering another's grant.
func (s *Store) PutGrant(convID, id string, data []byte) error {
	if convID == "" || id == "" {
		return errors.New("conversation and grant id are required")
	}
	if len(data) == 0 {
		return errors.New("empty grant")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.blobs[id]; ok {
		return errors.New("grant already exists (grants are append-only)")
	}
	s.put(&Blob{
		ID: id, Kind: KindGrant, ConversationID: convID,
		Data: data, UpdatedAt: time.Now().UTC(),
	})
	return nil
}

func (s *Store) put(b *Blob) {
	s.blobs[b.ID] = b
	if s.byConv[b.ConversationID] == nil {
		s.byConv[b.ConversationID] = map[string]struct{}{}
	}
	s.byConv[b.ConversationID][b.ID] = struct{}{}
}

func (s *Store) Get(id string) (*Blob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.blobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *b
	cp.Data = append([]byte(nil), b.Data...)
	return &cp, nil
}

// Entry is the metadata a peer needs to decide what to fetch.
type Entry struct {
	ID        string    `json:"id"`
	Kind      Kind      `json:"kind"`
	UpdatedAt time.Time `json:"updated_at"`
}

// List reports the blobs in a conversation. It deliberately reveals
// nothing beyond IDs, kinds and timestamps — the same metadata a shared
// folder would leak to whoever hosts it.
func (s *Store) List(convID string) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.byConv[convID]
	out := make([]Entry, 0, len(ids))
	for id := range ids {
		if b, ok := s.blobs[id]; ok {
			out = append(out, Entry{ID: b.ID, Kind: b.Kind, UpdatedAt: b.UpdatedAt})
		}
	}
	return out
}

// DeleteObject removes an object, but only for a caller who proves
// ownership by signing the challenge below with the object's signing key.
// This is how `revoke -all` reaches a relayed object.
func (s *Store) DeleteObject(id string, sig []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.blobs[id]
	if !ok {
		return ErrNotFound
	}
	if b.Kind != KindObject {
		return errors.New("only objects can be deleted this way")
	}
	if !ed25519.Verify(ed25519.PublicKey(b.SignPub), DeleteChallenge(id), sig) {
		return ErrNotOwner
	}
	delete(s.blobs, id)
	if ids := s.byConv[b.ConversationID]; ids != nil {
		delete(ids, id)
		if len(ids) == 0 {
			delete(s.byConv, b.ConversationID)
		}
	}
	return nil
}

// DeleteGrant removes a grant blob. Sealed grants carry no
// server-verifiable author, so this is authorized only by knowing the
// random blob ID — deliberately weaker than DeleteObject, and matching
// what soft revoke already claims: deleting a grant does not stop a
// recipient who cached the capability.
func (s *Store) DeleteGrant(convID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.blobs[id]
	if !ok || b.Kind != KindGrant || b.ConversationID != convID {
		return ErrNotFound
	}
	delete(s.blobs, id)
	if ids := s.byConv[convID]; ids != nil {
		delete(ids, id)
		if len(ids) == 0 {
			delete(s.byConv, convID)
		}
	}
	return nil
}

// DeleteChallenge is the exact byte string an owner signs to authorize
// deletion of an object. Domain-separated so a signature harvested from
// one context can never be replayed as a delete.
func DeleteChallenge(objectID string) []byte {
	return []byte("pipl/relay/delete/v1:" + objectID)
}
