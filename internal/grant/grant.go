// Package grant implements grant files: how a read capability travels
// from an owner to one recipient, peer to peer, through the same storage
// backend — so the server never sees a key.
//
// A grant is the capability plus provenance (which conversation, which
// sender), signed by the owner's identity key, then sealed to the
// recipient's identity box key. On disk it is an opaque random-named
// blob; recipients trial-open every grant file to find theirs.
package grant

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"

	"github.com/antonio/pipl/internal/identity"
	"github.com/antonio/pipl/internal/object"
)

type Grant struct {
	Capability     object.Capability `json:"capability"`
	From           string            `json:"from"`
	ConversationID string            `json:"conversation_id"`
	Sig            []byte            `json:"sig,omitempty"`
}

func (g Grant) signingBody() ([]byte, error) {
	g.Sig = nil
	return json.Marshal(g)
}

// New signs a grant with the owner's identity signing key, so the
// recipient can verify who granted them access.
func New(cap object.Capability, from, convID string, ownerSignPriv ed25519.PrivateKey) (Grant, error) {
	g := Grant{Capability: cap, From: from, ConversationID: convID}
	body, err := g.signingBody()
	if err != nil {
		return Grant{}, err
	}
	g.Sig = ed25519.Sign(ownerSignPriv, body)
	return g, nil
}

func (g Grant) Verify(ownerSignPub ed25519.PublicKey) error {
	body, err := g.signingBody()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ownerSignPub, body, g.Sig) {
		return errors.New("grant signature verification failed")
	}
	return nil
}

// Seal encrypts the grant so only the recipient can open it.
func Seal(g Grant, recipientBoxPub []byte) ([]byte, error) {
	data, err := json.Marshal(g)
	if err != nil {
		return nil, err
	}
	return identity.SealTo(recipientBoxPub, data)
}

// Open trial-decrypts a sealed grant. An error means "not addressed to
// this identity" and is expected during scans.
func Open(id *identity.Identity, blob []byte) (Grant, error) {
	data, err := id.OpenSealed(blob)
	if err != nil {
		return Grant{}, err
	}
	var g Grant
	if err := json.Unmarshal(data, &g); err != nil {
		return Grant{}, err
	}
	return g, nil
}

// SealSymmetric encrypts a grant under a conversation group key: one
// grant file serves the whole group, regardless of its size.
func SealSymmetric(g Grant, groupKey []byte) ([]byte, error) {
	data, err := json.Marshal(g)
	if err != nil {
		return nil, err
	}
	return symSeal(groupKey, data)
}

// OpenSymmetric trial-decrypts a group-encrypted grant with a group key.
func OpenSymmetric(groupKey, blob []byte) (Grant, error) {
	data, err := symOpen(groupKey, blob)
	if err != nil {
		return Grant{}, err
	}
	var g Grant
	if err := json.Unmarshal(data, &g); err != nil {
		return Grant{}, err
	}
	return g, nil
}

// ---- group member keys -----------------------------------------------------

// MemberKey is how a conversation's shared group key reaches each member:
// signed by the conversation creator's identity key, sealed to the
// member's identity box key, dropped in the conversation folder as a
// random-named .mkey file. The server never sees it.
type MemberKey struct {
	ConversationID string `json:"conversation_id"`
	GroupKey       []byte `json:"group_key"`
	Epoch          int    `json:"epoch"`
	From           string `json:"from"`
	Sig            []byte `json:"sig,omitempty"`
}

func (m MemberKey) signingBody() ([]byte, error) {
	m.Sig = nil
	return json.Marshal(m)
}

func NewMemberKey(convID string, groupKey []byte, epoch int, from string, signPriv ed25519.PrivateKey) (MemberKey, error) {
	m := MemberKey{ConversationID: convID, GroupKey: groupKey, Epoch: epoch, From: from}
	body, err := m.signingBody()
	if err != nil {
		return MemberKey{}, err
	}
	m.Sig = ed25519.Sign(signPriv, body)
	return m, nil
}

func (m MemberKey) Verify(creatorSignPub ed25519.PublicKey) error {
	body, err := m.signingBody()
	if err != nil {
		return err
	}
	if !ed25519.Verify(creatorSignPub, body, m.Sig) {
		return errors.New("member key signature verification failed")
	}
	return nil
}

func SealMemberKey(m MemberKey, recipientBoxPub []byte) ([]byte, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return identity.SealTo(recipientBoxPub, data)
}

func OpenMemberKey(id *identity.Identity, blob []byte) (MemberKey, error) {
	data, err := id.OpenSealed(blob)
	if err != nil {
		return MemberKey{}, err
	}
	var m MemberKey
	err = json.Unmarshal(data, &m)
	return m, err
}

// ---- symmetric helpers (AES-256-GCM; nonce || ciphertext) ------------------

func symSeal(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func symOpen(key, blob []byte) ([]byte, error) {
	if len(blob) < 12+16 {
		return nil, errors.New("blob too short")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, blob[:12], blob[12:], nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
