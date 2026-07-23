// Package object implements the PIPL object container: one encrypted,
// signed file per chat object.
//
// Layout:
//
//	magic "PIPL" | format version (u16) | header len (u32) | header JSON |
//	ciphertext (nonce || AEAD) | Ed25519 signature (64)
//
// The signature (under the object's signing key, held only by the owner)
// covers everything before it, so recipients — and no one else — can
// verify integrity, while only the owner can mint or rotate the file.
// The header JSON is bound to the ciphertext as AEAD associated data.
//
// AEAD is AES-256-GCM in this prototype (Go stdlib only); the design doc
// specifies XChaCha20-Poly1305 secretstream — swap when adding large
// media payloads.
package object

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var magic = []byte("PIPL")

const FormatVersion uint16 = 1

// Header is signed but not encrypted. It contains nothing an outside
// observer can use: random IDs and a per-object public key.
type Header struct {
	ObjectID       string `json:"object_id"`
	KeyVersion     int    `json:"key_version"`
	ConversationID string `json:"conversation_id"`
	ObjSignPub     []byte `json:"obj_sign_pub"`
	PrevObject     string `json:"prev_object,omitempty"`
	// Wrapped marks a superencryption layer: the plaintext of this
	// container is a complete inner PIPL object file, not a payload.
	// Revocation wraps the existing ciphertext in a new layer instead of
	// decrypting and re-encrypting — the owner never touches plaintext,
	// and removing the layer (unhide) makes old access keys valid again.
	Wrapped bool `json:"wrapped,omitempty"`
	// Slots carry this layer's key, encrypted once per audience access
	// key (LUKS-style). A group shares one access key = one slot for any
	// group size; a separate send gives each recipient their own access
	// key = one slot each, so one recipient can be revoked (by
	// re-wrapping with slots for the others) without re-granting anyone.
	// Zero slots = hidden: no access key opens the layer.
	// Slots live in the signed header, so they cannot be tampered with.
	Slots [][]byte `json:"slots,omitempty"`
}

// Capability is the read capability distributed to recipients. AccessKey
// is the holder's long-lived key for this object: a shared group key, or
// a personal per-recipient key for separate sends. It opens a key slot
// on every layer the holder is entitled to — surviving wraps and
// unwraps, so revocation never requires re-granting the others.
// Possession = access: treat as secret among the authorized audience.
type Capability struct {
	ObjectID   string `json:"object_id"`
	AccessKey  []byte `json:"access_key"`
	ObjSignPub []byte `json:"obj_sign_pub"`
}

// Payload is the encrypted content. Sender and timestamp live here — not
// in the header — so the storage layer never sees them.
type Payload struct {
	Type   string    `json:"type"` // "text" for now
	Body   string    `json:"body"`
	From   string    `json:"from"`
	SentAt time.Time `json:"sent_at"`
}

var idEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewID returns a random 128-bit identifier, safe to use as a filename
// and meaningless to anyone who sees it.
func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(idEnc.EncodeToString(b)), nil
}

// NewKey returns a fresh 256-bit content key.
func NewKey() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Encode encrypts plaintext under key, signs the result with the object's
// signing key, and returns the complete object file bytes.
func Encode(h Header, plaintext, key []byte, objSignPriv ed25519.PrivateKey) ([]byte, error) {
	hdr, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, hdr)

	var buf bytes.Buffer
	buf.Write(magic)
	if err := binary.Write(&buf, binary.BigEndian, FormatVersion); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(hdr))); err != nil {
		return nil, err
	}
	buf.Write(hdr)
	buf.Write(ct)
	sum := sha256.Sum256(buf.Bytes())
	buf.Write(ed25519.Sign(objSignPriv, sum[:]))
	return buf.Bytes(), nil
}

// Decoded is a parsed (but not yet verified or decrypted) object file.
type Decoded struct {
	Header    Header
	headerRaw []byte
	signed    []byte // everything before the trailing signature
	ct        []byte
	sig       []byte
}

func Decode(data []byte) (*Decoded, error) {
	minLen := len(magic) + 2 + 4 + ed25519.SignatureSize
	if len(data) < minLen {
		return nil, errors.New("object too short")
	}
	if !bytes.Equal(data[:4], magic) {
		return nil, errors.New("not a PIPL object")
	}
	if v := binary.BigEndian.Uint16(data[4:6]); v != FormatVersion {
		return nil, fmt.Errorf("unsupported format version %d", v)
	}
	hl := int(binary.BigEndian.Uint32(data[6:10]))
	sigStart := len(data) - ed25519.SignatureSize
	if 10+hl > sigStart {
		return nil, errors.New("corrupt object: bad header length")
	}
	hdrRaw := data[10 : 10+hl]
	var h Header
	if err := json.Unmarshal(hdrRaw, &h); err != nil {
		return nil, fmt.Errorf("corrupt header: %w", err)
	}
	return &Decoded{
		Header:    h,
		headerRaw: hdrRaw,
		signed:    data[:sigStart],
		ct:        data[10+hl : sigStart],
		sig:       data[sigStart:],
	}, nil
}

// Verify checks the object signature against the object's public signing
// key (carried inside the recipient's capability).
func (d *Decoded) Verify(objSignPub ed25519.PublicKey) error {
	sum := sha256.Sum256(d.signed)
	if !ed25519.Verify(objSignPub, sum[:], d.sig) {
		return errors.New("object signature verification failed")
	}
	return nil
}

// Decrypt opens the payload with the content key. A failure here after a
// successful Verify almost always means the capability is stale — the
// owner rotated the object (revocation).
func (d *Decoded) Decrypt(key []byte) ([]byte, error) {
	if len(d.ct) < 12+16 {
		return nil, errors.New("ciphertext too short")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, d.ct[:12], d.ct[12:], d.headerRaw)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed (wrong or rotated key): %w", err)
	}
	return pt, nil
}

// MakeSlot encrypts a layer key under one audience access key, for
// inclusion in a header's Slots.
func MakeSlot(accessKey, layerKey []byte) ([]byte, error) {
	gcm, err := newGCM(accessKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, layerKey, nil), nil
}

// UnlockSlot trial-decrypts each slot with an access key. ok=false means
// this access key has no slot on this layer: no access.
func (d *Decoded) UnlockSlot(accessKey []byte) (layerKey []byte, ok bool) {
	gcm, err := newGCM(accessKey)
	if err != nil {
		return nil, false
	}
	for _, slot := range d.Header.Slots {
		if len(slot) < 12+16 {
			continue
		}
		if key, err := gcm.Open(nil, slot[:12], slot[12:], nil); err == nil {
			return key, true
		}
	}
	return nil, false
}

// OpenWithCapability verifies an object file and peels layers, opening
// each layer's key slot with the capability's access key, until it
// reaches the payload. Any failure — bad signature, no matching slot —
// means the holder has no access (typically: revoked or hidden).
func OpenWithCapability(data []byte, c Capability) (Payload, error) {
	pub := ed25519.PublicKey(c.ObjSignPub)
	d, err := Decode(data)
	if err != nil {
		return Payload{}, err
	}
	for {
		if err := d.Verify(pub); err != nil {
			return Payload{}, err
		}
		layerKey, ok := d.UnlockSlot(c.AccessKey)
		if !ok {
			return Payload{}, errors.New("no key slot for this access key (revoked or hidden)")
		}
		pt, err := d.Decrypt(layerKey)
		if err != nil {
			return Payload{}, err
		}
		if !d.Header.Wrapped {
			return ParsePayload(pt)
		}
		if d, err = Decode(pt); err != nil {
			return Payload{}, err
		}
	}
}

func ParsePayload(pt []byte) (Payload, error) {
	var p Payload
	err := json.Unmarshal(pt, &p)
	return p, err
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("content key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
