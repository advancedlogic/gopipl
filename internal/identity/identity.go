// Package identity implements a peer's long-term identity keys and the
// sealed-box construction used to deliver grants confidentially.
//
// An identity is an Ed25519 signing keypair plus an X25519 keypair for
// receiving sealed grants. Private halves never leave the client machine;
// the server only ever sees PublicIdentity.
package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

type Identity struct {
	Handle   string
	SignPriv ed25519.PrivateKey
	BoxPriv  *ecdh.PrivateKey
}

// PublicIdentity is the only part of an identity that ever leaves the
// client. It is what the (keyless) server directory stores.
type PublicIdentity struct {
	Handle  string `json:"handle"`
	SignPub []byte `json:"sign_pub"`
	BoxPub  []byte `json:"box_pub"`
}

func New(handle string) (*Identity, error) {
	_, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	boxPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{Handle: handle, SignPriv: signPriv, BoxPriv: boxPriv}, nil
}

func (id *Identity) Public() PublicIdentity {
	return PublicIdentity{
		Handle:  id.Handle,
		SignPub: id.SignPriv.Public().(ed25519.PublicKey),
		BoxPub:  id.BoxPriv.PublicKey().Bytes(),
	}
}

func (p PublicIdentity) Equal(o PublicIdentity) bool {
	return p.Handle == o.Handle &&
		string(p.SignPub) == string(o.SignPub) &&
		string(p.BoxPub) == string(o.BoxPub)
}

// Fingerprint is a short digest of the signing key, for out-of-band
// verification between peers (the TOFU escape hatch).
func (p PublicIdentity) Fingerprint() string {
	sum := sha256.Sum256(p.SignPub)
	return hex.EncodeToString(sum[:8])
}

type diskIdentity struct {
	Handle   string `json:"handle"`
	SignPriv []byte `json:"sign_priv"`
	BoxPriv  []byte `json:"box_priv"`
}

func (id *Identity) Save(path string) error {
	d := diskIdentity{Handle: id.Handle, SignPriv: id.SignPriv, BoxPriv: id.BoxPriv.Bytes()}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func Load(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d diskIdentity
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	if len(d.SignPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("identity file: bad signing key length")
	}
	boxPriv, err := ecdh.X25519().NewPrivateKey(d.BoxPriv)
	if err != nil {
		return nil, fmt.Errorf("identity file: %w", err)
	}
	return &Identity{Handle: d.Handle, SignPriv: ed25519.PrivateKey(d.SignPriv), BoxPriv: boxPriv}, nil
}

// --- Sealed boxes -----------------------------------------------------------
//
// Anonymous ECIES: ephemeral X25519 -> HKDF-SHA256 -> AES-256-GCM.
// Prototype construction using only the Go standard library; the design
// doc specifies libsodium crypto_box_seal — swap here when adding
// non-Go clients. Layout: ephemeral pub (32) || nonce (12) || ciphertext.

const sealOverhead = 32 + 12

// SealTo encrypts plaintext so that only the holder of the X25519 private
// key matching recipientBoxPub can open it. The sender is anonymous at
// this layer; authenticity comes from the signature inside the grant.
func SealTo(recipientBoxPub, plaintext []byte) ([]byte, error) {
	curve := ecdh.X25519()
	peer, err := curve.NewPublicKey(recipientBoxPub)
	if err != nil {
		return nil, fmt.Errorf("bad recipient key: %w", err)
	}
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(peer)
	if err != nil {
		return nil, err
	}
	gcm, err := sealCipher(shared, eph.PublicKey().Bytes(), recipientBoxPub)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, sealOverhead+len(plaintext)+16)
	out = append(out, eph.PublicKey().Bytes()...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, nil), nil
}

// OpenSealed reverses SealTo. Failure simply means "not addressed to me"
// (or corrupted) — callers use this for trial decryption of grant files.
func (id *Identity) OpenSealed(blob []byte) ([]byte, error) {
	if len(blob) < sealOverhead+16 {
		return nil, errors.New("sealed blob too short")
	}
	ephPub, nonce, ct := blob[:32], blob[32:44], blob[44:]
	peer, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		return nil, err
	}
	shared, err := id.BoxPriv.ECDH(peer)
	if err != nil {
		return nil, err
	}
	gcm, err := sealCipher(shared, ephPub, id.BoxPriv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

func sealCipher(shared, ephPub, recipientPub []byte) (cipher.AEAD, error) {
	salt := append(append([]byte{}, ephPub...), recipientPub...)
	key, err := hkdf.Key(sha256.New, shared, salt, "pipl/sealbox/v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
