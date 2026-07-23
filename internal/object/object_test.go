package object

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"
)

// newObj is the common fixture: a one-layer object encrypted under a fresh
// layer key, with one slot per supplied access key.
func newObj(t *testing.T, body string, accessKeys ...[]byte) (data []byte, layerKey []byte, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	layerKey = mustKey(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	oid, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	var slots [][]byte
	for _, ak := range accessKeys {
		slot, err := MakeSlot(ak, layerKey)
		if err != nil {
			t.Fatalf("MakeSlot: %v", err)
		}
		slots = append(slots, slot)
	}
	payload, err := json.Marshal(Payload{
		Type: "text", Body: body, From: "alice", SentAt: time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	hdr := Header{
		ObjectID: oid, KeyVersion: 1, ConversationID: "conv1",
		ObjSignPub: pub, Slots: slots,
	}
	data, err = Encode(hdr, payload, layerKey, priv)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return data, layerKey, pub, priv
}

func mustKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

// wrap superencrypts an existing object file in a new signed layer, the way
// revoke/hide do: the whole inner file becomes this layer's plaintext.
func wrap(t *testing.T, inner []byte, priv ed25519.PrivateKey, keyVersion int, accessKeys ...[]byte) ([]byte, []byte) {
	t.Helper()
	layerKey := mustKey(t)
	var slots [][]byte
	for _, ak := range accessKeys {
		slot, err := MakeSlot(ak, layerKey)
		if err != nil {
			t.Fatalf("MakeSlot: %v", err)
		}
		slots = append(slots, slot)
	}
	d, err := Decode(inner)
	if err != nil {
		t.Fatalf("Decode inner: %v", err)
	}
	hdr := Header{
		ObjectID: d.Header.ObjectID, KeyVersion: keyVersion,
		ConversationID: d.Header.ConversationID,
		ObjSignPub:     priv.Public().(ed25519.PublicKey),
		Wrapped:        true, Slots: slots,
	}
	out, err := Encode(hdr, inner, layerKey, priv)
	if err != nil {
		t.Fatalf("Encode wrap: %v", err)
	}
	return out, layerKey
}

func TestNewIDIsRandomAndFilenameSafe(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatalf("NewID: %v", err)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q after %d draws", id, i)
		}
		seen[id] = true
		// base32 no-padding, lowercased: safe as a filename on any OS.
		for _, r := range id {
			if !(r >= 'a' && r <= 'z') && !(r >= '2' && r <= '7') {
				t.Fatalf("id %q contains unsafe rune %q", id, r)
			}
		}
	}
}

func TestNewKeyIs256Bit(t *testing.T) {
	a, b := mustKey(t), mustKey(t)
	if len(a) != 32 {
		t.Fatalf("key length = %d, want 32", len(a))
	}
	if bytes.Equal(a, b) {
		t.Fatal("two NewKey calls returned identical keys")
	}
}

func TestEncodeDecryptRoundTrip(t *testing.T) {
	data, layerKey, pub, _ := newObj(t, "hello")

	d, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if err := d.Verify(pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	pt, err := d.Decrypt(layerKey)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	p, err := ParsePayload(pt)
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if p.Body != "hello" || p.From != "alice" || p.Type != "text" {
		t.Fatalf("payload round-trip mismatch: %+v", p)
	}
}

// The whole point of the container: nothing readable on disk.
func TestCiphertextLeaksNoPlaintext(t *testing.T) {
	secret := "attack at dawn"
	data, _, _, _ := newObj(t, secret, mustKey(t))
	if bytes.Contains(data, []byte(secret)) {
		t.Fatal("plaintext found in encoded object")
	}
	if bytes.Contains(data, []byte("alice")) {
		t.Fatal("sender handle found in encoded object (payload must be encrypted)")
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	good, _, _, _ := newObj(t, "hi")

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"too short", []byte("PIPL")},
		{"bad magic", append([]byte("XXXX"), good[4:]...)},
		{"header length past end", func() []byte {
			b := bytes.Clone(good)
			b[6], b[7], b[8], b[9] = 0x7f, 0xff, 0xff, 0xff
			return b
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode(tc.data); err == nil {
				t.Fatal("Decode accepted malformed object")
			}
		})
	}
}

// Decode is only a parser: it does not authenticate. Truncated bytes may
// still parse (the tail is reinterpreted as a shorter ciphertext plus a
// bogus signature) — the signature check is what must reject them, so no
// caller can reach plaintext through a mangled file.
func TestTruncatedObjectIsRejectedBeforePlaintext(t *testing.T) {
	ak := mustKey(t)
	good, _, pub, _ := newObj(t, "hello", ak)

	for _, n := range []int{1, 10, ed25519.SignatureSize} {
		trunc := good[:len(good)-n]
		if d, err := Decode(trunc); err == nil {
			if err := d.Verify(pub); err == nil {
				t.Fatalf("truncated by %d: Verify accepted a mangled object", n)
			}
		}
		if _, err := OpenWithCapability(trunc, Capability{AccessKey: ak, ObjSignPub: pub}); err == nil {
			t.Fatalf("truncated by %d: OpenWithCapability returned a payload", n)
		}
	}
}

func TestDecodeRejectsWrongFormatVersion(t *testing.T) {
	data, _, _, _ := newObj(t, "hi")
	bad := bytes.Clone(data)
	bad[4], bad[5] = 0xff, 0xff // format version field
	if _, err := Decode(bad); err == nil {
		t.Fatal("Decode accepted unsupported format version")
	}
}

func TestVerifyRejectsWrongKeyAndTamperedBytes(t *testing.T) {
	data, _, pub, _ := newObj(t, "hi")
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	d, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Verify(otherPub); err == nil {
		t.Fatal("Verify accepted a foreign signing key")
	}

	// Flip a ciphertext byte: the signature covers it, so Verify must fail.
	tampered := bytes.Clone(data)
	tampered[len(tampered)-ed25519.SignatureSize-1] ^= 0x01
	dt, err := Decode(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := dt.Verify(pub); err == nil {
		t.Fatal("Verify accepted tampered ciphertext")
	}
}

// The header is AEAD associated data, so editing it breaks decryption even
// if an attacker could somehow re-sign the object.
func TestHeaderIsBoundToCiphertext(t *testing.T) {
	ak := mustKey(t)
	data, layerKey, _, priv := newObj(t, "hi", ak)

	d, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	forged := d.Header
	forged.ConversationID = "someone-elses-conversation"
	hdr, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild the file with the new header and the ORIGINAL ciphertext,
	// re-signing so only the AAD binding can catch it.
	var buf bytes.Buffer
	buf.Write([]byte("PIPL"))
	buf.Write([]byte{byte(FormatVersion >> 8), byte(FormatVersion)})
	l := len(hdr)
	buf.Write([]byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)})
	buf.Write(hdr)
	buf.Write(d.ct)
	sum := sha256.Sum256(buf.Bytes())
	buf.Write(ed25519.Sign(priv, sum[:]))

	d2, err := Decode(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := d2.Verify(priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("re-signed object should verify: %v", err)
	}
	if _, err := d2.Decrypt(layerKey); err == nil {
		t.Fatal("Decrypt accepted an object whose header was swapped (AAD binding broken)")
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	data, _, _, _ := newObj(t, "hi")
	d, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Decrypt(mustKey(t)); err == nil {
		t.Fatal("Decrypt accepted the wrong key")
	}
}

func TestNewGCMRejectsBadKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := newGCM(make([]byte, n)); err == nil {
			t.Fatalf("newGCM accepted a %d-byte key", n)
		}
	}
}

func TestSlotsOpenOnlyForTheirAccessKey(t *testing.T) {
	alice, bob, carol := mustKey(t), mustKey(t), mustKey(t)
	data, layerKey, _, _ := newObj(t, "hi", alice, bob)

	d, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	for name, ak := range map[string][]byte{"alice": alice, "bob": bob} {
		got, ok := d.UnlockSlot(ak)
		if !ok {
			t.Fatalf("%s has a slot but UnlockSlot failed", name)
		}
		if !bytes.Equal(got, layerKey) {
			t.Fatalf("%s unlocked the wrong layer key", name)
		}
	}
	if _, ok := d.UnlockSlot(carol); ok {
		t.Fatal("carol has no slot but UnlockSlot succeeded")
	}
}

func TestZeroSlotsOpenForNobody(t *testing.T) {
	data, _, _, _ := newObj(t, "hi") // no access keys => no slots
	d, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d.UnlockSlot(mustKey(t)); ok {
		t.Fatal("UnlockSlot succeeded against zero slots")
	}
}

func TestOpenWithCapabilitySingleLayer(t *testing.T) {
	ak := mustKey(t)
	data, _, pub, _ := newObj(t, "hello slots", ak)

	p, err := OpenWithCapability(data, Capability{AccessKey: ak, ObjSignPub: pub})
	if err != nil {
		t.Fatalf("OpenWithCapability: %v", err)
	}
	if p.Body != "hello slots" {
		t.Fatalf("body = %q", p.Body)
	}
}

// Hard revoke: wrap with slots for the remaining audience only. The
// survivor's ORIGINAL capability must still work — no re-granting — and the
// revoked peer's must not.
func TestOpenWithCapabilityAfterHardRevoke(t *testing.T) {
	bobKey, carolKey := mustKey(t), mustKey(t)
	data, _, pub, priv := newObj(t, "sensitive", bobKey, carolKey)

	bobCap := Capability{AccessKey: bobKey, ObjSignPub: pub}
	carolCap := Capability{AccessKey: carolKey, ObjSignPub: pub}
	if _, err := OpenWithCapability(data, carolCap); err != nil {
		t.Fatalf("carol should read before revocation: %v", err)
	}

	revoked, _ := wrap(t, data, priv, 2, bobKey) // slots for bob only

	p, err := OpenWithCapability(revoked, bobCap)
	if err != nil {
		t.Fatalf("bob lost access after revoking carol (grant was never touched): %v", err)
	}
	if p.Body != "sensitive" {
		t.Fatalf("body = %q", p.Body)
	}
	if _, err := OpenWithCapability(revoked, carolCap); err == nil {
		t.Fatal("carol still reads the object after hard revoke")
	}
}

// Hide = wrap with zero slots; unhide = peel the layer. Every pre-existing
// capability must work again afterwards.
func TestHideUnhideRoundTrip(t *testing.T) {
	ak := mustKey(t)
	data, _, pub, priv := newObj(t, "now you see me", ak)
	cap := Capability{AccessKey: ak, ObjSignPub: pub}

	hidden, hiddenLayerKey := wrap(t, data, priv, 2) // zero slots
	if _, err := OpenWithCapability(hidden, cap); err == nil {
		t.Fatal("hidden object was readable")
	}

	// unhide: owner decrypts the outer layer with the key it kept.
	d, err := Decode(hidden)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Header.Wrapped {
		t.Fatal("wrapped layer not marked Wrapped")
	}
	inner, err := d.Decrypt(hiddenLayerKey)
	if err != nil {
		t.Fatalf("owner cannot peel its own layer: %v", err)
	}
	if !bytes.Equal(inner, data) {
		t.Fatal("peeled layer does not reproduce the original object bytes")
	}
	p, err := OpenWithCapability(inner, cap)
	if err != nil {
		t.Fatalf("capability broken after unhide (must work with no re-granting): %v", err)
	}
	if p.Body != "now you see me" {
		t.Fatalf("body = %q", p.Body)
	}
}

// Wrapping never decrypts: layers nest, and one access key opens all of
// them as long as every layer has a slot for it.
func TestOpenWithCapabilityPeelsManyLayers(t *testing.T) {
	ak := mustKey(t)
	data, _, pub, priv := newObj(t, "deep", ak)
	for v := 2; v <= 6; v++ {
		data, _ = wrap(t, data, priv, v, ak)
	}
	p, err := OpenWithCapability(data, Capability{AccessKey: ak, ObjSignPub: pub})
	if err != nil {
		t.Fatalf("OpenWithCapability through 5 wraps: %v", err)
	}
	if p.Body != "deep" {
		t.Fatalf("body = %q", p.Body)
	}
}

// An access key that opens the outer layer but not an inner one yields no
// plaintext — access must hold at every layer.
func TestOpenWithCapabilityStopsAtLayerWithoutSlot(t *testing.T) {
	inner, outer := mustKey(t), mustKey(t)
	data, _, pub, priv := newObj(t, "deep", inner) // inner slot for `inner` only
	data, _ = wrap(t, data, priv, 2, outer)        // outer slot for `outer` only

	if _, err := OpenWithCapability(data, Capability{AccessKey: outer, ObjSignPub: pub}); err == nil {
		t.Fatal("capability opened an object it lacks an inner slot for")
	}
}

func TestOpenWithCapabilityRejectsForeignSigner(t *testing.T) {
	ak := mustKey(t)
	data, _, _, _ := newObj(t, "hi", ak)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithCapability(data, Capability{AccessKey: ak, ObjSignPub: otherPub}); err == nil {
		t.Fatal("OpenWithCapability accepted an object signed by another key")
	}
}
