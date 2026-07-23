package identity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func mustNew(t *testing.T, handle string) *Identity {
	t.Helper()
	id, err := New(handle)
	if err != nil {
		t.Fatalf("New(%q): %v", handle, err)
	}
	return id
}

func TestNewProducesDistinctUsableKeys(t *testing.T) {
	a, b := mustNew(t, "alice"), mustNew(t, "bob")

	if a.Handle != "alice" {
		t.Fatalf("handle = %q", a.Handle)
	}
	if len(a.SignPriv) != ed25519.PrivateKeySize {
		t.Fatalf("signing key length = %d", len(a.SignPriv))
	}
	if bytes.Equal(a.SignPriv, b.SignPriv) {
		t.Fatal("two identities share a signing key")
	}
	if bytes.Equal(a.BoxPriv.Bytes(), b.BoxPriv.Bytes()) {
		t.Fatal("two identities share a box key")
	}

	// The signing key must actually sign.
	msg := []byte("verify me")
	sig := ed25519.Sign(a.SignPriv, msg)
	if !ed25519.Verify(a.Public().SignPub, msg, sig) {
		t.Fatal("signature does not verify under the published public key")
	}
}

// PublicIdentity is the ONLY thing that may reach the server.
func TestPublicIdentityCarriesNoPrivateKeyMaterial(t *testing.T) {
	id := mustNew(t, "alice")
	pub := id.Public()

	if !bytes.Equal(pub.SignPub, id.SignPriv.Public().(ed25519.PublicKey)) {
		t.Fatal("SignPub does not match the private signing key")
	}
	if !bytes.Equal(pub.BoxPub, id.BoxPriv.PublicKey().Bytes()) {
		t.Fatal("BoxPub does not match the private box key")
	}

	wire, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	// The private seed is the first half of an Ed25519 private key.
	if bytes.Contains(wire, id.SignPriv.Seed()) {
		t.Fatal("serialized PublicIdentity contains the private signing seed")
	}
	if bytes.Contains(wire, id.BoxPriv.Bytes()) {
		t.Fatal("serialized PublicIdentity contains the private box key")
	}
}

func TestEqualAndFingerprint(t *testing.T) {
	a, b := mustNew(t, "alice"), mustNew(t, "bob")
	pa := a.Public()

	if !pa.Equal(a.Public()) {
		t.Fatal("identity not equal to itself")
	}
	if pa.Equal(b.Public()) {
		t.Fatal("distinct identities compared equal")
	}

	// A server swapping keys under a known handle must not compare equal:
	// this is what makes TOFU pinning meaningful.
	impostor := b.Public()
	impostor.Handle = "alice"
	if pa.Equal(impostor) {
		t.Fatal("key substitution under the same handle compared equal")
	}
	if pa.Fingerprint() == impostor.Fingerprint() {
		t.Fatal("distinct signing keys share a fingerprint")
	}
	if len(pa.Fingerprint()) != 16 { // 8 bytes hex
		t.Fatalf("fingerprint = %q, want 16 hex chars", pa.Fingerprint())
	}
	if pa.Fingerprint() != a.Public().Fingerprint() {
		t.Fatal("fingerprint is not stable across calls")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	id := mustNew(t, "alice")
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := id.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Handle != id.Handle {
		t.Fatalf("handle = %q, want %q", got.Handle, id.Handle)
	}
	if !bytes.Equal(got.SignPriv, id.SignPriv) {
		t.Fatal("signing key changed across save/load")
	}
	if !bytes.Equal(got.BoxPriv.Bytes(), id.BoxPriv.Bytes()) {
		t.Fatal("box key changed across save/load")
	}
	// A blob sealed to the original must open with the loaded identity.
	blob, err := SealTo(id.Public().BoxPub, []byte("still works"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := got.OpenSealed(blob)
	if err != nil {
		t.Fatalf("loaded identity cannot open sealed blob: %v", err)
	}
	if string(pt) != "still works" {
		t.Fatalf("plaintext = %q", pt)
	}
}

func TestSaveUsesOwnerOnlyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	id := mustNew(t, "alice")
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := id.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("identity file mode = %v, want no group/other access", perm)
	}
}

func TestLoadRejectsCorruptFiles(t *testing.T) {
	dir := t.TempDir()
	good := mustNew(t, "alice")

	badSign, err := json.Marshal(diskIdentity{
		Handle: "alice", SignPriv: []byte("too short"), BoxPriv: good.BoxPriv.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	badBox, err := json.Marshal(diskIdentity{
		Handle: "alice", SignPriv: good.SignPriv, BoxPriv: []byte("too short"),
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"not json":        []byte("{not json"),
		"bad signing key": badSign,
		"bad box key":     badBox,
		"empty":           nil,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load accepted a corrupt identity file")
			}
		})
	}

	if _, err := Load(filepath.Join(dir, "does-not-exist.json")); err == nil {
		t.Fatal("Load accepted a missing file")
	}
}

func TestSealToOpenSealedRoundTrip(t *testing.T) {
	recipient := mustNew(t, "bob")
	msg := []byte("a grant, sealed")

	blob, err := SealTo(recipient.Public().BoxPub, msg)
	if err != nil {
		t.Fatalf("SealTo: %v", err)
	}
	if bytes.Contains(blob, msg) {
		t.Fatal("sealed blob contains its plaintext")
	}

	pt, err := recipient.OpenSealed(blob)
	if err != nil {
		t.Fatalf("OpenSealed: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("plaintext = %q, want %q", pt, msg)
	}
}

// Trial decryption over a folder of grant files depends on this: a blob
// addressed to someone else must fail, not mis-open.
func TestOpenSealedRejectsBlobsForOthers(t *testing.T) {
	bob, mallory := mustNew(t, "bob"), mustNew(t, "mallory")

	blob, err := SealTo(bob.Public().BoxPub, []byte("for bob only"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mallory.OpenSealed(blob); err == nil {
		t.Fatal("mallory opened a blob sealed to bob")
	}
}

func TestSealToIsNonDeterministic(t *testing.T) {
	bob := mustNew(t, "bob")
	msg := []byte("same message")

	a, err := SealTo(bob.Public().BoxPub, msg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealTo(bob.Public().BoxPub, msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("sealing the same plaintext twice produced identical blobs")
	}
	// Both must still open: the ephemeral key is carried in the blob.
	for i, blob := range [][]byte{a, b} {
		pt, err := bob.OpenSealed(blob)
		if err != nil {
			t.Fatalf("blob %d: %v", i, err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("blob %d plaintext = %q", i, pt)
		}
	}
}

func TestOpenSealedRejectsTamperedBlobs(t *testing.T) {
	bob := mustNew(t, "bob")
	blob, err := SealTo(bob.Public().BoxPub, []byte("integrity matters"))
	if err != nil {
		t.Fatal(err)
	}

	// One flipped byte in each region: ephemeral key, nonce, ciphertext.
	for name, i := range map[string]int{
		"ephemeral key": 0,
		"nonce":         33,
		"ciphertext":    len(blob) - 1,
	} {
		t.Run(name, func(t *testing.T) {
			bad := bytes.Clone(blob)
			bad[i] ^= 0x01
			if _, err := bob.OpenSealed(bad); err == nil {
				t.Fatalf("OpenSealed accepted a blob with a flipped byte at %d", i)
			}
		})
	}
}

func TestOpenSealedRejectsTruncatedBlobs(t *testing.T) {
	bob := mustNew(t, "bob")
	blob, err := SealTo(bob.Public().BoxPub, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, sealOverhead, sealOverhead + 15} {
		if _, err := bob.OpenSealed(blob[:min(n, len(blob))]); err == nil {
			t.Fatalf("OpenSealed accepted a %d-byte blob", n)
		}
	}
}

// The sealed-box construction is a WIRE FORMAT: peers on other machines
// (and, later, non-Go clients) must derive the same key. Round-trip tests
// cannot see a change to the KDF salt or info string, because both sides
// change together — so pin a known-good blob. If this fails after an
// intentional format change, regenerate the vector AND bump the info
// string, because old peers can no longer open new blobs.
//
// Vector: X25519 recipient seed 0x01..0x20, ephemeral seed 0x40..0x5f,
// nonce 0xa0..0xab, plaintext "pipl golden vector".
func TestSealedBoxFormatIsStable(t *testing.T) {
	const (
		recipSeedHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
		blobHex      = "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a" +
			"a0a1a2a3a4a5a6a7a8a9aaab" +
			"f1a64d7d6552556fe0833489005daec83f8518f8cc8b8f47256ac9fcd4c199351f07"
	)
	seed, err := hex.DecodeString(recipSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := hex.DecodeString(blobHex)
	if err != nil {
		t.Fatal(err)
	}
	boxPriv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	id := &Identity{Handle: "vector", BoxPriv: boxPriv}

	pt, err := id.OpenSealed(blob)
	if err != nil {
		t.Fatalf("cannot open the pinned sealed box — the wire format changed "+
			"and existing peers/grants would break: %v", err)
	}
	if string(pt) != "pipl golden vector" {
		t.Fatalf("plaintext = %q, want %q", pt, "pipl golden vector")
	}
}

func TestSealToRejectsBadRecipientKey(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := SealTo(make([]byte, n), []byte("hi")); err == nil {
			t.Fatalf("SealTo accepted a %d-byte recipient key", n)
		}
	}
}
