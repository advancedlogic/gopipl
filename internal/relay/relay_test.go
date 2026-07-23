package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/antonio/pipl/internal/object"
)

// mkObject builds a signed object the way the client does.
func mkObject(t *testing.T, convID, body string) (id string, data []byte, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err = object.NewID()
	if err != nil {
		t.Fatal(err)
	}
	layerKey, err := object.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	ak, err := object.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	slot, err := object.MakeSlot(ak, layerKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(object.Payload{Type: "text", Body: body, From: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	data, err = object.Encode(object.Header{
		ObjectID: id, KeyVersion: 1, ConversationID: convID,
		ObjSignPub: pub, Slots: [][]byte{slot},
	}, payload, layerKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return id, data, priv
}

// rewrap re-signs an object under the given key, simulating what
// revocation/hide does: a new layer wrapping the old bytes.
func rewrap(t *testing.T, convID, id string, inner []byte, priv ed25519.PrivateKey) []byte {
	t.Helper()
	layerKey, err := object.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	data, err := object.Encode(object.Header{
		ObjectID: id, KeyVersion: 2, ConversationID: convID,
		ObjSignPub: priv.Public().(ed25519.PublicKey), Wrapped: true,
	}, inner, layerKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPutAndGetObject(t *testing.T) {
	s := NewStore()
	id, data, _ := mkObject(t, "conv1", "hello")

	if err := s.PutObject("conv1", id, data); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	got, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.Data) != string(data) {
		t.Fatal("stored bytes differ from what was written")
	}
	if got.Kind != KindObject {
		t.Fatalf("kind = %q", got.Kind)
	}
}

// The relay must never become a place where plaintext appears.
func TestStoredBlobIsCiphertextOnly(t *testing.T) {
	s := NewStore()
	id, data, _ := mkObject(t, "conv1", "the secret words")
	if err := s.PutObject("conv1", id, data); err != nil {
		t.Fatal(err)
	}
	b, err := s.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, probe := range []string{"the secret words", "alice"} {
		if containsSub(b.Data, probe) {
			t.Fatalf("relay blob contains plaintext %q", probe)
		}
	}
}

func containsSub(hay []byte, needle string) bool {
	n := []byte(needle)
	for i := 0; i+len(n) <= len(hay); i++ {
		if string(hay[i:i+len(n)]) == string(n) {
			return true
		}
	}
	return false
}

// The owner rewrites its own object: this is exactly revoke/hide.
func TestOwnerCanRewriteItsObject(t *testing.T) {
	s := NewStore()
	id, data, priv := mkObject(t, "conv1", "hello")
	if err := s.PutObject("conv1", id, data); err != nil {
		t.Fatal(err)
	}
	wrapped := rewrap(t, "conv1", id, data, priv)
	if err := s.PutObject("conv1", id, wrapped); err != nil {
		t.Fatalf("owner could not rewrite its own object: %v", err)
	}
	got, _ := s.Get(id)
	if string(got.Data) != string(wrapped) {
		t.Fatal("rewrite did not take effect")
	}
}

// THE core authorization property: nobody else can overwrite an object,
// even with a perfectly valid object signed by their own key. Without
// this, any peer could destroy or replace another peer's messages.
func TestStrangerCannotOverwriteAnotherPeersObject(t *testing.T) {
	s := NewStore()
	id, data, _ := mkObject(t, "conv1", "alice's message")
	if err := s.PutObject("conv1", id, data); err != nil {
		t.Fatal(err)
	}

	// Mallory forges a well-formed object reusing alice's object ID,
	// signed with her own key. It is internally valid — and must still
	// be refused.
	malPub, malPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	layerKey, _ := object.NewKey()
	evil, err := object.Encode(object.Header{
		ObjectID: id, KeyVersion: 99, ConversationID: "conv1", ObjSignPub: malPub,
	}, []byte(`{"type":"text","body":"mallory was here"}`), layerKey, malPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutObject("conv1", id, evil); err != ErrNotOwner {
		t.Fatalf("PutObject error = %v, want ErrNotOwner", err)
	}
	got, _ := s.Get(id)
	if string(got.Data) != string(data) {
		t.Fatal("a stranger's write modified the stored object")
	}
}

func TestPutObjectRejectsMalformedAndMismatched(t *testing.T) {
	s := NewStore()
	id, data, _ := mkObject(t, "conv1", "hello")

	t.Run("not a pipl object", func(t *testing.T) {
		if err := s.PutObject("conv1", "someid", []byte("garbage")); err == nil {
			t.Fatal("accepted non-object bytes")
		}
	})
	t.Run("id does not match header", func(t *testing.T) {
		if err := s.PutObject("conv1", "a-different-id", data); err == nil {
			t.Fatal("accepted an object whose header names another id")
		}
	})
	t.Run("conversation does not match header", func(t *testing.T) {
		if err := s.PutObject("other-conv", id, data); err == nil {
			t.Fatal("accepted an object into the wrong conversation")
		}
	})
	t.Run("tampered bytes", func(t *testing.T) {
		bad := append([]byte(nil), data...)
		bad[len(bad)-1] ^= 0x01 // break the signature
		if err := s.PutObject("conv1", id, bad); err == nil {
			t.Fatal("accepted an object with a broken signature")
		}
	})
}

func TestGrantsAreAppendOnly(t *testing.T) {
	s := NewStore()
	if err := s.PutGrant("conv1", "g1", []byte("sealed blob")); err != nil {
		t.Fatalf("PutGrant: %v", err)
	}
	if err := s.PutGrant("conv1", "g1", []byte("replacement")); err == nil {
		t.Fatal("a grant was overwritten; grants must be append-only")
	}
	got, err := s.Get("g1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "sealed blob" {
		t.Fatal("stored grant was modified")
	}
}

func TestListScopesToConversation(t *testing.T) {
	s := NewStore()
	id1, d1, _ := mkObject(t, "conv1", "one")
	id2, d2, _ := mkObject(t, "conv2", "two")
	if err := s.PutObject("conv1", id1, d1); err != nil {
		t.Fatal(err)
	}
	if err := s.PutObject("conv2", id2, d2); err != nil {
		t.Fatal(err)
	}
	if err := s.PutGrant("conv1", "g1", []byte("x")); err != nil {
		t.Fatal(err)
	}

	got := s.List("conv1")
	if len(got) != 2 {
		t.Fatalf("List(conv1) returned %d entries, want 2", len(got))
	}
	for _, e := range got {
		if e.ID == id2 {
			t.Fatal("List leaked a blob from another conversation")
		}
	}
	if len(s.List("nope")) != 0 {
		t.Fatal("List of an unknown conversation returned entries")
	}
}

func TestDeleteRequiresOwnerSignature(t *testing.T) {
	s := NewStore()
	id, data, priv := mkObject(t, "conv1", "hello")
	if err := s.PutObject("conv1", id, data); err != nil {
		t.Fatal(err)
	}

	// A stranger's signature over the right challenge must not work.
	_, malPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteObject(id, ed25519.Sign(malPriv, DeleteChallenge(id))); err != ErrNotOwner {
		t.Fatalf("delete by stranger: err = %v, want ErrNotOwner", err)
	}
	if _, err := s.Get(id); err != nil {
		t.Fatal("stranger's delete removed the object")
	}

	// A signature over a DIFFERENT object's challenge must not work
	// either — that is what the domain separation is for.
	otherID, otherData, _ := mkObject(t, "conv1", "other")
	if err := s.PutObject("conv1", otherID, otherData); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteObject(id, ed25519.Sign(priv, DeleteChallenge(otherID))); err != ErrNotOwner {
		t.Fatalf("replayed signature: err = %v, want ErrNotOwner", err)
	}

	// The owner can delete.
	if err := s.DeleteObject(id, ed25519.Sign(priv, DeleteChallenge(id))); err != nil {
		t.Fatalf("owner delete: %v", err)
	}
	if _, err := s.Get(id); err != ErrNotFound {
		t.Fatalf("after delete, Get = %v, want ErrNotFound", err)
	}
	if len(s.List("conv1")) != 1 {
		t.Fatal("deleted blob still listed")
	}
}

func TestGetReturnsACopy(t *testing.T) {
	s := NewStore()
	id, data, _ := mkObject(t, "conv1", "hello")
	if err := s.PutObject("conv1", id, data); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(id)
	got.Data[0] ^= 0xff // mutate the caller's copy

	again, _ := s.Get(id)
	if again.Data[0] != data[0] {
		t.Fatal("mutating a returned blob corrupted the store")
	}
}
