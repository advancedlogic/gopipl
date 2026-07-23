package grant

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/antonio/pipl/internal/identity"
	"github.com/antonio/pipl/internal/object"
)

func mustIdentity(t *testing.T, handle string) *identity.Identity {
	t.Helper()
	id, err := identity.New(handle)
	if err != nil {
		t.Fatalf("identity.New(%q): %v", handle, err)
	}
	return id
}

func mustKey(t *testing.T) []byte {
	t.Helper()
	k, err := object.NewKey()
	if err != nil {
		t.Fatalf("object.NewKey: %v", err)
	}
	return k
}

func testCapability(t *testing.T) object.Capability {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate obj signing key: %v", err)
	}
	return object.Capability{ObjectID: "obj1", AccessKey: mustKey(t), ObjSignPub: pub}
}

func TestNewAndVerify(t *testing.T) {
	owner := mustIdentity(t, "alice")
	cap := testCapability(t)

	g, err := New(cap, "alice", "conv1", owner.SignPriv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if g.From != "alice" || g.ConversationID != "conv1" {
		t.Fatalf("provenance not carried: %+v", g)
	}
	if !bytes.Equal(g.Capability.AccessKey, cap.AccessKey) {
		t.Fatal("access key not carried")
	}
	if len(g.Sig) == 0 {
		t.Fatal("grant is unsigned")
	}
	if err := g.Verify(owner.Public().SignPub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// A forged grant must not pass: recipients verify against the pinned
// identity of the sender before ever touching the object.
func TestVerifyRejectsForgeries(t *testing.T) {
	owner, mallory := mustIdentity(t, "alice"), mustIdentity(t, "mallory")
	g, err := New(testCapability(t), "alice", "conv1", owner.SignPriv)
	if err != nil {
		t.Fatal(err)
	}

	if err := g.Verify(mallory.Public().SignPub); err == nil {
		t.Fatal("grant verified under the wrong identity key")
	}

	// Mallory signs her own grant but claims to be alice.
	forged, err := New(testCapability(t), "alice", "conv1", mallory.SignPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := forged.Verify(owner.Public().SignPub); err == nil {
		t.Fatal("grant signed by mallory verified as alice")
	}

	// Field tampering after signing must break the signature.
	for name, mutate := range map[string]func(*Grant){
		"conversation": func(g *Grant) { g.ConversationID = "other-conv" },
		"from":         func(g *Grant) { g.From = "mallory" },
		"access key":   func(g *Grant) { g.Capability.AccessKey = []byte("swapped-key-swapped-key-swapped!") },
		"object id":    func(g *Grant) { g.Capability.ObjectID = "other-object" },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := g
			mutate(&tampered)
			if err := tampered.Verify(owner.Public().SignPub); err == nil {
				t.Fatalf("tampering with %s did not break the signature", name)
			}
		})
	}

	t.Run("missing signature", func(t *testing.T) {
		unsigned := g
		unsigned.Sig = nil
		if err := unsigned.Verify(owner.Public().SignPub); err == nil {
			t.Fatal("unsigned grant verified")
		}
	})
}

func TestSealOpenRoundTrip(t *testing.T) {
	owner, bob := mustIdentity(t, "alice"), mustIdentity(t, "bob")
	cap := testCapability(t)

	g, err := New(cap, "alice", "conv1", owner.SignPriv)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Seal(g, bob.Public().BoxPub)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(blob, cap.AccessKey) {
		t.Fatal("sealed grant leaks the access key in the clear")
	}

	got, err := Open(bob, blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got.Capability.AccessKey, cap.AccessKey) {
		t.Fatal("access key changed across seal/open")
	}
	if err := got.Verify(owner.Public().SignPub); err != nil {
		t.Fatalf("signature broken across seal/open: %v", err)
	}
}

// Recipients scan the whole grants folder and trial-open every file, so
// "not addressed to me" must be a clean error.
func TestOpenRejectsGrantsForOthers(t *testing.T) {
	owner, bob, carol := mustIdentity(t, "alice"), mustIdentity(t, "bob"), mustIdentity(t, "carol")

	g, err := New(testCapability(t), "alice", "conv1", owner.SignPriv)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Seal(g, bob.Public().BoxPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(carol, blob); err == nil {
		t.Fatal("carol opened a grant sealed to bob")
	}
	if _, err := Open(bob, []byte("garbage that is long enough to pass length checks!!")); err == nil {
		t.Fatal("Open accepted garbage")
	}
}

func TestSealSymmetricRoundTrip(t *testing.T) {
	owner := mustIdentity(t, "alice")
	groupKey := mustKey(t)
	cap := testCapability(t)

	g, err := New(cap, "alice", "conv1", owner.SignPriv)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := SealSymmetric(g, groupKey)
	if err != nil {
		t.Fatalf("SealSymmetric: %v", err)
	}
	if bytes.Contains(blob, cap.AccessKey) {
		t.Fatal("group-encrypted grant leaks the access key in the clear")
	}

	got, err := OpenSymmetric(groupKey, blob)
	if err != nil {
		t.Fatalf("OpenSymmetric: %v", err)
	}
	if !bytes.Equal(got.Capability.AccessKey, cap.AccessKey) {
		t.Fatal("access key changed across symmetric seal/open")
	}
	if err := got.Verify(owner.Public().SignPub); err != nil {
		t.Fatalf("signature broken across symmetric seal/open: %v", err)
	}
}

func TestOpenSymmetricRejectsWrongKeyAndTampering(t *testing.T) {
	owner := mustIdentity(t, "alice")
	groupKey := mustKey(t)

	g, err := New(testCapability(t), "alice", "conv1", owner.SignPriv)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := SealSymmetric(g, groupKey)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := OpenSymmetric(mustKey(t), blob); err == nil {
		t.Fatal("OpenSymmetric accepted the wrong group key")
	}
	tampered := bytes.Clone(blob)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := OpenSymmetric(groupKey, tampered); err == nil {
		t.Fatal("OpenSymmetric accepted a tampered blob")
	}
	for _, n := range []int{0, 12, 27} {
		if _, err := OpenSymmetric(groupKey, blob[:n]); err == nil {
			t.Fatalf("OpenSymmetric accepted a %d-byte blob", n)
		}
	}
}

// The two grant flavours are distinguishable only by trial decryption; a
// personally-sealed grant must not open with the group key, and vice versa.
func TestGrantFlavoursDoNotCrossOpen(t *testing.T) {
	owner, bob := mustIdentity(t, "alice"), mustIdentity(t, "bob")
	groupKey := mustKey(t)

	g, err := New(testCapability(t), "alice", "conv1", owner.SignPriv)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(g, bob.Public().BoxPub)
	if err != nil {
		t.Fatal(err)
	}
	symmetric, err := SealSymmetric(g, groupKey)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := OpenSymmetric(groupKey, sealed); err == nil {
		t.Fatal("group key opened a personally sealed grant")
	}
	if _, err := Open(bob, symmetric); err == nil {
		t.Fatal("bob's identity opened a group-encrypted grant")
	}
}

func TestSymmetricHelpersRejectBadKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := symSeal(make([]byte, n), []byte("hi")); err == nil {
			t.Fatalf("symSeal accepted a %d-byte key", n)
		}
		if _, err := symOpen(make([]byte, n), make([]byte, 64)); err == nil {
			t.Fatalf("symOpen accepted a %d-byte key", n)
		}
	}
}

// ---- member keys -----------------------------------------------------------

func TestMemberKeyRoundTripAndVerify(t *testing.T) {
	creator, bob := mustIdentity(t, "alice"), mustIdentity(t, "bob")
	groupKey := mustKey(t)

	mk, err := NewMemberKey("conv1", groupKey, 1, "alice", creator.SignPriv)
	if err != nil {
		t.Fatalf("NewMemberKey: %v", err)
	}
	if err := mk.Verify(creator.Public().SignPub); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	blob, err := SealMemberKey(mk, bob.Public().BoxPub)
	if err != nil {
		t.Fatalf("SealMemberKey: %v", err)
	}
	if bytes.Contains(blob, groupKey) {
		t.Fatal("sealed member key leaks the group key in the clear")
	}

	got, err := OpenMemberKey(bob, blob)
	if err != nil {
		t.Fatalf("OpenMemberKey: %v", err)
	}
	if !bytes.Equal(got.GroupKey, groupKey) {
		t.Fatal("group key changed across seal/open")
	}
	if got.ConversationID != "conv1" || got.Epoch != 1 || got.From != "alice" {
		t.Fatalf("member key fields not carried: %+v", got)
	}
	if err := got.Verify(creator.Public().SignPub); err != nil {
		t.Fatalf("signature broken across seal/open: %v", err)
	}
}

// conv join trusts the group key only because the creator signed it — a
// member key injected by anyone else must be rejected.
func TestMemberKeyVerifyRejectsForgeries(t *testing.T) {
	creator, mallory := mustIdentity(t, "alice"), mustIdentity(t, "mallory")

	forged, err := NewMemberKey("conv1", mustKey(t), 1, "alice", mallory.SignPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := forged.Verify(creator.Public().SignPub); err == nil {
		t.Fatal("member key signed by mallory verified as alice")
	}

	mk, err := NewMemberKey("conv1", mustKey(t), 1, "alice", creator.SignPriv)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*MemberKey){
		"group key":    func(m *MemberKey) { m.GroupKey = mustKey(t) },
		"epoch":        func(m *MemberKey) { m.Epoch = 2 },
		"conversation": func(m *MemberKey) { m.ConversationID = "other-conv" },
		"from":         func(m *MemberKey) { m.From = "mallory" },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := mk
			mutate(&tampered)
			if err := tampered.Verify(creator.Public().SignPub); err == nil {
				t.Fatalf("tampering with %s did not break the signature", name)
			}
		})
	}
}

func TestOpenMemberKeyRejectsBlobsForOthers(t *testing.T) {
	creator, bob, carol := mustIdentity(t, "alice"), mustIdentity(t, "bob"), mustIdentity(t, "carol")

	mk, err := NewMemberKey("conv1", mustKey(t), 1, "alice", creator.SignPriv)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := SealMemberKey(mk, bob.Public().BoxPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMemberKey(carol, blob); err == nil {
		t.Fatal("carol opened a member key sealed to bob")
	}
}

// ---- end-to-end: a grant actually opens the object it describes ------------

func TestGrantDeliversWorkingCapability(t *testing.T) {
	owner, bob := mustIdentity(t, "alice"), mustIdentity(t, "bob")

	accessKey, layerKey := mustKey(t), mustKey(t)
	objPub, objPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := object.MakeSlot(accessKey, layerKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"type":"text","body":"end to end","from":"alice"}`)
	data, err := object.Encode(object.Header{
		ObjectID: "obj1", KeyVersion: 1, ConversationID: "conv1",
		ObjSignPub: objPub, Slots: [][]byte{slot},
	}, payload, layerKey, objPriv)
	if err != nil {
		t.Fatal(err)
	}

	g, err := New(object.Capability{ObjectID: "obj1", AccessKey: accessKey, ObjSignPub: objPub},
		"alice", "conv1", owner.SignPriv)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Seal(g, bob.Public().BoxPub)
	if err != nil {
		t.Fatal(err)
	}

	// Bob's read path: open the grant, verify provenance, open the object.
	got, err := Open(bob, blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := got.Verify(owner.Public().SignPub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	p, err := object.OpenWithCapability(data, got.Capability)
	if err != nil {
		t.Fatalf("capability from grant did not open the object: %v", err)
	}
	if p.Body != "end to end" {
		t.Fatalf("body = %q", p.Body)
	}
}
