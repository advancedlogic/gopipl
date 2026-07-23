package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/antonio/pipl/internal/object"
)

func openStore(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return s
}

func TestBlobsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	id, data, _ := mkObject(t, "conv1", "persist me")

	s := openStore(t, dir)
	if err := s.PutObject("conv1", id, data); err != nil {
		t.Fatal(err)
	}
	if err := s.PutGrant("conv1", "g1.grant", []byte("sealed")); err != nil {
		t.Fatal(err)
	}

	// Restart: a brand new Store over the same directory.
	s2 := openStore(t, dir)
	got, err := s2.Get(id)
	if err != nil {
		t.Fatalf("object did not survive restart: %v", err)
	}
	if string(got.Data) != string(data) {
		t.Fatal("object bytes changed across restart")
	}
	if got.Kind != KindObject {
		t.Fatalf("kind = %q after restart", got.Kind)
	}
	g, err := s2.Get("g1.grant")
	if err != nil {
		t.Fatalf("grant did not survive restart: %v", err)
	}
	if string(g.Data) != "sealed" {
		t.Fatal("grant bytes changed across restart")
	}
	if len(s2.List("conv1")) != 2 {
		t.Fatalf("List after restart returned %d, want 2", len(s2.List("conv1")))
	}
}

// THE security property: the signing key that decides who may rewrite an
// object must survive. If it were lost, the first writer after a restart
// would silently inherit the right to replace someone else's message.
func TestOwnershipSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	id, data, priv := mkObject(t, "conv1", "mine")

	s := openStore(t, dir)
	if err := s.PutObject("conv1", id, data); err != nil {
		t.Fatal(err)
	}

	s2 := openStore(t, dir)

	// A stranger must still be refused after the restart.
	malPub, malPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	layerKey, _ := object.NewKey()
	evil, err := object.Encode(object.Header{
		ObjectID: id, KeyVersion: 99, ConversationID: "conv1", ObjSignPub: malPub,
	}, []byte(`{"type":"text","body":"stolen"}`), layerKey, malPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.PutObject("conv1", id, evil); err != ErrNotOwner {
		t.Fatalf("after restart, stranger write = %v, want ErrNotOwner", err)
	}

	// And the real owner must still be allowed.
	wrapped := rewrap(t, "conv1", id, data, priv)
	if err := s2.PutObject("conv1", id, wrapped); err != nil {
		t.Fatalf("after restart, owner could not rewrite its own object: %v", err)
	}

	// Deletion authority too.
	if err := s2.DeleteObject(id, ed25519.Sign(malPriv, DeleteChallenge(id))); err != ErrNotOwner {
		t.Fatalf("after restart, stranger delete = %v, want ErrNotOwner", err)
	}
	if err := s2.DeleteObject(id, ed25519.Sign(priv, DeleteChallenge(id))); err != nil {
		t.Fatalf("after restart, owner delete: %v", err)
	}
}

func TestDeletesSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	id, data, priv := mkObject(t, "conv1", "delete me")

	s := openStore(t, dir)
	if err := s.PutObject("conv1", id, data); err != nil {
		t.Fatal(err)
	}
	if err := s.PutGrant("conv1", "g1.grant", []byte("sealed")); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteObject(id, ed25519.Sign(priv, DeleteChallenge(id))); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGrant("conv1", "g1.grant"); err != nil {
		t.Fatal(err)
	}

	// A deleted blob must not come back — that would silently undo a
	// revocation.
	s2 := openStore(t, dir)
	if _, err := s2.Get(id); err != ErrNotFound {
		t.Fatalf("deleted object resurrected after restart (err = %v)", err)
	}
	if _, err := s2.Get("g1.grant"); err != ErrNotFound {
		t.Fatal("deleted grant resurrected after restart")
	}
	if n := len(s2.List("conv1")); n != 0 {
		t.Fatalf("List after restart returned %d, want 0", n)
	}
}

// Revocation replaces an object in place; the persisted copy must be the
// new one, or a restart would undo it.
func TestRewriteIsPersisted(t *testing.T) {
	dir := t.TempDir()
	id, data, priv := mkObject(t, "conv1", "v1")

	s := openStore(t, dir)
	if err := s.PutObject("conv1", id, data); err != nil {
		t.Fatal(err)
	}
	wrapped := rewrap(t, "conv1", id, data, priv)
	if err := s.PutObject("conv1", id, wrapped); err != nil {
		t.Fatal(err)
	}

	s2 := openStore(t, dir)
	got, err := s2.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != string(wrapped) {
		t.Fatal("restart served the pre-revocation version of the object")
	}
}

func TestPersistedBlobsAreCiphertextOnDisk(t *testing.T) {
	dir := t.TempDir()
	id, data, _ := mkObject(t, "conv1", "the secret words")

	s := openStore(t, dir)
	if err := s.PutObject("conv1", id, data); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "conv1", id))
	if err != nil {
		t.Fatalf("blob not written where expected: %v", err)
	}
	for _, probe := range []string{"the secret words", "alice"} {
		if containsSub(raw, probe) {
			t.Fatalf("on-disk blob contains plaintext %q", probe)
		}
	}
	// And the sidecar must not leak anything either.
	sidecar, err := os.ReadFile(filepath.Join(dir, "conv1", id+".meta"))
	if err != nil {
		t.Fatal(err)
	}
	for _, probe := range []string{"the secret words", "alice"} {
		if containsSub(sidecar, probe) {
			t.Fatalf("sidecar contains plaintext %q", probe)
		}
	}
}

// A damaged blob must not take the server down: it is skipped and
// reported, and everything else still loads.
func TestCorruptBlobIsSkippedNotFatal(t *testing.T) {
	dir := t.TempDir()
	goodID, goodData, _ := mkObject(t, "conv1", "fine")
	badID, badData, _ := mkObject(t, "conv1", "damaged")

	s := openStore(t, dir)
	if err := s.PutObject("conv1", goodID, goodData); err != nil {
		t.Fatal(err)
	}
	if err := s.PutObject("conv1", badID, badData); err != nil {
		t.Fatal(err)
	}
	// Destroy one sidecar.
	if err := os.WriteFile(filepath.Join(dir, "conv1", badID+".meta"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	s2 := openStore(t, dir)
	if _, err := s2.Get(goodID); err != nil {
		t.Fatalf("a corrupt neighbour prevented the good blob from loading: %v", err)
	}
	if _, err := s2.Get(badID); err != ErrNotFound {
		t.Fatal("corrupt blob was loaded anyway")
	}
	if len(s2.Skipped()) != 1 {
		t.Fatalf("Skipped() = %v, want exactly one entry", s2.Skipped())
	}
}

// An object sidecar with no signing key cannot be authorized, so it must
// be refused rather than loaded as unowned.
func TestObjectWithoutSigningKeyIsSkipped(t *testing.T) {
	dir := t.TempDir()
	id, data, _ := mkObject(t, "conv1", "x")
	s := openStore(t, dir)
	if err := s.PutObject("conv1", id, data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "conv1", id+".meta"),
		[]byte(`{"kind":"object","updated_at":"2026-01-01T00:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	s2 := openStore(t, dir)
	if _, err := s2.Get(id); err != ErrNotFound {
		t.Fatal("an object with no signing key was loaded — nobody could be authorized to rewrite it")
	}
}

// An empty dir means memory-only, which the demos and tests rely on.
func TestEmptyDirIsMemoryOnly(t *testing.T) {
	s := openStore(t, "")
	id, data, _ := mkObject(t, "conv1", "x")
	if err := s.PutObject("conv1", id, data); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(id); err != nil {
		t.Fatalf("memory-only store did not keep the blob: %v", err)
	}
}

// Temp files from an interrupted write must not be mistaken for blobs.
func TestPartialWritesAreIgnoredOnLoad(t *testing.T) {
	dir := t.TempDir()
	id, data, _ := mkObject(t, "conv1", "x")
	s := openStore(t, dir)
	if err := s.PutObject("conv1", id, data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "conv1", ".tmp-leftover"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}

	s2 := openStore(t, dir)
	if n := len(s2.List("conv1")); n != 1 {
		t.Fatalf("List = %d, want 1 (a leftover temp file was loaded as a blob)", n)
	}
	if len(s2.Skipped()) != 0 {
		t.Fatalf("leftover temp file was reported as damage: %v", s2.Skipped())
	}
}
