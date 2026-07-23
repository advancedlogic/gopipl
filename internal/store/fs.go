// Package store implements the storage backend. v0.1: local filesystem
// only — but a folder inside Dropbox/Drive/etc. already works, since the
// layout is just files. Conversation dir layout:
//
//	<dir>/pipl-conv.json   conversation marker (id + member handles)
//	<dir>/objects/<id>.pipl  encrypted object files
//	<dir>/grants/<rand>.grant  sealed grant files
package store

import (
	"os"
	"path/filepath"
)

func ObjectsDir(dir string) string { return filepath.Join(dir, "objects") }
func GrantsDir(dir string) string  { return filepath.Join(dir, "grants") }

func ObjectPath(dir, objectID string) string {
	return filepath.Join(ObjectsDir(dir), objectID+".pipl")
}

func GrantPath(dir, name string) string {
	return filepath.Join(GrantsDir(dir), name)
}

// WriteAtomic writes via temp file + rename so no reader (or sync
// client) ever observes a torn file. This is what makes hard revoke —
// replacing an object in place — safe.
func WriteAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
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
	return os.Rename(name, path)
}

// ListGrantFiles returns full paths of all grant files in a conversation
// directory. Missing directory is not an error (empty conversation).
func ListGrantFiles(dir string) ([]string, error) {
	return listByExt(dir, ".grant")
}

// ListMemberKeyFiles returns full paths of all sealed member-key files
// (how the conversation group key reaches each member).
func ListMemberKeyFiles(dir string) ([]string, error) {
	return listByExt(dir, ".mkey")
}

func listByExt(dir, ext string) ([]string, error) {
	entries, err := os.ReadDir(GrantsDir(dir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ext {
			out = append(out, GrantPath(dir, e.Name()))
		}
	}
	return out, nil
}
