package chat

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"github.com/antonio/pipl/internal/object"
	"github.com/antonio/pipl/internal/state"
	"github.com/antonio/pipl/internal/store"
)

// ErrNotOwner is returned when a peer tries to revoke or hide an object it
// did not send. Only the owner holds the object signing key, so only the
// owner can rewrite the file.
type ErrNotOwner struct{ ObjectID string }

func (e ErrNotOwner) Error() string {
	return fmt.Sprintf("you do not own object %s (only the sender can do this)", e.ObjectID)
}

// Owned reports the owner-side record for an object, if this peer sent it.
func (e *Env) Owned(objectID string) (state.OwnedObject, bool, error) {
	owned, err := e.St.Owned()
	if err != nil {
		return state.OwnedObject{}, false, err
	}
	o, ok := owned[objectID]
	return o, ok, nil
}

// RevokeFrom hard-revokes one recipient of a separate send: drop their
// access key from the audience and wrap the existing ciphertext in a new
// layer whose slots open only for the remaining keys.
//
// Plaintext is never touched (one encrypt pass over the existing
// ciphertext), and because everyone else keeps their original access key,
// NO ONE needs a new grant.
func (e *Env) RevokeFrom(convName, objectID, handle string) (layers, slots int, err error) {
	conv, err := e.Conversation(convName)
	if err != nil {
		return 0, 0, err
	}
	owned, err := e.St.Owned()
	if err != nil {
		return 0, 0, err
	}
	o, ok := owned[objectID]
	if !ok {
		return 0, 0, ErrNotOwner{objectID}
	}
	if o.Mode != "separate" {
		return 0, 0, fmt.Errorf("object %s went to the whole group under one shared key: "+
			"revoking one member needs a group-key rotation (roadmap) — send to a subset of "+
			"recipients for individually revocable messages, or hide it from everyone", objectID)
	}
	if _, ok := o.AccessKeys[handle]; !ok {
		return 0, 0, fmt.Errorf("%q has no access to object %s", handle, objectID)
	}
	if handle == e.ID.Handle {
		return 0, 0, fmt.Errorf("refusing to revoke your own access to %s", objectID)
	}

	delete(o.AccessKeys, handle)
	newLayerKey, err := object.NewKey()
	if err != nil {
		return 0, 0, err
	}
	var newSlots [][]byte
	for _, ak := range o.AccessKeys {
		slot, err := object.MakeSlot(ak, newLayerKey)
		if err != nil {
			return 0, 0, err
		}
		newSlots = append(newSlots, slot)
	}
	if err := wrapObject(conv, &o, newLayerKey, newSlots); err != nil {
		return 0, 0, err
	}
	if gn, ok := o.GrantFiles[handle]; ok {
		os.Remove(store.GrantPath(conv.Dir, gn))
		delete(o.GrantFiles, handle)
	}
	owned[objectID] = o
	if err := e.St.SaveOwned(owned); err != nil {
		return 0, 0, err
	}
	e.Notify(conv.ID)
	return len(o.LayerKeys), len(newSlots), nil
}

// Hide wraps the object with a key granted to NO ONE (zero slots).
// Existing grants stay in place but become inert; Unhide peels the layer
// and every one of them works again, with no re-granting.
func (e *Env) Hide(convName, objectID string) error {
	conv, err := e.Conversation(convName)
	if err != nil {
		return err
	}
	owned, err := e.St.Owned()
	if err != nil {
		return err
	}
	o, ok := owned[objectID]
	if !ok {
		return ErrNotOwner{objectID}
	}
	if o.Hidden {
		return fmt.Errorf("object %s is already hidden", objectID)
	}
	newLayerKey, err := object.NewKey()
	if err != nil {
		return err
	}
	if err := wrapObject(conv, &o, newLayerKey, nil); err != nil {
		return err
	}
	o.Hidden = true
	owned[objectID] = o
	if err := e.St.SaveOwned(owned); err != nil {
		return err
	}
	e.Notify(conv.ID)
	return nil
}

// Unhide peels the outermost layer, restoring the audience that existed
// before Hide. Nobody is re-granted.
func (e *Env) Unhide(convName, objectID string) error {
	conv, err := e.Conversation(convName)
	if err != nil {
		return err
	}
	owned, err := e.St.Owned()
	if err != nil {
		return err
	}
	o, ok := owned[objectID]
	if !ok {
		return ErrNotOwner{objectID}
	}
	if !o.Hidden {
		return fmt.Errorf("object %s is not hidden", objectID)
	}
	path := store.ObjectPath(conv.Dir, o.ObjectID)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	d, err := object.Decode(data)
	if err != nil {
		return err
	}
	if !d.Header.Wrapped || len(o.LayerKeys) < 2 {
		return fmt.Errorf("object %s is not wrapped (state out of sync?)", objectID)
	}
	inner, err := d.Decrypt(o.LayerKeys[0])
	if err != nil {
		return fmt.Errorf("cannot unwrap (state out of sync?): %w", err)
	}
	di, err := object.Decode(inner)
	if err != nil {
		return fmt.Errorf("inner object corrupt: %w", err)
	}
	if err := store.WriteAtomic(path, inner); err != nil {
		return err
	}
	o.LayerKeys = o.LayerKeys[1:]
	o.KeyVersion = di.Header.KeyVersion
	o.Hidden = false
	owned[objectID] = o
	if err := e.St.SaveOwned(owned); err != nil {
		return err
	}
	e.Notify(conv.ID)
	return nil
}

// RevokeAll deletes the object and every grant for it: permanent.
func (e *Env) RevokeAll(convName, objectID string) error {
	conv, err := e.Conversation(convName)
	if err != nil {
		return err
	}
	owned, err := e.St.Owned()
	if err != nil {
		return err
	}
	o, ok := owned[objectID]
	if !ok {
		return ErrNotOwner{objectID}
	}
	os.Remove(store.ObjectPath(conv.Dir, o.ObjectID))
	for _, gname := range o.GrantFiles {
		os.Remove(store.GrantPath(conv.Dir, gname))
	}
	delete(owned, objectID)
	if err := e.St.SaveOwned(owned); err != nil {
		return err
	}
	e.Notify(conv.ID)
	return nil
}

// RevokeSoft only deletes a recipient's grant file. Weak by design: a
// cached access key still opens the slot. Callers must say so.
func (e *Env) RevokeSoft(convName, objectID, handle string) error {
	conv, err := e.Conversation(convName)
	if err != nil {
		return err
	}
	owned, err := e.St.Owned()
	if err != nil {
		return err
	}
	o, ok := owned[objectID]
	if !ok {
		return ErrNotOwner{objectID}
	}
	if o.Mode != "separate" {
		return fmt.Errorf("object %s was sent under the shared group key", objectID)
	}
	if _, ok := o.AccessKeys[handle]; !ok {
		return fmt.Errorf("%q has no access to object %s", handle, objectID)
	}
	if gn, ok := o.GrantFiles[handle]; ok {
		os.Remove(store.GrantPath(conv.Dir, gn))
		delete(o.GrantFiles, handle)
	}
	owned[objectID] = o
	if err := e.St.SaveOwned(owned); err != nil {
		return err
	}
	e.Notify(conv.ID)
	return nil
}

// wrapObject superencrypts an object file in place: the existing file
// becomes the plaintext of a new signed layer whose key is offered through
// the given slots (nil slots = hidden from everyone). One encryption pass,
// no plaintext in memory — and reversible by peeling the layer off.
func wrapObject(conv state.Conversation, o *state.OwnedObject, newLayerKey []byte, slots [][]byte) error {
	path := store.ObjectPath(conv.Dir, o.ObjectID)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("object file missing: %w", err)
	}
	if _, err := object.Decode(data); err != nil {
		return fmt.Errorf("refusing to wrap: %w", err)
	}
	objPriv := ed25519.PrivateKey(o.ObjSignPriv)
	hdr := object.Header{
		ObjectID:       o.ObjectID,
		KeyVersion:     o.KeyVersion + 1,
		ConversationID: o.ConversationID,
		ObjSignPub:     objPriv.Public().(ed25519.PublicKey),
		Wrapped:        true,
		Slots:          slots,
	}
	wrapped, err := object.Encode(hdr, data, newLayerKey, objPriv)
	if err != nil {
		return err
	}
	if err := store.WriteAtomic(path, wrapped); err != nil {
		return err
	}
	o.LayerKeys = append([][]byte{newLayerKey}, o.LayerKeys...)
	o.KeyVersion++
	return nil
}
