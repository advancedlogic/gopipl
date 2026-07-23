// Package chat is the headless engine behind both front ends: the flag
// CLI and the Bubble Tea UI call the same functions here, so the two can
// never drift apart on anything security-relevant.
//
// Everything cryptographic still happens on the client. Nothing in this
// package sends a key, a plaintext, or a capability to the server — the
// server is only asked "who is this handle?" and told "something changed".
package chat

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/antonio/pipl/internal/api"
	"github.com/antonio/pipl/internal/grant"
	"github.com/antonio/pipl/internal/identity"
	"github.com/antonio/pipl/internal/object"
	"github.com/antonio/pipl/internal/state"
	"github.com/antonio/pipl/internal/store"
)

// Env bundles the loaded local state for one peer.
type Env struct {
	St  *state.State
	ID  *identity.Identity
	Cfg state.Config
	Cl  *api.Client // nil when no server is configured
}

func Load() (*Env, error) {
	st, err := state.Open()
	if err != nil {
		return nil, err
	}
	id, err := identity.Load(st.IdentityPath())
	if err != nil {
		return nil, fmt.Errorf("no identity found (run 'pipl init' first): %w", err)
	}
	cfg, err := st.LoadConfig()
	if err != nil {
		return nil, err
	}
	e := &Env{St: st, ID: id, Cfg: cfg}
	if cfg.Server != "" {
		e.Cl = api.New(cfg.Server)
	}
	return e, nil
}

// Handle is this peer's own handle.
func (e *Env) Handle() string { return e.ID.Handle }

func (e *Env) Conversation(name string) (state.Conversation, error) {
	convs, err := e.St.Conversations()
	if err != nil {
		return state.Conversation{}, err
	}
	c, ok := convs[name]
	if !ok {
		return state.Conversation{}, fmt.Errorf("unknown conversation %q", name)
	}
	return c, nil
}

// Conversations returns every known conversation, name-sorted for stable
// display.
func (e *Env) Conversations() ([]state.Conversation, error) {
	m, err := e.St.Conversations()
	if err != nil {
		return nil, err
	}
	out := make([]state.Conversation, 0, len(m))
	for _, c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Summary is a conversation plus enough activity to tell it apart from
// another one in a list. Two conversations with the same members look
// identical without this — which is exactly how you end up typing into a
// window nobody else is reading.
type Summary struct {
	Conversation state.Conversation
	Count        int
	Last         time.Time
	LastFrom     string
	// Err is set when this conversation could not be read (an unreachable
	// relay, say). Reported rather than swallowed so the list can say so
	// instead of silently showing zero messages.
	Err error
}

// Summaries describes every conversation, newest activity first, so the
// one being used is at the top.
func (e *Env) Summaries() ([]Summary, error) {
	convs, err := e.Conversations()
	if err != nil {
		return nil, err
	}
	out := make([]Summary, 0, len(convs))
	for _, c := range convs {
		s := Summary{Conversation: c}
		msgs, err := e.Messages(c)
		if err != nil {
			s.Err = err
		} else if len(msgs) > 0 {
			s.Count = len(msgs)
			last := msgs[len(msgs)-1]
			s.Last, s.LastFrom = last.SentAt, last.From
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Last.Equal(out[j].Last) {
			return out[i].Conversation.Name < out[j].Conversation.Name
		}
		return out[i].Last.After(out[j].Last)
	})
	return out, nil
}

// MemberIdentity resolves a handle to a public identity: self, a locally
// pinned peer, or (first contact) a server lookup that gets pinned TOFU.
// onPin, if set, is told about first-contact pins so a UI can surface the
// fingerprint for out-of-band verification.
func (e *Env) MemberIdentity(handle string, onPin func(identity.PublicIdentity)) (identity.PublicIdentity, error) {
	if handle == e.ID.Handle {
		return e.ID.Public(), nil
	}
	peers, err := e.St.Peers()
	if err != nil {
		return identity.PublicIdentity{}, err
	}
	if p, ok := peers[handle]; ok {
		return p, nil
	}
	if e.Cl == nil {
		return identity.PublicIdentity{}, fmt.Errorf("peer %q not pinned and no server configured", handle)
	}
	p, err := e.Cl.Lookup(handle)
	if err != nil {
		return identity.PublicIdentity{}, err
	}
	if p.Handle != handle {
		return identity.PublicIdentity{}, fmt.Errorf("server returned mismatched identity for %q", handle)
	}
	if err := e.St.PinPeer(p); err != nil {
		return identity.PublicIdentity{}, err
	}
	if onPin != nil {
		onPin(p)
	}
	return p, nil
}

// Notify pings the server that a conversation changed. Best-effort: peers
// still discover changes by scanning the folder.
func (e *Env) Notify(convID string) {
	if e.Cl == nil {
		return
	}
	_ = e.Cl.Notify(convID)
}

// ---- init ------------------------------------------------------------------

// Init creates and persists a new identity, registering it with the
// directory so peers can find it. Returns the public identity.
func Init(handle, server string) (identity.PublicIdentity, error) {
	st, err := state.Open()
	if err != nil {
		return identity.PublicIdentity{}, err
	}
	if _, err := os.Stat(st.IdentityPath()); err == nil {
		return identity.PublicIdentity{}, fmt.Errorf("identity already exists in %s", st.Home)
	}
	id, err := identity.New(handle)
	if err != nil {
		return identity.PublicIdentity{}, err
	}
	if err := id.Save(st.IdentityPath()); err != nil {
		return identity.PublicIdentity{}, err
	}
	if err := st.SaveConfig(state.Config{Server: server}); err != nil {
		return identity.PublicIdentity{}, err
	}
	pub := id.Public()
	if server != "" {
		if err := api.New(server).Register(pub); err != nil {
			return pub, fmt.Errorf("identity created, but registration failed: %w", err)
		}
	}
	return pub, nil
}

// Register re-publishes this peer's existing identity to the directory.
//
// It exists because a registration can be lost without the identity being
// lost — most often when the server is restarted without -data and its
// in-memory directory is wiped. Init refuses to run once an identity
// exists, so without this there was no way back: the peer stayed
// unresolvable (404) and no one could create a conversation including it.
//
// A 409 from the server means the handle is already held by DIFFERENT
// keys — you re-created an identity under a name someone (often a previous
// you) already claimed. The server refuses to reassign a handle on
// purpose: that is what stops it handing out attacker keys for a known
// name. The only clean recovery is a fresh handle; this returns a clear
// error rather than a bare "409 Conflict".
func (e *Env) Register() error {
	if e.Cl == nil {
		return fmt.Errorf("no server configured (run with a server to be findable)")
	}
	err := e.Cl.Register(e.ID.Public())
	if err != nil && strings.Contains(err.Error(), "409") {
		return fmt.Errorf(
			"the server already holds a different identity for the handle %q (fingerprint conflict): "+
				"a handle cannot be reassigned — that is what prevents key substitution. "+
				"If you re-created this identity, use a new handle. If the server's directory is simply stale "+
				"(restarted without -data), it must be cleared server-side", e.ID.Handle)
	}
	return err
}

// Unpin forgets a pinned peer so the next lookup re-pins the current
// identity from the server. This is the recovery for a stale pin: after a
// peer is re-created its keys change, and TOFU refuses the new ones until
// the old entry is dropped. Returns the fingerprint that was discarded.
func (e *Env) Unpin(handle string) (fingerprint string, ok bool, err error) {
	if handle == e.ID.Handle {
		return "", false, fmt.Errorf("cannot unpin yourself")
	}
	dropped, ok, err := e.St.UnpinPeer(handle)
	if err != nil || !ok {
		return "", ok, err
	}
	return dropped.Fingerprint(), true, nil
}

// HasIdentity reports whether this PIPL_HOME already holds an identity.
func HasIdentity() (bool, string, error) {
	st, err := state.Open()
	if err != nil {
		return false, "", err
	}
	_, err = os.Stat(st.IdentityPath())
	if os.IsNotExist(err) {
		return false, st.Home, nil
	}
	return err == nil, st.Home, err
}

// ---- conversations ---------------------------------------------------------

// Marker sits unencrypted in the shared folder: only the random
// conversation ID and member handles. (Handles being visible to the
// storage provider is a known v0.1 metadata leak — see design doc.)
type Marker struct {
	ID      string   `json:"conversation_id"`
	Creator string   `json:"creator"`
	Members []string `json:"members"`
}

func MarkerPath(dir string) string { return dir + string(os.PathSeparator) + "pipl-conv.json" }

// NewConversation creates a conversation and distributes the group key as
// sealed member-key blobs, one per member.
//
// dir selects the transport. A path makes the conversation folder-backed
// (peers with shared storage); an empty dir makes it relay-backed, where
// the encrypted blobs live on the server and peers need nothing in common
// but the invite code from Invite.
func (e *Env) NewConversation(name, dir string, with []string, onPin func(identity.PublicIdentity)) (state.Conversation, error) {
	if dir == "" && e.Cl == nil {
		return state.Conversation{}, fmt.Errorf(
			"a conversation needs either a shared folder or a server to relay through")
	}
	members := []string{e.ID.Handle}
	for _, h := range with {
		h = strings.TrimSpace(h)
		if h == "" || h == e.ID.Handle {
			continue
		}
		if _, err := e.MemberIdentity(h, onPin); err != nil {
			return state.Conversation{}, err
		}
		members = append(members, h)
	}
	sort.Strings(members)
	convID, err := object.NewID()
	if err != nil {
		return state.Conversation{}, err
	}

	conv := state.Conversation{
		Name: name, ID: convID, Dir: dir, Creator: e.ID.Handle,
		Members: members,
	}
	be, err := e.backendFor(conv)
	if err != nil {
		return state.Conversation{}, err
	}

	// The marker records the roster where joiners can find it. Folder
	// conversations keep it as a file (readable by whoever hosts the
	// folder — a known metadata leak); relay conversations carry the same
	// facts inside the invite code instead, so the server never gets a
	// roster it was not already able to infer from traffic.
	if dir != "" {
		marker, err := json.MarshalIndent(Marker{ID: convID, Creator: e.ID.Handle, Members: members}, "", "  ")
		if err != nil {
			return state.Conversation{}, err
		}
		if err := store.WriteAtomic(MarkerPath(dir), marker); err != nil {
			return state.Conversation{}, err
		}
		if err := os.MkdirAll(store.ObjectsDir(dir), 0o755); err != nil {
			return state.Conversation{}, err
		}
		if err := os.MkdirAll(store.GrantsDir(dir), 0o755); err != nil {
			return state.Conversation{}, err
		}
	}

	// Group key (epoch 1), sealed individually to each member: a one-time
	// fan-out at membership time. Afterwards a group message costs one
	// grant regardless of group size.
	groupKey, err := object.NewKey()
	if err != nil {
		return state.Conversation{}, err
	}
	for _, handle := range members {
		if handle == e.ID.Handle {
			continue
		}
		pub, err := e.MemberIdentity(handle, onPin)
		if err != nil {
			return state.Conversation{}, err
		}
		mk, err := grant.NewMemberKey(convID, groupKey, 1, e.ID.Handle, e.ID.SignPriv)
		if err != nil {
			return state.Conversation{}, err
		}
		blob, err := grant.SealMemberKey(mk, pub.BoxPub)
		if err != nil {
			return state.Conversation{}, err
		}
		mname, err := object.NewID()
		if err != nil {
			return state.Conversation{}, err
		}
		if err := be.PutGrant(mname+".mkey", blob); err != nil {
			return state.Conversation{}, err
		}
	}

	conv.GroupKey = groupKey
	if err := e.saveConv(name, conv); err != nil {
		return state.Conversation{}, err
	}
	e.Notify(convID)
	return conv, nil
}

// JoinConversation joins a folder-backed conversation by reading the
// marker its creator left in the shared folder. For relay-backed
// conversations use JoinInvite instead.
func (e *Env) JoinConversation(name, dir string, onPin func(identity.PublicIdentity)) (state.Conversation, error) {
	data, err := os.ReadFile(MarkerPath(dir))
	if err != nil {
		return state.Conversation{}, fmt.Errorf("no conversation marker in %s: %w", dir, err)
	}
	var m Marker
	if err := json.Unmarshal(data, &m); err != nil {
		return state.Conversation{}, err
	}
	return e.join(name, dir, m, onPin)
}

// JoinInvite joins using an invite code, which carries the same facts a
// folder marker would (conversation ID, creator, roster). The code is not
// a secret that grants access: the group key still arrives only as a
// member-key blob sealed to this peer's identity and signed by the
// creator, so a stolen code lets nobody read anything.
func (e *Env) JoinInvite(name, code string, onPin func(identity.PublicIdentity)) (state.Conversation, error) {
	inv, err := ParseInvite(code)
	if err != nil {
		return state.Conversation{}, err
	}
	if inv.Server != "" && e.Cfg.Server == "" {
		return state.Conversation{}, fmt.Errorf(
			"this invite relays through %s but you have no server configured (re-run 'pipl init -server %s')",
			inv.Server, inv.Server)
	}
	return e.join(name, inv.Dir, Marker{ID: inv.ID, Creator: inv.Creator, Members: inv.Members}, onPin)
}

// join is the shared tail of both: verify membership, then recover the
// group key from the sealed member-key blob addressed to this peer. The
// key is trusted only because the conversation creator signed it.
func (e *Env) join(name, dir string, m Marker, onPin func(identity.PublicIdentity)) (state.Conversation, error) {
	found := false
	for _, h := range m.Members {
		if h == e.ID.Handle {
			found = true
			continue
		}
		if _, err := e.MemberIdentity(h, onPin); err != nil {
			return state.Conversation{}, err
		}
	}
	if !found {
		return state.Conversation{}, fmt.Errorf("your handle %q is not a member of this conversation", e.ID.Handle)
	}
	creator, err := e.MemberIdentity(m.Creator, onPin)
	if err != nil {
		return state.Conversation{}, err
	}
	conv := state.Conversation{
		Name: name, ID: m.ID, Dir: dir, Creator: m.Creator, Members: m.Members,
	}
	be, err := e.backendFor(conv)
	if err != nil {
		return state.Conversation{}, err
	}
	mkFiles, err := be.MemberKeys()
	if err != nil {
		return state.Conversation{}, err
	}
	var groupKey []byte
	forThisConv := 0 // member keys that belong to this conversation
	for _, f := range mkFiles {
		mk, err := grant.OpenMemberKey(e.ID, f.Data)
		if err != nil {
			continue // not sealed to us
		}
		if mk.ConversationID != m.ID || mk.From != m.Creator {
			continue
		}
		forThisConv++
		if mk.Verify(ed25519.PublicKey(creator.SignPub)) != nil {
			continue
		}
		groupKey = mk.GroupKey
		break
	}
	if groupKey == nil {
		where := dir
		if where == "" {
			where = "the relay"
		}
		// Distinguish the two failure modes: none of the member keys were
		// sealed to us (an identity mismatch — the usual cause is the
		// creator having pinned a stale copy of our identity, e.g. after
		// we were re-created), versus one that was sealed to us but signed
		// by someone other than the named creator.
		if forThisConv == 0 {
			isMember := false
			for _, h := range m.Members {
				if h == e.ID.Handle {
					isMember = true
				}
			}
			if isMember {
				return state.Conversation{}, fmt.Errorf(
					"you are listed as a member of this conversation, but no member key in %s is sealed to your identity — "+
						"the creator (%s) likely pinned an older copy of %q. Ask them to re-add you: on their side, "+
						"remove %q from peers.json and re-create the conversation (your current identity must be registered: 'pipl register')",
					where, m.Creator, e.ID.Handle, e.ID.Handle)
			}
			return state.Conversation{}, fmt.Errorf(
				"your handle %q is not among this conversation's members (%v)", e.ID.Handle, m.Members)
		}
		return state.Conversation{}, fmt.Errorf(
			"a member key for you in %s failed verification against the creator %q's signing key "+
				"(is %q the identity that really created it?)", where, m.Creator, m.Creator)
	}
	conv.GroupKey = groupKey
	if err := e.saveConv(name, conv); err != nil {
		return state.Conversation{}, err
	}
	return conv, nil
}

func (e *Env) saveConv(name string, conv state.Conversation) error {
	convs, err := e.St.Conversations()
	if err != nil {
		return err
	}
	convs[name] = conv
	return e.St.SaveConversations(convs)
}

// ---- send ------------------------------------------------------------------

// SendResult reports what a send actually did, so a UI can be honest about
// which audience model was used.
type SendResult struct {
	ObjectID string
	Mode     string   // "group" or "separate"
	Audience []string // handles that can read it (excluding the sender)
}

// Send encrypts a message into the conversation folder and drops the
// grants that let the audience read it.
//
// recipients selects the audience:
//
//   - nil / everyone: one shared group key — ONE slot and ONE grant file
//     regardless of group size.
//   - a subset: a personal access key per recipient — one slot and one
//     sealed grant each. Members outside the subset get no slot, so they
//     genuinely cannot read it, and any recipient can later be revoked
//     alone (re-wrap with slots for the rest; nobody is re-granted).
//
// A subset send is exactly the `-separate` model, chosen automatically:
// per-message recipient selection is only possible with per-recipient keys.
func (e *Env) Send(convName, body string, recipients []string, forceSeparate bool) (SendResult, error) {
	conv, err := e.Conversation(convName)
	if err != nil {
		return SendResult{}, err
	}
	audience, subset, err := resolveAudience(conv, e.ID.Handle, recipients)
	if err != nil {
		return SendResult{}, err
	}
	separate := subset || forceSeparate

	// Per-object key material: a fresh layer key and a fresh signing
	// keypair. The private half stays in owned.json — it IS the power to
	// revoke.
	layerKey, err := object.NewKey()
	if err != nil {
		return SendResult{}, err
	}
	objPub, objPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SendResult{}, err
	}
	oid, err := object.NewID()
	if err != nil {
		return SendResult{}, err
	}
	payload, err := json.Marshal(object.Payload{
		Type: "text", Body: body, From: e.ID.Handle, SentAt: time.Now().UTC(),
	})
	if err != nil {
		return SendResult{}, err
	}

	var slots [][]byte
	accessKeys := map[string][]byte{}
	mode := "group"
	if separate {
		mode = "separate"
		// The sender is included so their own client can re-read the
		// message it sent.
		for _, handle := range withSender(audience, e.ID.Handle) {
			ak, err := object.NewKey()
			if err != nil {
				return SendResult{}, err
			}
			accessKeys[handle] = ak
			slot, err := object.MakeSlot(ak, layerKey)
			if err != nil {
				return SendResult{}, err
			}
			slots = append(slots, slot)
		}
	} else {
		if conv.GroupKey == nil {
			return SendResult{}, fmt.Errorf("conversation has no group key (re-join it)")
		}
		slot, err := object.MakeSlot(conv.GroupKey, layerKey)
		if err != nil {
			return SendResult{}, err
		}
		slots = append(slots, slot)
	}

	hdr := object.Header{
		ObjectID:       oid,
		KeyVersion:     1,
		ConversationID: conv.ID,
		ObjSignPub:     objPub,
		PrevObject:     conv.LastObject,
		Slots:          slots,
	}
	data, err := object.Encode(hdr, payload, layerKey, objPriv)
	if err != nil {
		return SendResult{}, err
	}
	be, err := e.backendFor(conv)
	if err != nil {
		return SendResult{}, err
	}
	if err := be.PutObject(oid, data); err != nil {
		return SendResult{}, err
	}

	grantFiles := map[string]string{}
	if separate {
		for handle, ak := range accessKeys {
			cap := object.Capability{ObjectID: oid, AccessKey: ak, ObjSignPub: objPub}
			g, err := grant.New(cap, e.ID.Handle, conv.ID, e.ID.SignPriv)
			if err != nil {
				return SendResult{}, err
			}
			pub, err := e.MemberIdentity(handle, nil)
			if err != nil {
				return SendResult{}, err
			}
			blob, err := grant.Seal(g, pub.BoxPub)
			if err != nil {
				return SendResult{}, err
			}
			gname, err := object.NewID()
			if err != nil {
				return SendResult{}, err
			}
			gname += ".grant"
			if err := be.PutGrant(gname, blob); err != nil {
				return SendResult{}, err
			}
			grantFiles[handle] = gname
		}
	} else {
		cap := object.Capability{ObjectID: oid, AccessKey: conv.GroupKey, ObjSignPub: objPub}
		g, err := grant.New(cap, e.ID.Handle, conv.ID, e.ID.SignPriv)
		if err != nil {
			return SendResult{}, err
		}
		blob, err := grant.SealSymmetric(g, conv.GroupKey)
		if err != nil {
			return SendResult{}, err
		}
		gname, err := object.NewID()
		if err != nil {
			return SendResult{}, err
		}
		gname += ".grant"
		if err := be.PutGrant(gname, blob); err != nil {
			return SendResult{}, err
		}
		grantFiles["*group*"] = gname
	}

	owned, err := e.St.Owned()
	if err != nil {
		return SendResult{}, err
	}
	owned[oid] = state.OwnedObject{
		ObjectID: oid, ConversationID: conv.ID, KeyVersion: 1,
		LayerKeys: [][]byte{layerKey}, ObjSignPriv: objPriv,
		Mode: mode, AccessKeys: accessKeys, GrantFiles: grantFiles,
	}
	if err := e.St.SaveOwned(owned); err != nil {
		return SendResult{}, err
	}
	conv.LastObject = oid
	if err := e.saveConv(convName, conv); err != nil {
		return SendResult{}, err
	}
	e.Notify(conv.ID)
	return SendResult{ObjectID: oid, Mode: mode, Audience: audience}, nil
}

// resolveAudience validates the requested recipients against the roster
// and reports whether this is a strict subset (which forces per-recipient
// keys). The sender is never counted as part of the audience.
func resolveAudience(conv state.Conversation, self string, recipients []string) (audience []string, subset bool, err error) {
	others := make([]string, 0, len(conv.Members))
	isMember := map[string]bool{}
	for _, m := range conv.Members {
		isMember[m] = true
		if m != self {
			others = append(others, m)
		}
	}
	sort.Strings(others)
	if len(recipients) == 0 {
		return others, false, nil
	}
	seen := map[string]bool{}
	for _, r := range recipients {
		r = strings.TrimSpace(r)
		if r == "" || r == self {
			continue
		}
		if !isMember[r] {
			return nil, false, fmt.Errorf("%q is not a member of this conversation", r)
		}
		seen[r] = true
	}
	if len(seen) == 0 {
		return nil, false, fmt.Errorf("no recipients selected")
	}
	for _, h := range others {
		if seen[h] {
			audience = append(audience, h)
		}
	}
	return audience, len(audience) < len(others), nil
}

func withSender(audience []string, self string) []string {
	out := append([]string{}, audience...)
	out = append(out, self)
	sort.Strings(out)
	return out
}

// ---- receive ---------------------------------------------------------------

// Message is one decrypted object, ready to display.
type Message struct {
	ObjectID string
	From     string
	Body     string
	SentAt   time.Time
	Mine     bool
	// Audience is the handles this peer can tell the message went to.
	// Only meaningful for messages this peer sent (the owner knows its own
	// access keys); empty for received messages, where the audience is
	// deliberately not visible.
	Audience []string
}

// Messages is the whole read path: trial-open every grant file, verify
// grant signatures against pinned member identities, verify object
// signatures, peel layers, decrypt. Every failure mode — not addressed to
// us, revoked, hidden, deleted — is silently skipped: absence of access is
// not an error.
func (e *Env) Messages(conv state.Conversation) ([]Message, error) {
	be, err := e.backendFor(conv)
	if err != nil {
		return nil, err
	}
	files, err := be.Grants()
	if err != nil {
		return nil, err
	}
	isMember := map[string]bool{}
	for _, m := range conv.Members {
		isMember[m] = true
	}
	owned, err := e.St.Owned()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var msgs []Message
	for _, f := range files {
		blob := f.Data
		// Personal sealed grant first, then the conversation group key.
		g, err := grant.Open(e.ID, blob)
		if err != nil && conv.GroupKey != nil {
			g, err = grant.OpenSymmetric(conv.GroupKey, blob)
		}
		if err != nil {
			continue // not addressed to us
		}
		if g.ConversationID != conv.ID || !isMember[g.From] {
			continue
		}
		sender, err := e.MemberIdentity(g.From, nil)
		if err != nil {
			continue
		}
		if g.Verify(ed25519.PublicKey(sender.SignPub)) != nil {
			continue // forged grant
		}
		if seen[g.Capability.ObjectID] {
			continue
		}
		data, err := be.GetObject(g.Capability.ObjectID)
		if err != nil {
			continue // object deleted (fully revoked)
		}
		p, err := object.OpenWithCapability(data, g.Capability)
		if err != nil || p.Type != "text" {
			continue // revoked, hidden, or forged: no access
		}
		seen[g.Capability.ObjectID] = true
		m := Message{
			ObjectID: g.Capability.ObjectID,
			From:     p.From, Body: p.Body, SentAt: p.SentAt,
			Mine: p.From == e.ID.Handle,
		}
		// For our own separate sends we know the audience, because we
		// minted one access key per recipient.
		if o, ok := owned[m.ObjectID]; ok && o.Mode == "separate" {
			for h := range o.AccessKeys {
				if h != e.ID.Handle {
					m.Audience = append(m.Audience, h)
				}
			}
			sort.Strings(m.Audience)
		}
		msgs = append(msgs, m)
	}
	sort.Slice(msgs, func(i, j int) bool {
		if msgs[i].SentAt.Equal(msgs[j].SentAt) {
			return msgs[i].ObjectID < msgs[j].ObjectID
		}
		return msgs[i].SentAt.Before(msgs[j].SentAt)
	})
	return msgs, nil
}
