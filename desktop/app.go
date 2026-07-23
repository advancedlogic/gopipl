package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/antonio/pipl/internal/chat"
	"github.com/antonio/pipl/internal/identity"
	"github.com/antonio/pipl/internal/state"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the single Wails binding. Every method forwards to internal/chat —
// the same headless engine the CLI and Bubble Tea UI use — so the three
// front ends cannot drift on anything security-relevant. No key material,
// plaintext, or capability is ever handled here; the engine keeps all of
// that on the client and never sends it to the server.
type App struct {
	ctx context.Context

	mu  sync.Mutex
	env *chat.Env // nil until an identity exists and Load succeeds

	// pins collects TOFU first-contact fingerprints seen since the last
	// call that drains them, so the UI can surface them for out-of-band
	// verification. Populated by the onPin callback the engine invokes.
	pinsMu sync.Mutex
	pins   []PinNotice
}

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	// Try to load an existing peer. A missing identity is not an error —
	// the frontend routes to first-run setup when Status reports it.
	if ok, _, _ := chat.HasIdentity(); ok {
		if env, err := chat.Load(); err == nil {
			a.mu.Lock()
			a.env = env
			a.mu.Unlock()
			// Re-announce this identity to the directory on every startup.
			// The server's directory is in-memory unless it was started
			// with -data, so a server restart drops every registration and
			// peers become unresolvable ("unknown handle"). Re-posting the
			// same identity is an idempotent upsert, so this is safe to do
			// unconditionally and keeps a running peer discoverable.
			a.reannounce(env)
		}
	}
	go a.watch(ctx)
}

// ---- DTOs ------------------------------------------------------------------
//
// Plain, JSON-tagged structs so Wails generates clean TypeScript types and
// times cross the bridge as ISO strings. They are display projections of
// the engine types, never carriers of secrets.

type StatusInfo struct {
	Ready       bool   `json:"ready"`       // identity exists and engine loaded
	NeedsSetup  bool   `json:"needsSetup"`  // no identity yet -> first-run screen
	Handle      string `json:"handle"`      // this peer's handle
	Fingerprint string `json:"fingerprint"` // this peer's identity fingerprint
	Home        string `json:"home"`        // state directory in use
	Server      string `json:"server"`      // coordination server URL ("" = none)
	Error       string `json:"error"`       // load error, if any
}

type ConversationInfo struct {
	Name      string   `json:"name"`
	ID        string   `json:"id"`
	Dir       string   `json:"dir"`   // "" for a relay-backed conversation
	Relay     bool     `json:"relay"` // true when there is no shared folder
	Creator   string   `json:"creator"`
	Members   []string `json:"members"`
	Others    []string `json:"others"` // members excluding self, for the recipient picker
	Count     int      `json:"count"`  // messages this peer can read
	LastAt    string   `json:"lastAt"` // ISO time of last activity ("" if none)
	LastFrom  string   `json:"lastFrom"`
	ReadError string   `json:"readError"` // set when the conversation could not be read
}

type MessageInfo struct {
	ObjectID string   `json:"objectId"`
	From     string   `json:"from"`
	Body     string   `json:"body"`
	SentAt   string   `json:"sentAt"` // ISO
	Mine     bool     `json:"mine"`
	Audience []string `json:"audience"` // only known for this peer's own separate sends
	Owned    bool     `json:"owned"`    // this peer can revoke/hide it
	Mode     string   `json:"mode"`     // "group" | "separate" | "" (not owned)
}

type SendOutcome struct {
	ObjectID string   `json:"objectId"`
	Mode     string   `json:"mode"`     // "group" or "separate"
	Audience []string `json:"audience"` // handles that can read it (excluding sender)
	Note     string   `json:"note"`     // honest-limitation / audience-model notice for the UI
}

type PinNotice struct {
	Handle      string `json:"handle"`
	Fingerprint string `json:"fingerprint"`
}

type HiddenInfo struct {
	ObjectID string `json:"objectId"`
	Preview  string `json:"preview"`
}

// ---- lifecycle -------------------------------------------------------------

// Status reports whether the app is ready, needs first-run setup, or failed
// to load. The frontend polls this on mount to decide which screen to show.
func (a *App) Status() StatusInfo {
	a.mu.Lock()
	env := a.env
	a.mu.Unlock()

	if env != nil {
		pub := env.ID.Public()
		return StatusInfo{
			Ready:       true,
			Handle:      pub.Handle,
			Fingerprint: pub.Fingerprint(),
			Home:        env.St.Home,
			Server:      env.Cfg.Server,
		}
	}
	ok, home, err := chat.HasIdentity()
	s := StatusInfo{Home: home}
	if err != nil {
		s.Error = err.Error()
		return s
	}
	if !ok {
		s.NeedsSetup = true
		return s
	}
	// Identity exists but Load failed — try once more to surface the error.
	if _, err := chat.Load(); err != nil {
		s.Error = err.Error()
	}
	return s
}

// Setup runs first-run initialisation: create this peer's identity and
// register it with the coordination server. server may be "" for no server.
func (a *App) Setup(handle, server string) (StatusInfo, error) {
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return StatusInfo{}, fmt.Errorf("handle is required")
	}
	pub, err := chat.Init(handle, server)
	// A non-nil err with a set handle means the identity was created but
	// registration failed — recoverable, so we still load and report it.
	regWarn := ""
	if err != nil {
		if pub.Handle == "" {
			return StatusInfo{}, err
		}
		regWarn = err.Error()
	}
	env, lerr := chat.Load()
	if lerr != nil {
		return StatusInfo{}, lerr
	}
	a.mu.Lock()
	a.env = env
	a.mu.Unlock()

	s := a.Status()
	if regWarn != "" {
		s.Error = regWarn // shown as a soft warning by the UI
	}
	return s, nil
}

// ---- conversations ---------------------------------------------------------

// Conversations returns every known conversation, most-recent activity
// first, matching how the Bubble Tea list orders them.
func (a *App) Conversations() ([]ConversationInfo, error) {
	env, err := a.engine()
	if err != nil {
		return nil, err
	}
	sums, err := env.Summaries()
	if err != nil {
		return nil, err
	}
	self := env.Handle()
	out := make([]ConversationInfo, 0, len(sums))
	for _, s := range sums {
		c := s.Conversation
		others := make([]string, 0, len(c.Members))
		for _, m := range c.Members {
			if m != self {
				others = append(others, m)
			}
		}
		sort.Strings(others)
		info := ConversationInfo{
			Name:     c.Name,
			ID:       c.ID,
			Dir:      c.Dir,
			Relay:    c.Dir == "",
			Creator:  c.Creator,
			Members:  c.Members,
			Others:   others,
			Count:    s.Count,
			LastFrom: s.LastFrom,
		}
		if !s.Last.IsZero() {
			info.LastAt = s.Last.Format(time.RFC3339)
		}
		if s.Err != nil {
			info.ReadError = s.Err.Error()
		}
		out = append(out, info)
	}
	return out, nil
}

// Messages returns the readable history of a conversation, oldest first,
// annotating which messages this peer owns (and can therefore revoke/hide).
func (a *App) Messages(convName string) ([]MessageInfo, error) {
	env, err := a.engine()
	if err != nil {
		return nil, err
	}
	conv, err := env.Conversation(convName)
	if err != nil {
		return nil, err
	}
	msgs, err := env.Messages(conv)
	if err != nil {
		return nil, err
	}
	out := make([]MessageInfo, 0, len(msgs))
	for _, m := range msgs {
		mi := MessageInfo{
			ObjectID: m.ObjectID,
			From:     m.From,
			Body:     m.Body,
			SentAt:   m.SentAt.Format(time.RFC3339),
			Mine:     m.Mine,
			Audience: m.Audience,
		}
		if o, ok, _ := env.Owned(m.ObjectID); ok {
			mi.Owned = true
			mi.Mode = o.Mode
		}
		out = append(out, mi)
	}
	return out, nil
}

// NewConversation creates a conversation. dir may be "" to relay through the
// server (no shared folder needed). with is the comma-or-slice list of peer
// handles to include.
func (a *App) NewConversation(name, dir string, with []string) (ConversationInfo, error) {
	env, err := a.engine()
	if err != nil {
		return ConversationInfo{}, err
	}
	conv, err := env.NewConversation(name, dir, cleanHandles(with), a.onPin)
	if err != nil {
		return ConversationInfo{}, err
	}
	a.changed()
	return a.oneConv(conv), nil
}

// JoinByInvite joins a relay-backed conversation from a pasted invite code.
func (a *App) JoinByInvite(name, code string) (ConversationInfo, error) {
	env, err := a.engine()
	if err != nil {
		return ConversationInfo{}, err
	}
	conv, err := env.JoinInvite(name, strings.TrimSpace(code), a.onPin)
	if err != nil {
		return ConversationInfo{}, err
	}
	a.changed()
	return a.oneConv(conv), nil
}

// JoinByFolder joins a folder-backed conversation from its shared directory.
func (a *App) JoinByFolder(name, dir string) (ConversationInfo, error) {
	env, err := a.engine()
	if err != nil {
		return ConversationInfo{}, err
	}
	conv, err := env.JoinConversation(name, dir, a.onPin)
	if err != nil {
		return ConversationInfo{}, err
	}
	a.changed()
	return a.oneConv(conv), nil
}

// Invite returns the invite code for a relay-backed conversation, to hand to
// the other members. The code carries the roster but never a key.
func (a *App) Invite(convName string) (string, error) {
	env, err := a.engine()
	if err != nil {
		return "", err
	}
	return env.Invite(convName)
}

// ---- send ------------------------------------------------------------------

// Send delivers a message. recipients selects the audience:
//   - empty: the whole roster, under the shared group key (one slot).
//   - a subset: per-recipient keys, so excluded members get no slot at all
//     (cryptographic exclusion) and any recipient can later be hard-revoked.
//
// forceSeparate forces per-recipient keys even for a whole-roster send.
func (a *App) Send(convName, body string, recipients []string, forceSeparate bool) (SendOutcome, error) {
	env, err := a.engine()
	if err != nil {
		return SendOutcome{}, err
	}
	if strings.TrimSpace(body) == "" {
		return SendOutcome{}, fmt.Errorf("message is empty")
	}
	res, err := env.Send(convName, body, cleanHandles(recipients), forceSeparate)
	if err != nil {
		return SendOutcome{}, err
	}
	a.changed()
	out := SendOutcome{ObjectID: res.ObjectID, Mode: res.Mode, Audience: res.Audience}
	// Name the audience model in force — the CLI and TUI both do this, and
	// CLAUDE.md requires the UI to keep doing so.
	if res.Mode == "group" {
		out.Note = "Sent to the whole roster under the shared group key. Revoking one member needs a group-key rotation (roadmap) — or hide it from everyone."
	} else {
		out.Note = "Sent with per-recipient keys. Excluded members got no slot, and any recipient can be hard-revoked without re-granting the rest."
	}
	return out, nil
}

// Unpin forgets a pinned peer so the next contact re-pins their current
// identity from the server. This is the recovery when someone re-created
// their identity: TOFU refuses their changed keys until the stale pin is
// dropped, which otherwise leaves them unable to be added to conversations
// (the "no member key sealed to your identity" failure).
func (a *App) Unpin(handle string) (string, error) {
	env, err := a.engine()
	if err != nil {
		return "", err
	}
	fp, ok, err := env.Unpin(handle)
	if err != nil {
		return "", err
	}
	if !ok {
		return fmt.Sprintf("%q was not pinned — nothing to do.", handle), nil
	}
	a.changed()
	return fmt.Sprintf("Forgot %s (was fingerprint %s). Next contact will re-pin from the server — "+
		"verify their new fingerprint out of band before trusting it.", handle, fp), nil
}

// ---- revocation ------------------------------------------------------------

// RevokeFrom hard-revokes one recipient of a per-recipient (separate) send.
func (a *App) RevokeFrom(convName, objectID, handle string) (string, error) {
	env, err := a.engine()
	if err != nil {
		return "", err
	}
	layers, slots, err := env.RevokeFrom(convName, objectID, handle)
	if err != nil {
		return "", err
	}
	a.changed()
	return fmt.Sprintf("Revoked %s: re-wrapped in a new layer (%d layers, %d slots). "+
		"No one else was re-granted. Note: revocation cannot un-share — anyone who already read it may have kept a copy.",
		handle, layers, slots), nil
}

// Hide wraps an object with zero key slots: invisible to everyone, all
// grants inert. Reversible with Unhide.
func (a *App) Hide(convName, objectID string) (string, error) {
	env, err := a.engine()
	if err != nil {
		return "", err
	}
	if err := env.Hide(convName, objectID); err != nil {
		return "", err
	}
	a.changed()
	return "Hidden from everyone (wrapped with zero slots). Unhide peels the layer and every grant works again.", nil
}

// Unhide peels the hide layer from an object, restoring the prior audience.
func (a *App) Unhide(convName, objectID string) (string, error) {
	env, err := a.engine()
	if err != nil {
		return "", err
	}
	if err := env.Unhide(convName, objectID); err != nil {
		return "", err
	}
	a.changed()
	return "Unhidden. Every original grant is valid again — nothing was re-granted.", nil
}

// RevokeAll permanently deletes an object and all its grants.
func (a *App) RevokeAll(convName, objectID string) (string, error) {
	env, err := a.engine()
	if err != nil {
		return "", err
	}
	if err := env.RevokeAll(convName, objectID); err != nil {
		return "", err
	}
	a.changed()
	return "Permanently deleted the object and all grants. This cannot be undone, and cannot un-share what was already read.", nil
}

// Hidden lists the objects this peer has hidden in a conversation (invisible
// in the normal history by design), with a preview only the owner can read.
func (a *App) Hidden(convName string) ([]HiddenInfo, error) {
	env, err := a.engine()
	if err != nil {
		return nil, err
	}
	conv, err := env.Conversation(convName)
	if err != nil {
		return nil, err
	}
	hs, err := env.HiddenObjects(conv)
	if err != nil {
		return nil, err
	}
	out := make([]HiddenInfo, 0, len(hs))
	for _, h := range hs {
		out = append(out, HiddenInfo{ObjectID: h.ObjectID, Preview: h.Preview})
	}
	return out, nil
}

// DrainPins returns and clears the TOFU first-contact notices seen since the
// last call, so the UI can prompt for out-of-band fingerprint verification.
func (a *App) DrainPins() []PinNotice {
	a.pinsMu.Lock()
	defer a.pinsMu.Unlock()
	out := a.pins
	a.pins = nil
	return out
}

// ---- helpers ---------------------------------------------------------------

// reannounce re-posts this peer's public identity to the coordination
// server so peers can resolve its handle. Idempotent (the server upserts an
// identical identity), best-effort, and a no-op when no server is
// configured. Failures are surfaced via a toast event, never fatal.
func (a *App) reannounce(env *chat.Env) {
	if env == nil || env.Cl == nil {
		return
	}
	if err := env.Cl.Register(env.ID.Public()); err != nil {
		if a.ctx != nil {
			wailsruntime.EventsEmit(a.ctx, "pipl:notice", map[string]string{
				"kind": "warn",
				"text": "Could not re-announce your identity to " + env.Cfg.Server +
					": " + err.Error() + ". Peers may not be able to find you until the server is reachable.",
			})
		}
	}
}

// Reannounce lets the UI re-register this peer on demand — e.g. after
// starting or restarting the server. Returns a human-readable result.
func (a *App) Reannounce() (string, error) {
	env, err := a.engine()
	if err != nil {
		return "", err
	}
	if env.Cl == nil {
		return "", fmt.Errorf("no coordination server is configured for this peer")
	}
	if err := env.Cl.Register(env.ID.Public()); err != nil {
		return "", fmt.Errorf("re-announce to %s failed: %w", env.Cfg.Server, err)
	}
	return "Re-announced " + env.Handle() + " to " + env.Cfg.Server + ".", nil
}

func (a *App) engine() (*chat.Env, error) {
	a.mu.Lock()
	env := a.env
	a.mu.Unlock()
	if env == nil {
		return nil, fmt.Errorf("no identity yet — complete first-run setup")
	}
	return env, nil
}

func (a *App) onPin(pub identity.PublicIdentity) {
	a.pinsMu.Lock()
	a.pins = append(a.pins, PinNotice{Handle: pub.Handle, Fingerprint: pub.Fingerprint()})
	a.pinsMu.Unlock()
	if a.ctx != nil {
		wailsruntime.EventsEmit(a.ctx, "pipl:pin", PinNotice{Handle: pub.Handle, Fingerprint: pub.Fingerprint()})
	}
}

func (a *App) oneConv(c state.Conversation) ConversationInfo {
	self := ""
	if env, err := a.engine(); err == nil {
		self = env.Handle()
	}
	others := make([]string, 0, len(c.Members))
	for _, m := range c.Members {
		if m != self {
			others = append(others, m)
		}
	}
	sort.Strings(others)
	return ConversationInfo{
		Name:    c.Name,
		ID:      c.ID,
		Dir:     c.Dir,
		Relay:   c.Dir == "",
		Creator: c.Creator,
		Members: c.Members,
		Others:  others,
	}
}

// changed tells the frontend to refetch, then also drains any pins so the
// UI can prompt for verification promptly after a first-contact operation.
func (a *App) changed() {
	if a.ctx != nil {
		wailsruntime.EventsEmit(a.ctx, "pipl:changed")
	}
}

// watch polls for server notifications where possible and emits a change
// event so live updates arrive without the user refreshing. It is
// intentionally coarse: the engine's Messages call is the source of truth,
// and this only decides when the frontend should call it again.
func (a *App) watch(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if a.ctx != nil && a.env != nil {
				wailsruntime.EventsEmit(a.ctx, "pipl:tick")
			}
		}
	}
}

func cleanHandles(in []string) []string {
	out := make([]string, 0, len(in))
	for _, h := range in {
		h = strings.TrimSpace(h)
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}
