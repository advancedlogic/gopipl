// Package tui is the Bubble Tea front end. It renders state and collects
// input; every cryptographic decision is delegated to internal/chat, which
// the flag CLI uses too.
package tui

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/antonio/pipl/internal/chat"
	"github.com/antonio/pipl/internal/identity"
	"github.com/antonio/pipl/internal/state"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

type screen int

const (
	screenSetup         screen = iota // no identity yet: pick a handle
	screenConversations               // list / create / join
	screenNewConv                     // name + folder + member picker
	screenJoinConv                    // name + folder
	screenChat                        // the conversation itself
)

// focus tracks which control has the keyboard inside a screen.
type focus int

const (
	focusInput focus = iota
	focusRecipients
	focusHistory
)

type Model struct {
	env    *chat.Env
	screen screen
	width  int
	height int

	// conversation list
	convs     []state.Conversation
	convIdx   int
	activeIdx int // -1 when no conversation is open

	// chat screen
	conv       state.Conversation
	msgs       []chat.Message
	history    viewport.Model
	input      textinput.Model
	focus      focus
	msgIdx     int // selection in history, for revoke/hide
	recipients map[string]bool
	recipIdx   int

	// forms (new / join)
	form     []textinput.Model
	formIdx  int
	pickIdx  int
	picked   map[string]bool
	dirEntry string

	// directory of known handles, for the member picker
	directory []string

	status    string
	statusErr bool
	notice    string // sticky honest-limitation notice
	// invite is the code for the open conversation, shown on demand (i).
	// For a relay-backed conversation it is the only way others can join.
	invite     string
	showInvite bool

	// live refresh
	cancelFollow context.CancelFunc
	followingID  string
}

// New builds the initial model. A missing identity is not an error: the
// UI opens on the setup screen instead.
func New() (Model, error) {
	m := Model{activeIdx: -1, recipients: map[string]bool{}, picked: map[string]bool{}}
	ok, home, err := chat.HasIdentity()
	if err != nil {
		return m, err
	}
	if !ok {
		m.screen = screenSetup
		m.form = []textinput.Model{newInput("your handle (e.g. alice)", 32)}
		m.form[0].Focus()
		m.status = "no identity in " + home + " — create one to start"
		return m, nil
	}
	env, err := chat.Load()
	if err != nil {
		return m, err
	}
	m.env = env
	m.screen = screenConversations
	if err := m.reloadConvs(); err != nil {
		return m, err
	}
	return m, nil
}

func newInput(placeholder string, limit int) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.CharLimit = limit
	ti.Prompt = "› "
	return ti
}

func (m *Model) reloadConvs() error {
	convs, err := m.env.Conversations()
	if err != nil {
		return err
	}
	m.convs = convs
	if m.convIdx >= len(convs) {
		m.convIdx = max(0, len(convs)-1)
	}
	return nil
}

// ---- messages --------------------------------------------------------------

type msgsLoaded struct {
	convID string
	msgs   []chat.Message
	err    error
}

// folderChanged is emitted by the follow loop: either a server push or a
// poll tick noticed something may have changed.
type folderChanged struct{ convID string }

type statusMsg struct {
	text  string
	isErr bool
}

type tickMsg time.Time

func (m Model) Init() tea.Cmd { return textinput.Blink }

// loadMessages re-runs the whole read path for the open conversation.
func (m Model) loadMessages() tea.Cmd {
	conv := m.conv
	env := m.env
	return func() tea.Msg {
		msgs, err := env.Messages(conv)
		return msgsLoaded{convID: conv.ID, msgs: msgs, err: err}
	}
}

// follow subscribes to server notifications for a conversation and also
// polls, so the UI stays live even with no server configured.
func (m *Model) follow(conv state.Conversation) tea.Cmd {
	if m.cancelFollow != nil {
		m.cancelFollow()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancelFollow = cancel
	m.followingID = conv.ID
	env := m.env

	sub := func() tea.Msg {
		if env.Cl == nil {
			<-ctx.Done()
			return nil
		}
		// Events blocks until the stream drops or ctx is cancelled.
		_ = env.Cl.Events(ctx, conv.ID, func() {
			select {
			case pushes <- conv.ID:
			default: // a refresh is already pending; nothing to add
			}
		})
		return nil
	}
	return tea.Batch(sub, waitForPush, pollTick())
}

// pushes carries server notifications from the SSE goroutine into the
// Bubble Tea update loop. Buffered and non-blocking: a burst of pings
// collapses into a single refresh.
var pushes = make(chan string, 1)

func waitForPush() tea.Msg { return folderChanged{convID: <-pushes} }

// pollTick drives folder rescans. Without a server this is the only
// discovery mechanism; with one it is a safety net for missed pushes.
func pollTick() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// ---- helpers ---------------------------------------------------------------

// selectedRecipients returns the handles currently toggled on.
//
// A nil result means "everyone" — the engine's signal to use the shared
// group key. Callers MUST therefore distinguish it from the empty
// selection, which means the opposite (nobody) and must never be sent:
// use everyoneSelected/noneSelected rather than testing for nil, or a
// deselect-all would silently send to the whole roster.
func (m Model) selectedRecipients() []string {
	others := m.others()
	out := make([]string, 0, len(others))
	for _, h := range others {
		if m.recipients[h] {
			out = append(out, h)
		}
	}
	if len(out) == len(others) {
		return nil // everyone: group send
	}
	return out
}

// everyoneSelected reports whether the send will use the group key.
func (m Model) everyoneSelected() bool { return m.selectedRecipients() == nil }

// noneSelected reports whether the user has excluded every recipient, in
// which case there is nothing to send.
func (m Model) noneSelected() bool {
	sel := m.selectedRecipients()
	return sel != nil && len(sel) == 0
}

// others is the roster minus this peer, sorted.
func (m Model) others() []string {
	var out []string
	for _, h := range m.conv.Members {
		if h != m.env.Handle() {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

// selectAll turns every recipient back on (the default: group send).
func (m *Model) selectAll() {
	m.recipients = map[string]bool{}
	for _, h := range m.others() {
		m.recipients[h] = true
	}
	m.recipIdx = 0
}

func (m *Model) setStatus(format string, args ...any) {
	m.status = fmt.Sprintf(format, args...)
	m.statusErr = false
}

func (m *Model) setError(err error) {
	m.status = err.Error()
	m.statusErr = true
}

// onPin surfaces first-contact TOFU pins, which the user is meant to
// verify out of band. Never silently swallowed.
func (m *Model) onPin(p identity.PublicIdentity) {
	m.notice = fmt.Sprintf("pinned %s (fingerprint %s) — verify out of band", p.Handle, p.Fingerprint())
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
