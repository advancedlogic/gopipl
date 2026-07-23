package tui

import (
	"os"
	"strings"
	"testing"

	"github.com/antonio/pipl/internal/chat"

	tea "github.com/charmbracelet/bubbletea"
)

// withHome points PIPL_HOME at a scratch dir so tests never touch the
// developer's real identity.
func withHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("PIPL_HOME", home)
	return home
}

func keyRunes(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// drive feeds a model a sequence of messages, discarding commands.
func drive(m tea.Model, msgs ...tea.Msg) tea.Model {
	for _, msg := range msgs {
		m, _ = m.Update(msg)
	}
	return m
}

func TestNewWithoutIdentityOpensSetup(t *testing.T) {
	withHome(t)
	m, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m.screen != screenSetup {
		t.Fatalf("screen = %v, want setup", m.screen)
	}
	view := m.View()
	if !strings.Contains(view, "new identity") {
		t.Fatalf("setup view does not prompt for an identity:\n%s", view)
	}
	// The setup screen must state the key-custody promise.
	if !strings.Contains(view, "never leave this machine") {
		t.Fatalf("setup view omits the key-custody note:\n%s", view)
	}
}

func TestSetupCreatesIdentityAndAdvances(t *testing.T) {
	withHome(t)
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	// Type a handle, press enter. No server: registration is skipped.
	m2 := drive(m, keyRunes("alice"), tea.KeyMsg{Type: tea.KeyEnter})
	got := m2.(Model)
	if got.screen != screenConversations {
		t.Fatalf("screen = %v, want conversations (status: %q)", got.screen, got.status)
	}
	if got.env == nil || got.env.Handle() != "alice" {
		t.Fatal("identity was not created and loaded")
	}
	// The fingerprint must be surfaced for out-of-band verification.
	if !strings.Contains(got.notice, "fingerprint") {
		t.Fatalf("notice omits the fingerprint: %q", got.notice)
	}
}

func TestSetupRejectsEmptyHandle(t *testing.T) {
	withHome(t)
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	got := drive(m, tea.KeyMsg{Type: tea.KeyEnter}).(Model)
	if got.screen != screenSetup {
		t.Fatal("empty handle advanced past setup")
	}
	if got.status == "" {
		t.Fatal("empty handle produced no feedback")
	}
}

// newChatModel builds a peer sitting in an open conversation with the
// given roster, ready for recipient-selection tests. The conversation is
// persisted with a real shared folder and group key, so send paths
// exercise the same code as production rather than a stub.
func newChatModel(t *testing.T, self string, others ...string) Model {
	t.Helper()
	home := withHome(t)
	if _, err := chat.Init(self, ""); err != nil {
		t.Fatalf("init %s: %v", self, err)
	}
	env, err := chat.Load()
	if err != nil {
		t.Fatal(err)
	}
	// The roster's other members need identities this peer has pinned,
	// because a subset send seals a grant to each of them.
	peerHomes := map[string]string{}
	for _, h := range others {
		ph := home + string(os.PathSeparator) + "peer-" + h
		peerHomes[h] = ph
		t.Setenv("PIPL_HOME", ph)
		if _, err := chat.Init(h, ""); err != nil {
			t.Fatalf("init %s: %v", h, err)
		}
		pe, err := chat.Load()
		if err != nil {
			t.Fatal(err)
		}
		pub := pe.ID.Public()
		t.Setenv("PIPL_HOME", home)
		if err := env.St.PinPeer(pub); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PIPL_HOME", home)

	conv, err := env.NewConversation("team", home+string(os.PathSeparator)+"shared", others, nil)
	if err != nil {
		t.Fatalf("NewConversation: %v", err)
	}
	m := Model{
		env:        env,
		screen:     screenChat,
		width:      100,
		height:     30,
		recipients: map[string]bool{},
		picked:     map[string]bool{},
		activeIdx:  0,
		conv:       conv,
	}
	m.input = newInput("message", 2000)
	m.selectAll()
	m.layout()
	return m
}

func TestOthersExcludesSelf(t *testing.T) {
	m := newChatModel(t, "alice", "bob", "carol")
	got := m.others()
	if len(got) != 2 || got[0] != "bob" || got[1] != "carol" {
		t.Fatalf("others() = %v, want [bob carol]", got)
	}
}

// Everyone selected must mean "group key", which the engine signals by a
// nil recipient list.
func TestSelectAllMeansGroupSend(t *testing.T) {
	m := newChatModel(t, "alice", "bob", "carol")
	if sel := m.selectedRecipients(); sel != nil {
		t.Fatalf("selectedRecipients() = %v, want nil (group send)", sel)
	}
}

func TestTogglingOneRecipientMakesItASubset(t *testing.T) {
	m := newChatModel(t, "alice", "bob", "carol")
	m.focus = focusRecipients
	// Highlight carol, toggle her off.
	m2 := drive(m, tea.KeyMsg{Type: tea.KeyDown}, keyRunes(" ")).(Model)

	sel := m2.selectedRecipients()
	if len(sel) != 1 || sel[0] != "bob" {
		t.Fatalf("selectedRecipients() = %v, want [bob]", sel)
	}
	// The status must explain that this switches crypto modes.
	if !strings.Contains(m2.status, "per-recipient") {
		t.Fatalf("status does not explain the audience model: %q", m2.status)
	}
}

func TestDeselectingEveryoneBlocksSend(t *testing.T) {
	m := newChatModel(t, "alice", "bob")
	m.focus = focusRecipients
	m2 := drive(m, keyRunes(" ")).(Model) // bob off; nobody left

	m2.input.SetValue("nobody will read this")
	m2.focus = focusInput
	m3 := drive(m2, tea.KeyMsg{Type: tea.KeyEnter}).(Model)

	if m3.input.Value() == "" {
		t.Fatal("send proceeded with no recipients (input was cleared)")
	}
	if !strings.Contains(m3.status, "no recipients") {
		t.Fatalf("status = %q, want a no-recipients warning", m3.status)
	}
}

func TestPressingAReselectsEveryone(t *testing.T) {
	m := newChatModel(t, "alice", "bob", "carol")
	m.focus = focusRecipients
	m2 := drive(m, keyRunes(" ")).(Model) // drop bob
	if m2.selectedRecipients() == nil {
		t.Fatal("expected a subset after toggling bob off")
	}
	m3 := drive(m2, keyRunes("a")).(Model)
	if m3.selectedRecipients() != nil {
		t.Fatal("'a' did not restore the full roster (group send)")
	}
}

func TestTabCyclesFocus(t *testing.T) {
	m := newChatModel(t, "alice", "bob")
	want := []focus{focusRecipients, focusHistory, focusInput}
	cur := tea.Model(m)
	for i, w := range want {
		cur = drive(cur, tea.KeyMsg{Type: tea.KeyTab})
		if got := cur.(Model).focus; got != w {
			t.Fatalf("after %d tabs focus = %v, want %v", i+1, got, w)
		}
	}
}

// The recipient panel is the security-relevant control: it must always
// show who is and is not included, and name the audience model.
func TestChatViewShowsRecipientsAndAudienceModel(t *testing.T) {
	m := newChatModel(t, "alice", "bob", "carol")

	view := m.View()
	for _, want := range []string{"recipients", "bob", "carol", "group key"} {
		if !strings.Contains(view, want) {
			t.Fatalf("chat view missing %q:\n%s", want, view)
		}
	}

	m.focus = focusRecipients
	m2 := drive(m, tea.KeyMsg{Type: tea.KeyDown}, keyRunes(" ")).(Model) // carol off
	view2 := m2.View()
	if !strings.Contains(view2, "per-recipient") {
		t.Fatalf("subset view does not announce per-recipient keys:\n%s", view2)
	}
	if !strings.Contains(view2, "[ ] carol") {
		t.Fatalf("excluded recipient not shown as unchecked:\n%s", view2)
	}
	if !strings.Contains(view2, "[x] bob") {
		t.Fatalf("included recipient not shown as checked:\n%s", view2)
	}
}

// End-to-end through the UI: two peers, a real shared folder, a subset
// send. The excluded member must not be able to read it.
func TestSubsetSendThroughUIExcludesNonRecipients(t *testing.T) {
	root := t.TempDir()
	shared := root + string(os.PathSeparator) + "shared"

	// Three identities in separate homes.
	homes := map[string]string{}
	for _, h := range []string{"alice", "bob", "carol"} {
		home := root + string(os.PathSeparator) + h
		homes[h] = home
		t.Setenv("PIPL_HOME", home)
		if _, err := chat.Init(h, ""); err != nil {
			t.Fatalf("init %s: %v", h, err)
		}
	}
	// Cross-pin: no server, so peers must know each other locally.
	pubs := map[string][]byte{}
	_ = pubs
	for _, h := range []string{"alice", "bob", "carol"} {
		t.Setenv("PIPL_HOME", homes[h])
		env, err := chat.Load()
		if err != nil {
			t.Fatal(err)
		}
		for _, other := range []string{"alice", "bob", "carol"} {
			if other == h {
				continue
			}
			t.Setenv("PIPL_HOME", homes[other])
			oe, err := chat.Load()
			if err != nil {
				t.Fatal(err)
			}
			pub := oe.ID.Public()
			t.Setenv("PIPL_HOME", homes[h])
			if err := env.St.PinPeer(pub); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Alice creates the conversation and sends to bob only.
	t.Setenv("PIPL_HOME", homes["alice"])
	alice, err := chat.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.NewConversation("team", shared, []string{"bob", "carol"}, nil); err != nil {
		t.Fatalf("NewConversation: %v", err)
	}
	if _, err := alice.Send("team", "everyone sees this", nil, false); err != nil {
		t.Fatal(err)
	}
	res, err := alice.Send("team", "bob only", []string{"bob"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "separate" {
		t.Fatalf("subset send used mode %q, want separate", res.Mode)
	}

	read := func(handle string) []string {
		t.Setenv("PIPL_HOME", homes[handle])
		env, err := chat.Load()
		if err != nil {
			t.Fatal(err)
		}
		conv, err := env.JoinConversation("team", shared, nil)
		if err != nil {
			t.Fatalf("%s join: %v", handle, err)
		}
		msgs, err := env.Messages(conv)
		if err != nil {
			t.Fatalf("%s messages: %v", handle, err)
		}
		var bodies []string
		for _, m := range msgs {
			bodies = append(bodies, m.Body)
		}
		return bodies
	}

	bobSees := strings.Join(read("bob"), "|")
	carolSees := strings.Join(read("carol"), "|")

	if !strings.Contains(bobSees, "bob only") {
		t.Fatalf("bob cannot read the message addressed to him: %q", bobSees)
	}
	if !strings.Contains(bobSees, "everyone sees this") {
		t.Fatalf("bob cannot read the group message: %q", bobSees)
	}
	if !strings.Contains(carolSees, "everyone sees this") {
		t.Fatalf("carol cannot read the group message: %q", carolSees)
	}
	if strings.Contains(carolSees, "bob only") {
		t.Fatalf("carol read a message she was excluded from: %q", carolSees)
	}
}
