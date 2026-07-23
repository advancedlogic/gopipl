package tui

import (
	"errors"
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

// Two conversations with the same members are indistinguishable in a bare
// list, which is how you end up typing into one nobody else is reading.
// The list must show activity, and put the busiest first.

func TestConversationListShowsActivity(t *testing.T) {
	m := newChatModel(t, "alice", "bob")
	// A second conversation with the SAME members, deliberately.
	if _, err := m.env.NewConversation("quiet", m.env.St.Home+string(os.PathSeparator)+"shared2",
		[]string{"bob"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.env.Send("team", "over here", nil, false); err != nil {
		t.Fatal(err)
	}

	m.screen = screenConversations
	if err := m.reloadConvs(); err != nil {
		t.Fatal(err)
	}
	sums, err := m.env.Summaries()
	if err != nil {
		t.Fatal(err)
	}
	got := drive(m, summariesLoaded{summaries: sums}).(Model)

	view := got.View()
	if !strings.Contains(view, "1 msg") {
		t.Fatalf("list does not show the message count:\n%s", view)
	}
	if !strings.Contains(view, "no messages") {
		t.Fatalf("list does not mark the empty conversation:\n%s", view)
	}
	// The one with traffic must sort first, so the cursor starts on it.
	if got.convs[0].Name != "team" {
		t.Fatalf("conversation order = %v, want the active one first",
			[]string{got.convs[0].Name, got.convs[1].Name})
	}
}

func TestConversationListReportsUnreachable(t *testing.T) {
	m := newChatModel(t, "alice", "bob")
	m.screen = screenConversations
	if err := m.reloadConvs(); err != nil {
		t.Fatal(err)
	}
	got := drive(m, summariesLoaded{summaries: []chat.Summary{{
		Conversation: m.conv,
		Err:          errors.New("relay down"),
	}}}).(Model)

	if !strings.Contains(got.View(), "unreachable") {
		t.Fatalf("a conversation that cannot be read is not flagged:\n%s", got.View())
	}
}

// The local name is per-peer, so it cannot confirm two windows are in the
// same conversation. The ID can.
func TestChatHeaderShowsConversationIdentity(t *testing.T) {
	m := newChatModel(t, "alice", "bob")
	view := m.View()

	if !strings.Contains(view, short(m.conv.ID)) {
		t.Fatalf("header omits the conversation id:\n%s", view)
	}
	// And where it lives, since that decides whether a server is needed.
	if !strings.Contains(view, "folder") {
		t.Fatalf("header does not say the conversation is folder-backed:\n%s", view)
	}
}

// Every destructive or mode-changing operation the flag CLI offers must
// be reachable from the UI too, or the two front ends have drifted.

func TestPForcesPerRecipientKeysForWholeRoster(t *testing.T) {
	m := newChatModel(t, "alice", "bob", "carol")
	if m.separate {
		t.Fatal("per-recipient mode should be off by default")
	}
	m.focus = focusRecipients
	m2 := drive(m, keyRunes("p")).(Model)

	if !m2.separate {
		t.Fatal("p did not enable per-recipient keys")
	}
	// Still everyone — but now the costly, individually revocable mode.
	if !m2.everyoneSelected() {
		t.Fatal("p should not change WHO is selected")
	}
	if !strings.Contains(m2.status, "per-recipient") {
		t.Fatalf("status does not explain the mode: %q", m2.status)
	}
	if !strings.Contains(m2.View(), "per-recipient") {
		t.Fatal("view does not show that per-recipient keys are in force")
	}
	if m3 := drive(m2, keyRunes("p")).(Model); m3.separate {
		t.Fatal("p did not toggle back off")
	}
}

func TestSendHonoursTheSeparateToggle(t *testing.T) {
	m := newChatModel(t, "alice", "bob")
	m.separate = true
	m.input.SetValue("revocable later")
	m2 := drive(m, tea.KeyMsg{Type: tea.KeyEnter}).(Model)

	if m2.input.Value() != "" {
		t.Fatalf("send did not go through: %q", m2.status)
	}
	// A separate send records per-recipient access keys; a group send
	// records none.
	owned, err := m2.env.St.Owned()
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 1 {
		t.Fatalf("expected 1 owned object, got %d", len(owned))
	}
	for _, o := range owned {
		if o.Mode != "separate" {
			t.Fatalf("mode = %q, want separate (the p toggle was ignored)", o.Mode)
		}
	}
}

// Hidden messages are invisible in the history by design, so restoring one
// must be an explicit choice rather than a guess.
func TestUnhideOffersAPickerAndRestoresTheChosenMessage(t *testing.T) {
	m := newChatModel(t, "alice", "bob")

	var ids []string
	for _, body := range []string{"first secret", "second secret"} {
		res, err := m.env.Send(m.conv.Name, body, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, res.ObjectID)
		if err := m.env.Hide(m.conv.Name, res.ObjectID); err != nil {
			t.Fatal(err)
		}
	}

	m.focus = focusHistory
	m2 := drive(m, keyRunes("u")).(Model)
	if !m2.showHidden {
		t.Fatalf("u did not open the hidden picker (status %q)", m2.status)
	}
	if len(m2.hidden) != 2 {
		t.Fatalf("picker lists %d hidden messages, want 2", len(m2.hidden))
	}
	// The owner kept every layer key, so it can preview its own hidden
	// messages even though nobody else can decrypt them.
	view := m2.View()
	for _, want := range []string{"first secret", "second secret"} {
		if !strings.Contains(view, want) {
			t.Fatalf("picker does not preview %q:\n%s", want, view)
		}
	}

	// Restore the SECOND one specifically.
	target := m2.hidden[1].ObjectID
	m3 := drive(m2, tea.KeyMsg{Type: tea.KeyDown}, tea.KeyMsg{Type: tea.KeyEnter}).(Model)
	if m3.showHidden {
		t.Fatal("picker stayed open after restoring")
	}
	owned, err := m3.env.St.Owned()
	if err != nil {
		t.Fatal(err)
	}
	if owned[target].Hidden {
		t.Fatalf("chosen message %s is still hidden", short(target))
	}
	// And only that one.
	other := ids[0]
	if target == ids[0] {
		other = ids[1]
	}
	if !owned[other].Hidden {
		t.Fatalf("unhide also restored %s, which was not chosen", short(other))
	}
}

func TestUnhideSaysSoWhenNothingIsHidden(t *testing.T) {
	m := newChatModel(t, "alice", "bob")
	m.focus = focusHistory
	m2 := drive(m, keyRunes("u")).(Model)
	if m2.showHidden {
		t.Fatal("picker opened with nothing hidden")
	}
	if !strings.Contains(m2.status, "nothing hidden") {
		t.Fatalf("status = %q", m2.status)
	}
}

// Deleting for everyone is irreversible, so it must be confirmed rather
// than fired on a single keypress.
func TestDeleteRequiresConfirmation(t *testing.T) {
	m := newChatModel(t, "alice", "bob")
	res, err := m.env.Send(m.conv.Name, "delete me", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	m2 := drive(m, msgsLoadedFor(m, t)).(Model)
	m2.focus = focusHistory

	m3 := drive(m2, keyRunes("d")).(Model)
	if m3.confirmWhat == nil {
		t.Fatal("d did not ask for confirmation")
	}
	if !strings.Contains(m3.View(), "cannot be undone") {
		t.Fatal("confirmation prompt does not warn that deletion is permanent")
	}

	// Anything other than y cancels, and the object survives.
	cancelled := drive(m3, keyRunes("n")).(Model)
	if cancelled.confirmWhat != nil {
		t.Fatal("n left the confirmation pending")
	}
	owned, _ := cancelled.env.St.Owned()
	if _, still := owned[res.ObjectID]; !still {
		t.Fatal("cancelling the prompt deleted the object anyway")
	}

	// y goes through.
	confirmed := drive(m3, keyRunes("y")).(Model)
	owned, _ = confirmed.env.St.Owned()
	if _, still := owned[res.ObjectID]; still {
		t.Fatal("confirming did not delete the object")
	}
}

func TestSoftRevokeIsReachableAndLabelledWeak(t *testing.T) {
	// Four members so that {bob, carol} is a genuine subset — with only
	// three, that IS everyone and the group key would be used instead.
	m := newChatModel(t, "alice", "bob", "carol", "dave")
	res, err := m.env.Send(m.conv.Name, "subset", []string{"bob", "carol"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "separate" {
		t.Fatalf("setup: mode = %q, want separate", res.Mode)
	}
	m2 := drive(m, msgsLoadedFor(m, t)).(Model)
	m2.focus = focusHistory
	m2.recipIdx = 0 // bob

	m3 := drive(m2, keyRunes("s")).(Model)
	if m3.statusErr {
		t.Fatalf("soft revoke failed: %q", m3.status)
	}
	if !strings.Contains(m3.status, "soft-revoked") {
		t.Fatalf("status = %q", m3.status)
	}
	// The weakness must be stated, not buried.
	if !strings.Contains(m3.notice, "weak") {
		t.Fatalf("notice does not flag soft revoke as weak: %q", m3.notice)
	}
}

// msgsLoadedFor synchronously loads the conversation's messages so a test
// can select one in the history.
func msgsLoadedFor(m Model, t *testing.T) tea.Msg {
	t.Helper()
	msgs, err := m.env.Messages(m.conv)
	if err != nil {
		t.Fatal(err)
	}
	return msgsLoaded{convID: m.conv.ID, msgs: msgs}
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
