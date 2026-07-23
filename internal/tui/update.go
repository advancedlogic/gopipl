package tui

import (
	"fmt"
	"strings"

	"github.com/antonio/pipl/internal/chat"
	"github.com/antonio/pipl/internal/state"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		return m, nil

	case statusMsg:
		m.status, m.statusErr = msg.text, msg.isErr
		return m, nil

	case msgsLoaded:
		if msg.err != nil {
			m.setError(msg.err)
			return m, nil
		}
		if msg.convID != m.conv.ID {
			return m, nil // a stale load for a conversation we left
		}
		m.msgs = msg.msgs
		if m.msgIdx >= len(m.msgs) {
			m.msgIdx = max(0, len(m.msgs)-1)
		}
		m.renderHistory()
		return m, nil

	case summariesLoaded:
		if msg.err != nil {
			m.setError(msg.err)
			return m, nil
		}
		if m.summaries == nil {
			m.summaries = map[string]chat.Summary{}
		}
		// Reorder the list to match: most recent activity first, so the
		// conversation being used is the one under the cursor.
		keep := ""
		if m.convIdx < len(m.convs) {
			keep = m.convs[m.convIdx].ID
		}
		m.convs = m.convs[:0]
		for _, s := range msg.summaries {
			m.summaries[s.Conversation.ID] = s
			m.convs = append(m.convs, s.Conversation)
		}
		for i, c := range m.convs {
			if c.ID == keep {
				m.convIdx = i
			}
		}
		if m.convIdx >= len(m.convs) {
			m.convIdx = max(0, len(m.convs)-1)
		}
		return m, nil

	case folderChanged:
		var cmds []tea.Cmd
		cmds = append(cmds, waitForPush) // keep listening
		if msg.convID == m.conv.ID {
			cmds = append(cmds, m.loadMessages())
		}
		return m, tea.Batch(cmds...)

	case tickMsg:
		// The conversation list refreshes too, so activity elsewhere shows
		// up without having to open each conversation to find it.
		if m.screen == screenConversations {
			return m, tea.Batch(pollTick(), m.loadSummaries())
		}
		if m.screen != screenChat {
			return m, nil
		}
		return m, tea.Batch(pollTick(), m.loadMessages())

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	// Route anything else to the focused text input.
	return m.routeToInput(msg)
}

func (m Model) routeToInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch m.screen {
	case screenChat:
		if m.focus == focusInput {
			m.input, cmd = m.input.Update(msg)
		}
	case screenSetup, screenNewConv, screenJoinConv:
		if m.formIdx < len(m.form) {
			m.form[m.formIdx], cmd = m.form[m.formIdx].Update(msg)
		}
	}
	return m, cmd
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// ctrl+c always quits, whatever has focus.
	if msg.Type == tea.KeyCtrlC {
		if m.cancelFollow != nil {
			m.cancelFollow()
		}
		return m, tea.Quit
	}
	switch m.screen {
	case screenSetup:
		return m.keySetup(msg)
	case screenConversations:
		return m.keyConversations(msg)
	case screenNewConv:
		return m.keyNewConv(msg)
	case screenJoinConv:
		return m.keyJoinConv(msg)
	case screenChat:
		return m.keyChat(msg)
	}
	return m, nil
}

// ---- setup -----------------------------------------------------------------

func (m Model) keySetup(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		handle := strings.TrimSpace(m.form[0].Value())
		if handle == "" {
			m.setStatus("a handle is required")
			return m, nil
		}
		server := defaultServer
		if len(m.form) > 1 {
			if s := strings.TrimSpace(m.form[1].Value()); s != "" {
				server = s
			}
		}
		pub, err := chat.Init(handle, server)
		if err != nil {
			// Registration failure is not fatal: the identity exists.
			m.setError(err)
			if pub.Handle == "" {
				return m, nil
			}
		}
		env, err := chat.Load()
		if err != nil {
			m.setError(err)
			return m, nil
		}
		m.env = env
		m.screen = screenConversations
		if err := m.reloadConvs(); err != nil {
			m.setError(err)
			return m, nil
		}
		m.notice = fmt.Sprintf("identity %s (fingerprint %s) — peers should verify this out of band",
			pub.Handle, pub.Fingerprint())
		return m, nil
	case tea.KeyTab, tea.KeyShiftTab:
		if len(m.form) > 1 {
			m.form[m.formIdx].Blur()
			m.formIdx = (m.formIdx + 1) % len(m.form)
			m.form[m.formIdx].Focus()
		}
		return m, nil
	}
	var cmd tea.Cmd
	m.form[m.formIdx], cmd = m.form[m.formIdx].Update(msg)
	return m, cmd
}

// ---- conversation list -----------------------------------------------------

func (m Model) keyConversations(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		if m.showInvite { // close the invite overlay first
			m.showInvite = false
			m.status = ""
			return m, nil
		}
		if m.cancelFollow != nil {
			m.cancelFollow()
		}
		return m, tea.Quit
	case "up", "k":
		if m.convIdx > 0 {
			m.convIdx--
		}
		return m, nil
	case "down", "j":
		if m.convIdx < len(m.convs)-1 {
			m.convIdx++
		}
		return m, nil
	case "i":
		if m.showInvite { // toggle off
			m.showInvite = false
			m.status = ""
			return m, nil
		}
		if m.convIdx >= len(m.convs) {
			m.setStatus("no conversation selected")
			return m, nil
		}
		code, err := m.env.Invite(m.convs[m.convIdx].Name)
		if err != nil {
			m.setError(err)
			return m, nil
		}
		m.invite = code
		m.showInvite = true
		m.setStatus("invite for %q — copy it to whoever should join (i or esc to close)",
			m.convs[m.convIdx].Name)
		return m, nil
	case "n":
		m.screen = screenNewConv
		m.form = []textinput.Model{
			newInput("conversation name (local label)", 40),
			newInput("shared folder — leave empty to use the server relay", 256),
		}
		m.formIdx = 0
		m.form[0].Focus()
		m.picked = map[string]bool{}
		m.pickIdx = 0
		m.loadDirectory()
		m.setStatus("name it, then tab to pick members (folder optional)")
		return m, nil
	case "J":
		m.screen = screenJoinConv
		m.form = []textinput.Model{
			newInput("conversation name (local label)", 40),
			newInput("invite code (pipl1:...) — or a shared folder path", 4096),
		}
		m.formIdx = 0
		m.form[0].Focus()
		m.setStatus("paste the invite code a peer sent you")
		return m, nil
	case "enter":
		if len(m.convs) == 0 {
			m.setStatus("no conversations yet — press n to create one")
			return m, nil
		}
		return m.openConversation(m.convIdx)
	}
	return m, nil
}

func (m Model) openConversation(idx int) (tea.Model, tea.Cmd) {
	m.conv = m.convs[idx]
	m.activeIdx = idx
	m.screen = screenChat
	m.input = newInput("message", 2000)
	m.input.Focus()
	m.focus = focusInput
	m.msgIdx = 0
	m.selectAll()
	m.layout()
	m.setStatus("everyone selected — group key (one slot, one grant)")
	return m, tea.Batch(m.loadMessages(), m.follow(m.conv), textinput.Blink)
}

// loadDirectory collects handles this peer already knows: pinned peers
// plus everyone in existing conversations. The picker offers these, and
// free text handles anyone else.
func (m *Model) loadDirectory() {
	set := map[string]bool{}
	if peers, err := m.env.St.Peers(); err == nil {
		for h := range peers {
			set[h] = true
		}
	}
	for _, c := range m.convs {
		for _, h := range c.Members {
			set[h] = true
		}
	}
	delete(set, m.env.Handle())
	m.directory = m.directory[:0]
	for h := range set {
		m.directory = append(m.directory, h)
	}
	sortStrings(m.directory)
}

// ---- new conversation ------------------------------------------------------

func (m Model) keyNewConv(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// formIdx == len(form) means focus is on the member picker.
	onPicker := m.formIdx == len(m.form)

	switch msg.Type {
	case tea.KeyEsc:
		m.screen = screenConversations
		m.status = ""
		return m, nil
	case tea.KeyTab:
		if m.formIdx < len(m.form) {
			m.form[m.formIdx].Blur()
		}
		m.formIdx++
		if m.formIdx > len(m.form) {
			m.formIdx = 0
		}
		if m.formIdx < len(m.form) {
			m.form[m.formIdx].Focus()
		}
		return m, nil
	case tea.KeyShiftTab:
		if m.formIdx < len(m.form) {
			m.form[m.formIdx].Blur()
		}
		m.formIdx--
		if m.formIdx < 0 {
			m.formIdx = len(m.form)
		}
		if m.formIdx < len(m.form) {
			m.form[m.formIdx].Focus()
		}
		return m, nil
	}

	if onPicker {
		switch msg.String() {
		case "up", "k":
			if m.pickIdx > 0 {
				m.pickIdx--
			}
			return m, nil
		case "down", "j":
			if m.pickIdx < len(m.directory)-1 {
				m.pickIdx++
			}
			return m, nil
		case " ":
			if m.pickIdx < len(m.directory) {
				h := m.directory[m.pickIdx]
				m.picked[h] = !m.picked[h]
			}
			return m, nil
		case "enter":
			return m.createConversation()
		}
		return m, nil
	}

	if msg.Type == tea.KeyEnter {
		return m.createConversation()
	}
	var cmd tea.Cmd
	m.form[m.formIdx], cmd = m.form[m.formIdx].Update(msg)
	return m, cmd
}

func (m Model) createConversation() (tea.Model, tea.Cmd) {
	name := strings.TrimSpace(m.form[0].Value())
	dir := strings.TrimSpace(m.form[1].Value())
	if name == "" {
		m.setStatus("a name is required")
		return m, nil
	}
	if dir == "" && m.env.Cl == nil {
		m.setStatus("no server configured, so a shared folder is required")
		return m, nil
	}
	var with []string
	for _, h := range m.directory {
		if m.picked[h] {
			with = append(with, h)
		}
	}
	// Allow handles not yet known locally, typed as "a,b" in the name of
	// convenience? No — the picker is the contract. Require at least one.
	if len(with) == 0 {
		m.setStatus("pick at least one member (tab to the list, space to toggle)")
		return m, nil
	}
	conv, err := m.env.NewConversation(name, dir, with, m.onPin)
	if err != nil {
		m.setError(err)
		return m, nil
	}
	if err := m.reloadConvs(); err != nil {
		m.setError(err)
		return m, nil
	}
	// Surface the invite immediately: for a relay conversation it is the
	// ONLY way the others can join, so burying it would strand them.
	if code, err := m.env.Invite(conv.Name); err == nil {
		m.invite = code
		m.notice = "send this invite to the others — press i to see it again"
	}
	for i, c := range m.convs {
		if c.ID == conv.ID {
			m.screen = screenChat
			return m.openConversation(i)
		}
	}
	m.screen = screenConversations
	return m, nil
}

// ---- join conversation -----------------------------------------------------

func (m Model) keyJoinConv(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.screen = screenConversations
		m.status = ""
		return m, nil
	case tea.KeyTab, tea.KeyShiftTab:
		m.form[m.formIdx].Blur()
		m.formIdx = (m.formIdx + 1) % len(m.form)
		m.form[m.formIdx].Focus()
		return m, nil
	case tea.KeyEnter:
		name := strings.TrimSpace(m.form[0].Value())
		where := strings.TrimSpace(m.form[1].Value())
		if name == "" || where == "" {
			m.setStatus("a name and either an invite code or a folder are required")
			return m, nil
		}
		// An invite code is self-identifying, so no mode switch is needed.
		var conv state.Conversation
		var err error
		if strings.HasPrefix(where, "pipl1:") {
			conv, err = m.env.JoinInvite(name, where, m.onPin)
		} else {
			conv, err = m.env.JoinConversation(name, where, m.onPin)
		}
		if err != nil {
			m.setError(err)
			return m, nil
		}
		if err := m.reloadConvs(); err != nil {
			m.setError(err)
			return m, nil
		}
		for i, c := range m.convs {
			if c.ID == conv.ID {
				return m.openConversation(i)
			}
		}
		m.screen = screenConversations
		return m, nil
	}
	var cmd tea.Cmd
	m.form[m.formIdx], cmd = m.form[m.formIdx].Update(msg)
	return m, cmd
}

// ---- chat ------------------------------------------------------------------

func (m Model) keyChat(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// A pending destructive action swallows every key until answered.
	if m.confirmWhat != nil {
		switch msg.String() {
		case "y", "Y":
			act := m.confirmWhat
			m.confirm, m.confirmWhat = "", nil
			return act(m)
		default:
			m.confirm, m.confirmWhat = "", nil
			m.setStatus("cancelled")
			return m, nil
		}
	}
	// The hidden-message picker likewise takes priority.
	if m.showHidden {
		return m.keyHidden(msg)
	}

	switch msg.Type {
	case tea.KeyEsc:
		if m.showInvite { // esc closes the invite overlay first
			m.showInvite = false
			return m, nil
		}
		if m.cancelFollow != nil {
			m.cancelFollow()
			m.cancelFollow = nil
		}
		m.screen = screenConversations
		m.status = ""
		if err := m.reloadConvs(); err != nil {
			m.setError(err)
		}
		return m, tea.Batch(m.loadSummaries(), pollTick())

	case tea.KeyTab:
		// input -> recipients -> history -> input
		m.focus = (m.focus + 1) % 3
		if m.focus == focusInput {
			m.input.Focus()
		} else {
			m.input.Blur()
		}
		return m, nil

	case tea.KeyEnter:
		if m.focus == focusInput {
			return m.send()
		}
		return m, nil
	}

	switch m.focus {
	case focusRecipients:
		return m.keyRecipients(msg)
	case focusHistory:
		return m.keyHistory(msg)
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m Model) keyRecipients(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	others := m.others()
	switch msg.String() {
	case "up", "k":
		if m.recipIdx > 0 {
			m.recipIdx--
		}
	case "down", "j":
		if m.recipIdx < len(others)-1 {
			m.recipIdx++
		}
	case " ":
		if m.recipIdx < len(others) {
			h := others[m.recipIdx]
			m.recipients[h] = !m.recipients[h]
			m.describeAudience()
		}
	case "a":
		m.selectAll()
		m.describeAudience()
	case "p":
		// Force per-recipient keys even when sending to everyone, so the
		// message stays individually revocable later (CLI: -separate).
		m.separate = !m.separate
		m.describeAudience()
	case "i":
		return m.toggleInvite()
	}
	return m, nil
}

// describeAudience keeps the user honest about which crypto path a send
// will take — the whole point of exposing the choice.
func (m *Model) describeAudience() {
	sel := m.selectedRecipients()
	switch {
	case m.everyoneSelected() && m.separate:
		m.setStatus("everyone, per-recipient keys — costs a grant each, but any one is revocable alone")
	case m.everyoneSelected():
		m.setStatus("everyone selected — group key (one slot, one grant, any group size)")
	case m.noneSelected():
		m.setStatus("no recipients selected — nothing to send")
	default:
		m.setStatus("subset (%s) — per-recipient keys: others get no slot, each is revocable alone",
			strings.Join(sel, ", "))
	}
}

func (m Model) keyHistory(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.msgIdx > 0 {
			m.msgIdx--
			m.renderHistory()
		}
	case "down", "j":
		if m.msgIdx < len(m.msgs)-1 {
			m.msgIdx++
			m.renderHistory()
		}
	case "h":
		return m.hideSelected()
	case "u":
		return m.openHidden()
	case "r":
		return m.revokeSelected()
	case "s":
		return m.softRevokeSelected()
	case "d":
		return m.deleteSelected()
	case "i":
		return m.toggleInvite()
	}
	return m, nil
}

// toggleInvite shows the code others need to join this conversation.
// Bound outside the message input, where "i" is just a letter.
func (m Model) toggleInvite() (tea.Model, tea.Cmd) {
	if m.showInvite {
		m.showInvite = false
		return m, nil
	}
	code, err := m.env.Invite(m.conv.Name)
	if err != nil {
		m.setError(err)
		return m, nil
	}
	m.invite = code
	m.showInvite = true
	m.setStatus("invite code — copy it to whoever should join (esc or i to close)")
	return m, nil
}

func (m Model) send() (tea.Model, tea.Cmd) {
	body := strings.TrimSpace(m.input.Value())
	if body == "" {
		return m, nil
	}
	if m.noneSelected() {
		m.setStatus("no recipients selected — pick at least one (tab to recipients, space to toggle)")
		return m, nil
	}
	sel := m.selectedRecipients()
	res, err := m.env.Send(m.conv.Name, body, sel, m.separate)
	if err != nil {
		m.setError(err)
		return m, nil
	}
	m.input.SetValue("")
	if res.Mode == "group" {
		m.setStatus("sent %s to the group (one shared key)", short(res.ObjectID))
	} else {
		m.setStatus("sent %s to %s with per-recipient keys — each revocable alone",
			short(res.ObjectID), strings.Join(res.Audience, ", "))
	}
	// Re-read our own conversation record: LastObject advanced.
	if c, err := m.env.Conversation(m.conv.Name); err == nil {
		m.conv = c
	}
	return m, m.loadMessages()
}

func (m Model) selectedMessage() (chat.Message, bool) {
	if m.msgIdx < 0 || m.msgIdx >= len(m.msgs) {
		return chat.Message{}, false
	}
	return m.msgs[m.msgIdx], true
}

func (m Model) hideSelected() (tea.Model, tea.Cmd) {
	sel, ok := m.selectedMessage()
	if !ok {
		return m, nil
	}
	if err := m.env.Hide(m.conv.Name, sel.ObjectID); err != nil {
		m.setError(err)
		return m, nil
	}
	m.setStatus("hidden %s — wrapped with zero key slots; press u to restore", short(sel.ObjectID))
	m.notice = "hide is reversible, but anyone who already read it may have kept a copy — revocation cannot un-share."
	return m, m.loadMessages()
}

// openHidden shows the hidden-message picker. Hidden objects decrypt for
// nobody, so they cannot appear in the history — but the owner kept every
// layer key, so it can still preview its own.
func (m Model) openHidden() (tea.Model, tea.Cmd) {
	list, err := m.env.HiddenObjects(m.conv)
	if err != nil {
		m.setError(err)
		return m, nil
	}
	if len(list) == 0 {
		m.setStatus("nothing hidden in this conversation")
		return m, nil
	}
	m.hidden = list
	m.hiddenIdx = 0
	m.showHidden = true
	m.setStatus("pick a hidden message to restore")
	return m, nil
}

func (m Model) keyHidden(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q", "u":
		m.showHidden = false
		m.status = ""
		return m, nil
	case "up", "k":
		if m.hiddenIdx > 0 {
			m.hiddenIdx--
		}
		return m, nil
	case "down", "j":
		if m.hiddenIdx < len(m.hidden)-1 {
			m.hiddenIdx++
		}
		return m, nil
	case "enter":
		if m.hiddenIdx >= len(m.hidden) {
			return m, nil
		}
		target := m.hidden[m.hiddenIdx].ObjectID
		if err := m.env.Unhide(m.conv.Name, target); err != nil {
			m.setError(err)
			return m, nil
		}
		m.showHidden = false
		m.setStatus("restored %s — every previous grant works again, nothing was re-granted", short(target))
		return m, m.loadMessages()
	}
	return m, nil
}

// deleteSelected is `revoke -all`: the object and every grant for it are
// destroyed. Irreversible, so it is confirmed.
func (m Model) deleteSelected() (tea.Model, tea.Cmd) {
	sel, ok := m.selectedMessage()
	if !ok {
		return m, nil
	}
	if !sel.Mine {
		m.setStatus("only the sender can delete a message")
		return m, nil
	}
	m.confirm = fmt.Sprintf("delete %s for everyone? this cannot be undone  [y/N]", short(sel.ObjectID))
	m.confirmWhat = func(m Model) (tea.Model, tea.Cmd) {
		if err := m.env.RevokeAll(m.conv.Name, sel.ObjectID); err != nil {
			m.setError(err)
			return m, nil
		}
		m.setStatus("deleted %s for everyone (object and all grants removed)", short(sel.ObjectID))
		m.notice = "anyone who already read it may have kept a copy — revocation cannot un-share."
		return m, m.loadMessages()
	}
	return m, nil
}

// softRevokeSelected is `revoke -soft`: delete one recipient's grant
// without re-keying. Deliberately labelled as the weak tier.
func (m Model) softRevokeSelected() (tea.Model, tea.Cmd) {
	sel, ok := m.selectedMessage()
	if !ok {
		return m, nil
	}
	if !sel.Mine {
		m.setStatus("only the sender can revoke a message")
		return m, nil
	}
	others := m.others()
	if m.recipIdx >= len(others) {
		m.setStatus("highlight a recipient (tab to recipients) to soft-revoke them")
		return m, nil
	}
	target := others[m.recipIdx]
	if err := m.env.RevokeSoft(m.conv.Name, sel.ObjectID, target); err != nil {
		m.setError(err)
		return m, nil
	}
	m.setStatus("soft-revoked %s from %s — grant deleted", short(sel.ObjectID), target)
	m.notice = "soft revoke is weak: a cached access key still opens the slot. Use r for a hard revoke."
	return m, m.loadMessages()
}

func (m Model) revokeSelected() (tea.Model, tea.Cmd) {
	sel, ok := m.selectedMessage()
	if !ok {
		return m, nil
	}
	if !sel.Mine {
		m.setStatus("only the sender can revoke a message")
		return m, nil
	}
	if len(sel.Audience) == 0 {
		m.setStatus("%s went to the whole group under one shared key — press h to hide it from everyone",
			short(sel.ObjectID))
		return m, nil
	}
	// Revoke the recipient currently highlighted in the recipient list, so
	// the action is unambiguous.
	others := m.others()
	if m.recipIdx >= len(others) {
		m.setStatus("highlight a recipient (tab to recipients) to revoke them")
		return m, nil
	}
	target := others[m.recipIdx]
	layers, slots, err := m.env.RevokeFrom(m.conv.Name, sel.ObjectID, target)
	if err != nil {
		m.setError(err)
		return m, nil
	}
	m.setStatus("revoked %s from %s — %d layer(s), %d slot(s); no one else was re-granted",
		short(sel.ObjectID), target, layers, slots)
	m.notice = "if they already read it, they may have kept a copy — revocation cannot un-share."
	return m, m.loadMessages()
}

func short(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

var _ = fmt.Sprintf
