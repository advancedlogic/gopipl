package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

const defaultServer = "http://127.0.0.1:8737"

var (
	colAccent = lipgloss.AdaptiveColor{Light: "#7d3ac1", Dark: "#c9a0ff"}
	colMuted  = lipgloss.AdaptiveColor{Light: "#6b6b6b", Dark: "#8a8a8a"}
	colOK     = lipgloss.AdaptiveColor{Light: "#137a4d", Dark: "#5ddba0"}
	colWarn   = lipgloss.AdaptiveColor{Light: "#a8410a", Dark: "#ffb86b"}
	colErr    = lipgloss.AdaptiveColor{Light: "#b3261e", Dark: "#ff8f87"}

	styTitle    = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	styMuted    = lipgloss.NewStyle().Foreground(colMuted)
	styOK       = lipgloss.NewStyle().Foreground(colOK)
	styWarn     = lipgloss.NewStyle().Foreground(colWarn)
	styErr      = lipgloss.NewStyle().Foreground(colErr)
	stySelected = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	styPanel    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).
			BorderForeground(colMuted).Padding(0, 1)
	styPanelHot = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).
			BorderForeground(colAccent).Padding(0, 1)
)

// layout recomputes panel sizes. Called on resize and on entering chat.
func (m *Model) layout() {
	if m.width == 0 {
		m.width = 80
	}
	if m.height == 0 {
		m.height = 24
	}
	sidebar := m.sidebarWidth()
	historyW := m.width - sidebar - 6
	if historyW < 20 {
		historyW = 20
	}
	// title + input + status + notice + borders
	historyH := m.height - 9
	if historyH < 3 {
		historyH = 3
	}
	m.history.Width = historyW
	m.history.Height = historyH
	m.input.Width = historyW - 2
	m.renderHistory()
}

func (m Model) sidebarWidth() int {
	w := 18
	for _, h := range m.conv.Members {
		if len(h)+8 > w {
			w = len(h) + 8
		}
	}
	return min(w, 30)
}

func (m Model) View() string {
	switch m.screen {
	case screenSetup:
		return m.viewSetup()
	case screenConversations:
		return m.viewConversations()
	case screenNewConv:
		return m.viewNewConv()
	case screenJoinConv:
		return m.viewJoinConv()
	case screenChat:
		return m.viewChat()
	}
	return ""
}

// inviteBox renders an invite code in a bordered panel with a note that it
// carries no key. Shared by the conversation list and the chat view so the
// reassurance is stated the same way in both.
func inviteBox(code string, width int) string {
	return styPanelHot.Width(width).Render(
		styTitle.Render("invite code") + "\n" +
			styMuted.Render("Send to whoever should join. It carries no key —\n"+
				"access still needs a member key sealed to their identity,\n"+
				"so a stolen code reads nothing.") + "\n\n" +
			code)
}

func (m Model) footer(keys string) string {
	var b strings.Builder
	b.WriteString("\n")
	if m.notice != "" {
		b.WriteString(styWarn.Render("! "+m.notice) + "\n")
	}
	if m.status != "" {
		if m.statusErr {
			b.WriteString(styErr.Render("✗ "+m.status) + "\n")
		} else {
			b.WriteString(styOK.Render("• "+m.status) + "\n")
		}
	}
	b.WriteString(styMuted.Render(keys))
	return b.String()
}

// ---- setup -----------------------------------------------------------------

func (m Model) viewSetup() string {
	var b strings.Builder
	b.WriteString(styTitle.Render("PIPL — new identity") + "\n\n")
	b.WriteString(styMuted.Render(
		"Your keys are generated here and never leave this machine.\n"+
			"The server only learns your public identity.") + "\n\n")
	b.WriteString(m.form[0].View() + "\n")
	if len(m.form) > 1 {
		b.WriteString(m.form[1].View() + "\n")
	}
	b.WriteString(m.footer("enter=create  ctrl+c=quit"))
	return b.String()
}

// ---- conversation list -----------------------------------------------------

func (m Model) viewConversations() string {
	var b strings.Builder
	// The home directory is shown because with several peers on one
	// machine the handle alone doesn't say which window you are looking at.
	b.WriteString(styTitle.Render("PIPL — "+m.env.Handle()) + "  " +
		styMuted.Render(m.env.St.Home) + "\n\n")
	if len(m.convs) == 0 {
		b.WriteString(styMuted.Render("no conversations yet\n\npress n to create one, J to join one by folder\n"))
	} else {
		// Width the name column so the activity lines up and the eye can
		// scan it — the whole point is spotting which one is live.
		nameW := 4
		for _, c := range m.convs {
			if len(c.Name) > nameW {
				nameW = len(c.Name)
			}
		}
		for i, c := range m.convs {
			s, known := m.summaries[c.ID]
			line := fmt.Sprintf("%-*s  %s", nameW, c.Name,
				styMuted.Render("("+strings.Join(c.Members, ", ")+")"))
			switch {
			case !known:
				// Activity has not loaded yet; say nothing rather than
				// imply the conversation is empty.
			case s.Err != nil:
				line += "  " + styErr.Render("unreachable")
			case s.Count == 0:
				line += "  " + styMuted.Render("no messages")
			default:
				line += fmt.Sprintf("  %s", styOK.Render(fmt.Sprintf("%d msg", s.Count)))
				line += styMuted.Render(fmt.Sprintf("  last %s from %s",
					s.Last.Local().Format("15:04"), s.LastFrom))
			}
			if i == m.convIdx {
				b.WriteString(stySelected.Render("› "+line) + "\n")
			} else {
				b.WriteString("  " + line + "\n")
			}
		}
		b.WriteString("\n" + styMuted.Render("most recent first"))
	}
	if m.showInvite {
		b.WriteString("\n" + inviteBox(m.invite, min(m.width-2, 76)) + "\n")
	}
	keys := "↑/↓=select  enter=open  i=invite  n=new  J=join  q=quit"
	if m.showInvite {
		keys = "i or esc=close invite"
	}
	b.WriteString(m.footer(keys))
	return b.String()
}

// ---- new / join ------------------------------------------------------------

func (m Model) viewNewConv() string {
	var b strings.Builder
	b.WriteString(styTitle.Render("New conversation") + "\n\n")
	b.WriteString(styMuted.Render(
		"Leave the folder empty to relay through the server: peers then\n"+
			"need nothing in common but the invite code you get back.") + "\n\n")
	labels := []string{"name", "shared folder (optional)"}
	for i := range m.form {
		mark := "  "
		if m.formIdx == i {
			mark = "› "
		}
		b.WriteString(mark + styMuted.Render(labels[i]) + "\n" + m.form[i].View() + "\n\n")
	}

	hot := m.formIdx == len(m.form)
	head := "members"
	if hot {
		head = "members  " + styMuted.Render("(space=toggle)")
	}
	b.WriteString(head + "\n")
	if len(m.directory) == 0 {
		b.WriteString(styMuted.Render("  no known peers yet — they must run pipl and register first\n"))
	}
	for i, h := range m.directory {
		box := "[ ]"
		if m.picked[h] {
			box = "[x]"
		}
		line := fmt.Sprintf("%s %s", box, h)
		if hot && i == m.pickIdx {
			b.WriteString(stySelected.Render("› "+line) + "\n")
		} else {
			b.WriteString("  " + line + "\n")
		}
	}
	b.WriteString(m.footer("tab=next field  space=toggle  enter=create  esc=back"))
	return b.String()
}

func (m Model) viewJoinConv() string {
	var b strings.Builder
	b.WriteString(styTitle.Render("Join conversation") + "\n\n")
	b.WriteString(styMuted.Render(
		"Paste an invite code, or point at a shared folder. Either way your\n"+
			"group key comes from a member-key blob sealed to your identity\n"+
			"and signed by the creator — the code itself grants nothing.") + "\n\n")
	labels := []string{"name", "invite code or folder"}
	for i := range m.form {
		mark := "  "
		if m.formIdx == i {
			mark = "› "
		}
		b.WriteString(mark + styMuted.Render(labels[i]) + "\n" + m.form[i].View() + "\n\n")
	}
	b.WriteString(m.footer("tab=next field  enter=join  esc=back"))
	return b.String()
}

// ---- chat ------------------------------------------------------------------

// renderHistory rebuilds the scrollback. Called whenever messages or the
// selection change.
func (m *Model) renderHistory() {
	var b strings.Builder
	if len(m.msgs) == 0 {
		b.WriteString(styMuted.Render("no messages yet"))
	}
	for i, msg := range m.msgs {
		who := msg.From
		if msg.Mine {
			who = "you"
		}
		head := fmt.Sprintf("%s %s", msg.SentAt.Local().Format("15:04"), who)
		line := fmt.Sprintf("%s  %s", styMuted.Render(head), msg.Body)
		// Only our own separate sends carry a known audience.
		if msg.Mine && len(msg.Audience) > 0 {
			line += styMuted.Render(fmt.Sprintf("  → %s", strings.Join(msg.Audience, ", ")))
		}
		if m.focus == focusHistory && i == m.msgIdx {
			b.WriteString(stySelected.Render("› ") + line)
		} else {
			b.WriteString("  " + line)
		}
		if i < len(m.msgs)-1 {
			b.WriteString("\n")
		}
	}
	m.history.SetContent(b.String())
	m.history.GotoBottom()
}

func (m Model) viewChat() string {
	// The conversation ID is shown because the local name is per-peer: two
	// windows can display the same name and be different conversations, or
	// different names and be the same one. The ID is the thing that must
	// match between peers.
	where := "relay"
	if m.conv.Dir != "" {
		where = "folder"
	}
	title := styTitle.Render("# "+m.conv.Name) + "  " +
		styMuted.Render(strings.Join(m.conv.Members, ", ")) + "  " +
		styMuted.Render(fmt.Sprintf("[%s %s]", where, short(m.conv.ID)))

	// Recipients panel.
	var rb strings.Builder
	rb.WriteString("recipients\n")
	others := m.others()
	for i, h := range others {
		box := "[ ]"
		if m.recipients[h] {
			box = "[x]"
		}
		line := fmt.Sprintf("%s %s", box, h)
		if m.focus == focusRecipients && i == m.recipIdx {
			rb.WriteString(stySelected.Render("› "+line) + "\n")
		} else {
			rb.WriteString("  " + line + "\n")
		}
	}
	rb.WriteString("\n")
	switch {
	case m.noneSelected():
		rb.WriteString(styErr.Render("nobody\nselected"))
	case m.everyoneSelected() && !m.separate:
		rb.WriteString(styMuted.Render("group key\n1 slot, 1 grant"))
	default:
		rb.WriteString(styWarn.Render("per-recipient\nkeys"))
	}
	if m.separate {
		rb.WriteString(styWarn.Render("\n[p] forced"))
	}

	recipPanel := styPanel
	histPanel := styPanel
	switch m.focus {
	case focusRecipients:
		recipPanel = styPanelHot
	case focusHistory:
		histPanel = styPanelHot
	}

	body := lipgloss.JoinHorizontal(lipgloss.Top,
		histPanel.Width(m.history.Width).Render(m.history.View()),
		recipPanel.Width(m.sidebarWidth()).Render(rb.String()),
	)

	keys := "tab=switch pane  enter=send  esc=back  ctrl+c=quit"
	switch m.focus {
	case focusRecipients:
		keys = "space=toggle  a=all  p=per-recipient keys  i=invite  tab=switch pane"
	case focusHistory:
		keys = "↑/↓=select  h=hide  u=unhide…  r=revoke  s=soft-revoke  d=delete  i=invite"
	}

	width := m.history.Width + m.sidebarWidth() + 2

	if m.showInvite {
		body = inviteBox(m.invite, width)
		keys = "i or esc=close"
	}

	// Hidden messages decrypt for nobody, so they cannot appear in the
	// history — they get their own picker, previewed from the owner's
	// retained layer keys.
	if m.showHidden {
		var hb strings.Builder
		hb.WriteString(styTitle.Render("hidden messages") + "  " +
			styMuted.Render("(only you can see these)") + "\n\n")
		for i, h := range m.hidden {
			preview := h.Preview
			if preview == "" {
				preview = styMuted.Render("(cannot preview)")
			}
			line := fmt.Sprintf("%s  %s", styMuted.Render(short(h.ObjectID)), preview)
			if i == m.hiddenIdx {
				hb.WriteString(stySelected.Render("› "+line) + "\n")
			} else {
				hb.WriteString("  " + line + "\n")
			}
		}
		body = styPanelHot.Width(width).Render(hb.String())
		keys = "↑/↓=select  enter=restore  esc=close"
	}

	if m.confirmWhat != nil {
		keys = styWarn.Render(m.confirm)
	}

	return title + "\n" + body + "\n" + m.input.View() + m.footer(keys)
}
