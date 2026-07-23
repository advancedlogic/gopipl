// pipl: the peer client. Everything cryptographic happens here, on the
// client — the server never sees a key.
//
// Run with no arguments for the interactive UI:
//
//	pipl
//
// Or drive it with flags (same engine underneath, internal/chat):
//
//	pipl init   -handle alice [-server http://127.0.0.1:8737]
//	pipl conv new  -name chat -dir /path/shared -with bob[,carol]
//	pipl conv join -name chat -dir /path/shared
//	pipl send   -conv chat [-to bob,carol] [-separate] <message...>
//	pipl recv   -conv chat [-follow]
//	pipl revoke -conv chat -object <id> (-from bob [-soft] | -all)
//	pipl hide   -conv chat -object <id>
//	pipl unhide -conv chat -object <id>
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/antonio/pipl/internal/chat"
	"github.com/antonio/pipl/internal/identity"
	"github.com/antonio/pipl/internal/state"
	"github.com/antonio/pipl/internal/tui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	args, err := takeHomeFlag(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "pipl:", err)
		os.Exit(2)
	}

	// No subcommand: the interactive UI.
	if len(args) == 0 {
		if err := runTUI(); err != nil {
			fmt.Fprintln(os.Stderr, "pipl:", err)
			os.Exit(1)
		}
		return
	}
	switch args[0] {
	case "ui":
		err = runTUI()
	case "init":
		err = cmdInit(args[1:])
	case "register":
		err = cmdRegister(args[1:])
	case "unpin":
		err = cmdUnpin(args[1:])
	case "conv":
		if len(args) < 2 {
			usage()
			os.Exit(2)
		}
		switch args[1] {
		case "new":
			err = cmdConvNew(args[2:])
		case "join":
			err = cmdConvJoin(args[2:])
		case "invite":
			err = cmdConvInvite(args[2:])
		default:
			usage()
			os.Exit(2)
		}
	case "send":
		err = cmdSend(args[1:])
	case "recv":
		err = cmdRecv(args[1:])
	case "revoke":
		err = cmdRevoke(args[1:])
	case "hide":
		err = cmdHide(args[1:])
	case "unhide":
		err = cmdUnhide(args[1:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pipl:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  pipl                                          interactive UI (default)

  -home DIR   on any command, use DIR for this peer's keys and state.
              Running several peers on one machine is just several -home
              directories. Overrides $PIPL_HOME; default ~/.pipl.

  pipl init   -handle NAME [-server URL]        create identity
  pipl register                                 re-publish your identity (after a server reset)
  pipl unpin  -handle NAME                       forget a peer's pinned keys (after they re-created)
  pipl conv new  -name NAME -with H,H [-dir D]  start a conversation. With -dir it lives in a
                                                shared folder; without, it relays through the
                                                server (no folder needed) and prints an invite.
  pipl conv join -name NAME (-invite CODE|-dir D)  join by invite code, or from a shared folder
  pipl conv invite -name NAME                   reprint a conversation's invite code
  pipl send   -conv NAME [-to H,H] MESSAGE...   send text (default: whole roster, one shared
                                                group key; -to a subset: per-recipient keys,
                                                individually revocable)
              [-separate]                       ...force per-recipient keys for the whole roster
  pipl recv   -conv NAME [-follow]              read messages (follow = live)
  pipl revoke -conv NAME -object ID -from H     revoke one recipient of a per-recipient send
              [-soft]                           ...only delete their grant, no re-keying
  pipl revoke -conv NAME -object ID -all        revoke everyone (deletes the object)
  pipl hide   -conv NAME -object ID             wrap with a private key: no one can read it
  pipl unhide -conv NAME -object ID             peel the layer: previous grants work again
`)
}

// takeHomeFlag pulls -home/--home out of the command line wherever it
// appears and points local state at that directory, returning the
// remaining arguments for normal subcommand dispatch.
//
// It is handled here rather than by each subcommand's FlagSet so that it
// works uniformly: before or after the subcommand, and on bare `pipl`,
// which takes no subcommand at all. Accepts `-home DIR` and `-home=DIR`.
//
// Everything after a `--` separator, and everything after the message
// terminator of `send`, is left untouched — a message may legitimately
// contain the text "-home".
func takeHomeFlag(argv []string) ([]string, error) {
	var out []string
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		// The first bare word after `send` starts the message; anything
		// beyond it is content, never flags.
		if len(out) >= 2 && out[0] == "send" && !strings.HasPrefix(a, "-") &&
			!strings.HasPrefix(out[len(out)-1], "-") {
			return append(out, argv[i:]...), nil
		}
		switch {
		case a == "--":
			return append(out, argv[i+1:]...), nil
		case a == "-home" || a == "--home":
			if i+1 >= len(argv) {
				return nil, fmt.Errorf("-home needs a directory")
			}
			state.SetHome(argv[i+1])
			i++
		case strings.HasPrefix(a, "-home="), strings.HasPrefix(a, "--home="):
			dir := a[strings.Index(a, "=")+1:]
			if dir == "" {
				return nil, fmt.Errorf("-home needs a directory")
			}
			state.SetHome(dir)
		default:
			out = append(out, a)
		}
	}
	return out, nil
}

func runTUI() error {
	m, err := tui.New()
	if err != nil {
		return err
	}
	_, err = tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

// pinNotice prints first-contact TOFU pins to stderr, where they cannot be
// mistaken for message output.
func pinNotice(p identity.PublicIdentity) {
	fmt.Fprintf(os.Stderr, "pinned %s (fingerprint %s) — verify out of band\n", p.Handle, p.Fingerprint())
}

// ---- init ------------------------------------------------------------------

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	handle := fs.String("handle", "", "your handle (required)")
	server := fs.String("server", "http://127.0.0.1:8737", "coordination server URL ('' for none)")
	fs.Parse(args)
	if *handle == "" {
		return fmt.Errorf("-handle is required")
	}
	pub, err := chat.Init(*handle, *server)
	if err != nil {
		if pub.Handle == "" {
			return err
		}
		// Identity exists; only registration failed.
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	_, home, _ := chat.HasIdentity()
	fmt.Printf("created identity %s (fingerprint %s) in %s\n", pub.Handle, pub.Fingerprint(), home)
	if *server != "" && err == nil {
		fmt.Printf("registered with %s\n", *server)
	}
	return nil
}

// cmdRegister re-publishes an existing identity to the directory. Needed
// after the server loses its directory (e.g. a restart without -data),
// which otherwise leaves the peer unresolvable with no way back — init
// refuses once an identity exists.
func cmdRegister(args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	fs.Parse(args)
	e, err := chat.Load()
	if err != nil {
		return err
	}
	if err := e.Register(); err != nil {
		return err
	}
	pub := e.ID.Public()
	fmt.Printf("re-registered %s (fingerprint %s) with %s\n", pub.Handle, pub.Fingerprint(), e.Cfg.Server)
	return nil
}

// cmdUnpin forgets a pinned peer so the next contact re-pins their current
// identity from the server. The recovery when a peer was re-created and
// TOFU refuses their changed keys.
func cmdUnpin(args []string) error {
	fs := flag.NewFlagSet("unpin", flag.ExitOnError)
	handle := fs.String("handle", "", "peer handle to forget (required)")
	fs.Parse(args)
	if *handle == "" {
		return fmt.Errorf("-handle is required")
	}
	e, err := chat.Load()
	if err != nil {
		return err
	}
	fp, ok, err := e.Unpin(*handle)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Printf("%q was not pinned — nothing to do\n", *handle)
		return nil
	}
	fmt.Printf("forgot %s (was fingerprint %s) — next contact will re-pin from the server\n", *handle, fp)
	fmt.Println("note: verify their new fingerprint out of band before trusting it.")
	return nil
}

// ---- conversations ---------------------------------------------------------

func cmdConvNew(args []string) error {
	fs := flag.NewFlagSet("conv new", flag.ExitOnError)
	name := fs.String("name", "", "local name for the conversation (required)")
	dir := fs.String("dir", "", "shared folder; omit to relay through the server instead")
	with := fs.String("with", "", "comma-separated peer handles (required)")
	fs.Parse(args)
	if *name == "" || *with == "" {
		return fmt.Errorf("-name and -with are required")
	}
	e, err := chat.Load()
	if err != nil {
		return err
	}
	conv, err := e.NewConversation(*name, *dir, strings.Split(*with, ","), pinNotice)
	if err != nil {
		return err
	}
	where := conv.Dir
	if where == "" {
		where = "the server relay (no shared folder needed)"
	}
	fmt.Printf("conversation %q created in %s (members: %s; group key distributed)\n",
		conv.Name, where, strings.Join(conv.Members, ", "))
	code, err := e.Invite(conv.Name)
	if err != nil {
		return err
	}
	fmt.Printf("\ninvite (send to the others, then they run 'pipl conv join -name %s -invite CODE'):\n%s\n",
		conv.Name, code)
	return nil
}

func cmdConvJoin(args []string) error {
	fs := flag.NewFlagSet("conv join", flag.ExitOnError)
	name := fs.String("name", "", "local name for the conversation (required)")
	dir := fs.String("dir", "", "shared folder of the conversation")
	invite := fs.String("invite", "", "invite code from the creator (instead of -dir)")
	fs.Parse(args)
	if *name == "" || (*dir == "" && *invite == "") {
		return fmt.Errorf("-name and one of -dir or -invite are required")
	}
	e, err := chat.Load()
	if err != nil {
		return err
	}
	var conv state.Conversation
	if *invite != "" {
		conv, err = e.JoinInvite(*name, *invite, pinNotice)
	} else {
		conv, err = e.JoinConversation(*name, *dir, pinNotice)
	}
	if err != nil {
		return err
	}
	where := conv.Dir
	if where == "" {
		where = "the server relay"
	}
	fmt.Printf("joined conversation %q in %s (members: %s; group key received)\n",
		conv.Name, where, strings.Join(conv.Members, ", "))
	return nil
}

// cmdConvInvite reprints a conversation's invite code.
func cmdConvInvite(args []string) error {
	fs := flag.NewFlagSet("conv invite", flag.ExitOnError)
	name := fs.String("name", "", "conversation name (required)")
	fs.Parse(args)
	if *name == "" {
		return fmt.Errorf("-name is required")
	}
	e, err := chat.Load()
	if err != nil {
		return err
	}
	code, err := e.Invite(*name)
	if err != nil {
		return err
	}
	fmt.Println(code)
	return nil
}

// ---- send ------------------------------------------------------------------

func cmdSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	convName := fs.String("conv", "", "conversation name (required)")
	to := fs.String("to", "", "comma-separated recipients (default: the whole roster)")
	separate := fs.Bool("separate", false, "force per-recipient access keys even when sending to everyone")
	fs.Parse(args)
	msg := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if *convName == "" || msg == "" {
		return fmt.Errorf("usage: pipl send -conv NAME [-to H,H] [-separate] MESSAGE...")
	}
	e, err := chat.Load()
	if err != nil {
		return err
	}
	var recipients []string
	if *to != "" {
		recipients = strings.Split(*to, ",")
	}
	res, err := e.Send(*convName, msg, recipients, *separate)
	if err != nil {
		return err
	}
	fmt.Printf("sent %s\n", res.ObjectID)
	if res.Mode == "separate" {
		fmt.Fprintf(os.Stderr, "audience: %s (per-recipient keys — each revocable alone)\n",
			strings.Join(res.Audience, ", "))
	}
	return nil
}

// ---- recv ------------------------------------------------------------------

func cmdRecv(args []string) error {
	fs := flag.NewFlagSet("recv", flag.ExitOnError)
	convName := fs.String("conv", "", "conversation name (required)")
	follow := fs.Bool("follow", false, "keep listening for new messages")
	fs.Parse(args)
	if *convName == "" {
		return fmt.Errorf("-conv is required")
	}
	e, err := chat.Load()
	if err != nil {
		return err
	}
	conv, err := e.Conversation(*convName)
	if err != nil {
		return err
	}

	seen := map[string]bool{}
	scan := func() {
		msgs, err := e.Messages(conv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
			return
		}
		for _, m := range msgs {
			if seen[m.ObjectID] {
				continue
			}
			seen[m.ObjectID] = true
			fmt.Printf("[%s] %s: %s  (%s)\n",
				m.SentAt.Local().Format("15:04:05"), m.From, m.Body, m.ObjectID)
		}
	}
	scan()
	if !*follow {
		return nil
	}
	if e.Cl != nil {
		fmt.Fprintln(os.Stderr, "(following via server notifications — ctrl-c to stop)")
		return e.Cl.Events(context.Background(), conv.ID, scan)
	}
	fmt.Fprintln(os.Stderr, "(no server configured: polling the folder every 2s — ctrl-c to stop)")
	for {
		time.Sleep(2 * time.Second)
		scan()
	}
}

// ---- revoke / hide / unhide ------------------------------------------------

func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	convName := fs.String("conv", "", "conversation name (required)")
	objectID := fs.String("object", "", "object id (required)")
	from := fs.String("from", "", "handle to revoke")
	all := fs.Bool("all", false, "revoke everyone: delete the object")
	soft := fs.Bool("soft", false, "with -from: only delete their grant file (no key rotation)")
	fs.Parse(args)
	if *convName == "" || *objectID == "" || (*from == "" && !*all) {
		return fmt.Errorf("usage: pipl revoke -conv NAME -object ID (-from HANDLE [-soft] | -all)")
	}
	e, err := chat.Load()
	if err != nil {
		return err
	}

	if *all {
		if err := e.RevokeAll(*convName, *objectID); err != nil {
			return err
		}
		fmt.Printf("revoked %s for everyone (object and all grants deleted)\n", *objectID)
		fmt.Println("note: anyone who already read it may have kept a copy — revocation cannot un-share.")
		return nil
	}
	if *soft {
		if err := e.RevokeSoft(*convName, *objectID, *from); err != nil {
			return err
		}
		fmt.Printf("soft-revoked %s from %s (grant deleted; a cached access key would still open the slot — use hard revoke)\n",
			*objectID, *from)
		return nil
	}
	layers, slots, err := e.RevokeFrom(*convName, *objectID, *from)
	if err != nil {
		return err
	}
	fmt.Printf("hard-revoked %s from %s (wrapped, now %d layer(s), %d slot(s) for the remaining audience — no re-granting needed)\n",
		*objectID, *from, layers, slots)
	fmt.Println("note: if they already read it, they may have kept a copy — revocation cannot un-share.")
	return nil
}

func cmdHide(args []string) error {
	fs := flag.NewFlagSet("hide", flag.ExitOnError)
	convName := fs.String("conv", "", "conversation name (required)")
	objectID := fs.String("object", "", "object id (required)")
	fs.Parse(args)
	if *convName == "" || *objectID == "" {
		return fmt.Errorf("usage: pipl hide -conv NAME -object ID")
	}
	e, err := chat.Load()
	if err != nil {
		return err
	}
	if err := e.Hide(*convName, *objectID); err != nil {
		return err
	}
	o, _, err := e.Owned(*objectID)
	if err != nil {
		return err
	}
	fmt.Printf("hidden %s (wrapped with zero key slots — v%d, %d layer(s); 'pipl unhide' to restore)\n",
		*objectID, o.KeyVersion, len(o.LayerKeys))
	return nil
}

func cmdUnhide(args []string) error {
	fs := flag.NewFlagSet("unhide", flag.ExitOnError)
	convName := fs.String("conv", "", "conversation name (required)")
	objectID := fs.String("object", "", "object id (required)")
	fs.Parse(args)
	if *convName == "" || *objectID == "" {
		return fmt.Errorf("usage: pipl unhide -conv NAME -object ID")
	}
	e, err := chat.Load()
	if err != nil {
		return err
	}
	if err := e.Unhide(*convName, *objectID); err != nil {
		return err
	}
	o, _, err := e.Owned(*objectID)
	if err != nil {
		return err
	}
	fmt.Printf("restored %s to v%d — previously granted recipients can read it again\n",
		*objectID, o.KeyVersion)
	return nil
}
