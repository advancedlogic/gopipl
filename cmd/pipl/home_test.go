package main

import (
	"reflect"
	"testing"

	"github.com/antonio/pipl/internal/state"
)

// takeHomeFlag rewrites global state, so restore it around each case.
func withCleanHome(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { state.SetHome("") })
}

func TestTakeHomeFlag(t *testing.T) {
	cases := []struct {
		name     string
		argv     []string
		wantArgs []string
		wantHome string
	}{
		{
			name:     "no flag leaves args untouched",
			argv:     []string{"send", "-conv", "team", "hello"},
			wantArgs: []string{"send", "-conv", "team", "hello"},
		},
		{
			name:     "bare pipl with home",
			argv:     []string{"-home", "C:/peers/alice"},
			wantArgs: nil,
			wantHome: "C:/peers/alice",
		},
		{
			name:     "before the subcommand",
			argv:     []string{"-home", "/a", "recv", "-conv", "team"},
			wantArgs: []string{"recv", "-conv", "team"},
			wantHome: "/a",
		},
		{
			name:     "after the subcommand",
			argv:     []string{"recv", "-home", "/a", "-conv", "team"},
			wantArgs: []string{"recv", "-conv", "team"},
			wantHome: "/a",
		},
		{
			name:     "equals form",
			argv:     []string{"-home=/a", "recv"},
			wantArgs: []string{"recv"},
			wantHome: "/a",
		},
		{
			name:     "double dash form",
			argv:     []string{"--home", "/a", "recv"},
			wantArgs: []string{"recv"},
			wantHome: "/a",
		},
		{
			name:     "windows path with spaces survives",
			argv:     []string{"-home", `C:\Users\A B\.pipl`, "recv"},
			wantArgs: []string{"recv"},
			wantHome: `C:\Users\A B\.pipl`,
		},
		// The message of a send is content, not flags: a message that
		// happens to contain "-home" must reach the recipient intact.
		{
			name:     "send message containing -home is not eaten",
			argv:     []string{"send", "-conv", "team", "why", "is", "-home", "broken"},
			wantArgs: []string{"send", "-conv", "team", "why", "is", "-home", "broken"},
		},
		{
			name:     "home flag before a send message still applies",
			argv:     []string{"-home", "/a", "send", "-conv", "team", "hello", "-home", "x"},
			wantArgs: []string{"send", "-conv", "team", "hello", "-home", "x"},
			wantHome: "/a",
		},
		{
			name:     "everything after -- is literal",
			argv:     []string{"-home", "/a", "send", "-conv", "team", "--", "-home", "literal"},
			wantArgs: []string{"send", "-conv", "team", "-home", "literal"},
			wantHome: "/a",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withCleanHome(t)
			state.SetHome("")
			got, err := takeHomeFlag(tc.argv)
			if err != nil {
				t.Fatalf("takeHomeFlag: %v", err)
			}
			if !reflect.DeepEqual(got, tc.wantArgs) {
				t.Errorf("args = %q, want %q", got, tc.wantArgs)
			}
			home, err := state.Home()
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantHome != "" && home != tc.wantHome {
				t.Errorf("home = %q, want %q", home, tc.wantHome)
			}
		})
	}
}

func TestTakeHomeFlagRejectsMissingValue(t *testing.T) {
	withCleanHome(t)
	for _, argv := range [][]string{
		{"-home"},
		{"recv", "-home"},
		{"-home="},
	} {
		if _, err := takeHomeFlag(argv); err == nil {
			t.Errorf("takeHomeFlag(%q) accepted a missing directory", argv)
		}
	}
}

// The override must beat the environment variable, so a -home on the
// command line is never silently ignored because a stale PIPL_HOME is set.
func TestHomeFlagBeatsEnvironment(t *testing.T) {
	withCleanHome(t)
	t.Setenv("PIPL_HOME", "/from/env")

	got, err := state.Home()
	if err != nil {
		t.Fatal(err)
	}
	if got != "/from/env" {
		t.Fatalf("without a flag, home = %q, want the env value", got)
	}

	if _, err := takeHomeFlag([]string{"-home", "/from/flag", "recv"}); err != nil {
		t.Fatal(err)
	}
	got, err = state.Home()
	if err != nil {
		t.Fatal(err)
	}
	if got != "/from/flag" {
		t.Fatalf("home = %q, want the flag to win over $PIPL_HOME", got)
	}
}
