// Command pipl-register re-posts existing peer identities to the directory
// server. Useful after a memory-only server restart drops registrations.
// Usage: pipl-register <server-url> <home-dir>...
package main

import (
	"fmt"
	"os"

	"github.com/antonio/pipl/internal/api"
	"github.com/antonio/pipl/internal/identity"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: pipl-register <server-url> <home-dir>...")
		os.Exit(2)
	}
	// Optional TLS pin via PIPL_TLS_PIN, for a self-signed https server.
	cl := api.New(os.Args[1], os.Getenv("PIPL_TLS_PIN"))
	for _, home := range os.Args[2:] {
		id, err := identity.Load(home + "/identity.json")
		if err != nil {
			fmt.Printf("%s: %v\n", home, err)
			continue
		}
		if err := cl.Register(id.Public()); err != nil {
			fmt.Printf("%s (%s): %v\n", home, id.Handle, err)
			continue
		}
		fmt.Printf("registered %s (fp %s)\n", id.Handle, id.Public().Fingerprint())
	}
}
