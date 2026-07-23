// pipl-server: the deliberately minimal coordination server.
//
// It holds NO keys, NO plaintext, NO capabilities, and NO chat content —
// only a public-identity directory (TOFU) and ephemeral "conversation X
// changed" notifications. Compromise of this server yields, at worst,
// metadata. Peers sharing a filesystem can chat without it entirely.
//
// Single static binary; stdlib only. The same handler set is designed to
// mount behind AWS Lambda + API Gateway later (see design doc §7).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/antonio/pipl/internal/identity"
)

// ---- notification hub ------------------------------------------------------

type hub struct {
	mu   sync.Mutex
	subs map[string]map[chan struct{}]struct{}
}

func newHub() *hub { return &hub{subs: map[string]map[chan struct{}]struct{}{}} }

func (h *hub) subscribe(conv string) chan struct{} {
	ch := make(chan struct{}, 8)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.subs[conv] == nil {
		h.subs[conv] = map[chan struct{}]struct{}{}
	}
	h.subs[conv][ch] = struct{}{}
	return ch
}

func (h *hub) unsubscribe(conv string, ch chan struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs[conv], ch)
	if len(h.subs[conv]) == 0 {
		delete(h.subs, conv)
	}
}

func (h *hub) notify(conv string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[conv] {
		select {
		case ch <- struct{}{}:
		default: // slow subscriber: drop; client rescans on next event anyway
		}
	}
}

// ---- identity directory (TOFU) --------------------------------------------

type directory struct {
	mu   sync.Mutex
	path string // optional persistence file
	ids  map[string]identity.PublicIdentity
}

func newDirectory(path string) (*directory, error) {
	d := &directory{path: path, ids: map[string]identity.PublicIdentity{}}
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			if err := json.Unmarshal(data, &d.ids); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return d, nil
}

// register applies first-write-wins: an existing handle with different
// keys is rejected. The server cannot rewrite an identity out from under
// peers — and clients additionally pin fingerprints locally.
func (d *directory) register(p identity.PublicIdentity) (conflict bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if existing, ok := d.ids[p.Handle]; ok {
		if existing.Equal(p) {
			return false, nil
		}
		return true, nil
	}
	d.ids[p.Handle] = p
	if d.path != "" {
		data, err := json.MarshalIndent(d.ids, "", "  ")
		if err != nil {
			return false, err
		}
		return false, os.WriteFile(d.path, data, 0o600)
	}
	return false, nil
}

func (d *directory) lookup(handle string) (identity.PublicIdentity, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	p, ok := d.ids[handle]
	return p, ok
}

// ---- main ------------------------------------------------------------------

func main() {
	addr := flag.String("addr", "127.0.0.1:8737", "listen address")
	dataFile := flag.String("data", "", "optional file to persist the identity directory")
	flag.Parse()

	dir, err := newDirectory(*dataFile)
	if err != nil {
		log.Fatal(err)
	}
	h := newHub()

	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/identities", func(w http.ResponseWriter, r *http.Request) {
		var p identity.PublicIdentity
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Handle == "" ||
			len(p.SignPub) != 32 || len(p.BoxPub) != 32 {
			http.Error(w, "bad identity", http.StatusBadRequest)
			return
		}
		conflict, err := dir.register(p)
		if err != nil {
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		if conflict {
			http.Error(w, "handle already registered with different keys", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /v1/identities/{handle}", func(w http.ResponseWriter, r *http.Request) {
		p, ok := dir.lookup(r.PathValue("handle"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(p)
	})

	mux.HandleFunc("POST /v1/notify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ConversationID string `json:"conversation_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ConversationID == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		h.notify(body.ConversationID)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /v1/events", func(w http.ResponseWriter, r *http.Request) {
		conv := r.URL.Query().Get("conversation")
		if conv == "" {
			http.Error(w, "missing ?conversation", http.StatusBadRequest)
			return
		}
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		ch := h.subscribe(conv)
		defer h.unsubscribe(conv, ch)
		fmt.Fprint(w, ": connected\n\n")
		fl.Flush()
		ping := time.NewTicker(25 * time.Second)
		defer ping.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ch:
				fmt.Fprintf(w, "data: {\"conversation_id\":%q}\n\n", conv)
				fl.Flush()
			case <-ping.C:
				fmt.Fprint(w, ": ping\n\n")
				fl.Flush()
			}
		}
	})

	log.Printf("pipl-server listening on %s (keyless: identity directory + notifications only)", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
