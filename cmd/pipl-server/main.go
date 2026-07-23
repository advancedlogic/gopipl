// pipl-server: the deliberately minimal coordination server.
//
// It holds NO keys, NO plaintext, and NO capabilities: a public-identity
// directory (TOFU), "conversation X changed" notifications, and a blob
// relay that stores ciphertext it cannot decrypt.
//
// The relay is what lets peers who share no filesystem chat at all
// (design §7, amendment A5). It is durable rather than store-and-forward,
// because revocation works by rewriting a stored object — a blob deleted
// on delivery could never be revoked. The server authorizes rewrites by
// verifying each object's Ed25519 signature, which is a public operation:
// it can check authorship without holding any secret, so only an object's
// owner can replace or delete it.
//
// Compromise of this server therefore yields ciphertext and metadata
// (who talks to whom, when, and how big) — never content. Peers sharing a
// filesystem can still chat with no server at all.
//
// Single static binary; stdlib only. The same handler set is designed to
// mount behind AWS Lambda + API Gateway later (see design doc §7).
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/antonio/pipl/internal/identity"
	"github.com/antonio/pipl/internal/relay"
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
	blobDir := flag.String("blobs", "", "optional directory to persist relayed blobs (ciphertext); memory-only if unset")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (with -tls-key)")
	tlsKey := flag.String("tls-key", "", "TLS private key file (with -tls-cert)")
	tlsSelf := flag.Bool("tls-self-signed", false, "generate a self-signed TLS cert; clients pin its fingerprint")
	tlsDir := flag.String("tls-dir", "", "with -tls-self-signed, cache the cert here so its fingerprint survives restarts")
	fpFile := flag.String("tls-fingerprint-file", "", "write the cert fingerprint here (for clients to pin)")
	flag.Parse()

	tlsCfg, tlsNote, err := tlsConfig(*tlsCert, *tlsKey, *tlsSelf, *tlsDir, *addr)
	if err != nil {
		log.Fatal(err)
	}

	dir, err := newDirectory(*dataFile)
	if err != nil {
		log.Fatal(err)
	}
	h := newHub()
	blobs, err := relay.OpenStore(*blobDir)
	if err != nil {
		log.Fatal(err)
	}
	for _, s := range blobs.Skipped() {
		log.Printf("warning: skipped unreadable blob %s", s)
	}

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

	// ---- sealed-blob relay -------------------------------------------------
	//
	// Durable storage for ciphertext the server cannot read, so peers who
	// share no filesystem can still exchange objects and grants. The server
	// verifies object signatures — a public operation needing no secret —
	// so only an object's owner can rewrite or delete it. See design §7/A5.

	mux.HandleFunc("PUT /v1/blobs/{conv}/objects/{id}", func(w http.ResponseWriter, r *http.Request) {
		data, err := readLimited(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		switch err := blobs.PutObject(r.PathValue("conv"), r.PathValue("id"), data); {
		case err == nil:
			h.notify(r.PathValue("conv"))
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, relay.ErrNotOwner):
			// Someone tried to overwrite an object they do not own.
			http.Error(w, err.Error(), http.StatusForbidden)
		default:
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	mux.HandleFunc("PUT /v1/blobs/{conv}/grants/{id}", func(w http.ResponseWriter, r *http.Request) {
		data, err := readLimited(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := blobs.PutGrant(r.PathValue("conv"), r.PathValue("id"), data); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		h.notify(r.PathValue("conv"))
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /v1/blobs/{conv}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(blobs.List(r.PathValue("conv")))
	})

	mux.HandleFunc("GET /v1/blobs/{conv}/{id}", func(w http.ResponseWriter, r *http.Request) {
		b, err := blobs.Get(r.PathValue("id"))
		if err != nil || b.ConversationID != r.PathValue("conv") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(b.Data)
	})

	// Grant deletion (soft revoke). A sealed grant carries no signature
	// the server can verify, so authorization here rests only on knowing
	// the random blob ID — the same exposure a shared folder gives anyone
	// who can list it. Soft revoke is the documented weak tier either way;
	// hard revoke rewrites the object, which IS signature-checked.
	mux.HandleFunc("DELETE /v1/blobs/{conv}/grants/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := blobs.DeleteGrant(r.PathValue("conv"), r.PathValue("id")); err != nil {
			http.NotFound(w, r)
			return
		}
		h.notify(r.PathValue("conv"))
		w.WriteHeader(http.StatusNoContent)
	})

	// Deletion is authorized by a signature over a fixed challenge under
	// the object's own signing key: no accounts, no passwords, and the
	// server still cannot mint one.
	mux.HandleFunc("DELETE /v1/blobs/{conv}/objects/{id}", func(w http.ResponseWriter, r *http.Request) {
		sig, err := hex.DecodeString(r.URL.Query().Get("sig"))
		if err != nil || len(sig) == 0 {
			http.Error(w, "missing or malformed ?sig", http.StatusBadRequest)
			return
		}
		switch err := blobs.DeleteObject(r.PathValue("id"), sig); {
		case err == nil:
			h.notify(r.PathValue("conv"))
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, relay.ErrNotFound):
			http.NotFound(w, r)
		default:
			http.Error(w, err.Error(), http.StatusForbidden)
		}
	})

	log.Printf("pipl-server listening on %s", *addr)
	log.Print("  keyless: identity directory, notifications, and a blob relay that stores only ciphertext")
	if *blobDir == "" {
		log.Print("  relay storage: MEMORY ONLY — relayed conversations are lost on restart (-blobs DIR to persist)")
	} else {
		log.Printf("  relay storage: %s", *blobDir)
	}
	log.Printf("  %s", tlsNote)

	srv := &http.Server{Addr: *addr, Handler: mux, TLSConfig: tlsCfg}
	if tlsCfg == nil {
		log.Fatal(srv.ListenAndServe())
	}
	// Persist the fingerprint if asked, so a local client can pin without
	// copying it out of the logs.
	if fp := certFingerprint(tlsCfg.Certificates[0].Certificate[0]); *fpFile != "" {
		if err := writeFingerprintFile(*fpFile, fp); err != nil {
			log.Fatalf("writing fingerprint file: %v", err)
		}
		log.Printf("  fingerprint written to %s", *fpFile)
	}
	// Cert and key already live in TLSConfig.Certificates, so pass "".
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// maxBlob bounds a single upload. Generous for text, and a backstop
// against a peer filling the server with one request.
const maxBlob = 8 << 20 // 8 MiB

func readLimited(r *http.Request) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBlob+1))
	if err != nil {
		return nil, errors.New("read error")
	}
	if len(data) > maxBlob {
		return nil, fmt.Errorf("blob exceeds %d bytes", maxBlob)
	}
	if len(data) == 0 {
		return nil, errors.New("empty body")
	}
	return data, nil
}
