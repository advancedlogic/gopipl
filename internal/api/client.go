// Package api is the client for the pipl server: identity directory
// lookups, change notifications (POST), and a change-event subscription
// (SSE). Note what is absent: no keys, no content, no capabilities ever
// touch this API.
package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/antonio/pipl/internal/identity"
)

type Client struct {
	Base string
	http *http.Client
}

func New(base string) *Client {
	return &Client{
		Base: strings.TrimRight(base, "/"),
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) Register(p identity.PublicIdentity) error {
	return c.post("/v1/identities", p)
}

func (c *Client) Lookup(handle string) (identity.PublicIdentity, error) {
	var p identity.PublicIdentity
	resp, err := c.http.Get(c.Base + "/v1/identities/" + handle)
	if err != nil {
		return p, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return p, fmt.Errorf("unknown handle %q (has that peer run 'pipl init'?)", handle)
	}
	if resp.StatusCode != http.StatusOK {
		return p, fmt.Errorf("server: %s", resp.Status)
	}
	return p, json.NewDecoder(resp.Body).Decode(&p)
}

func (c *Client) Notify(convID string) error {
	return c.post("/v1/notify", map[string]string{"conversation_id": convID})
}

func (c *Client) post(path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.http.Post(c.Base+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server: %s", resp.Status)
	}
	return nil
}

// ---- blob relay ------------------------------------------------------------
//
// Objects and grants stored on the server as opaque ciphertext, for peers
// who share no filesystem. Nothing here sends a key: the payloads are the
// same encrypted bytes that would otherwise sit in a shared folder.

// BlobEntry is one item in a conversation's relay listing.
type BlobEntry struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"` // "object" | "grant"
	UpdatedAt time.Time `json:"updated_at"`
}

func (c *Client) PutObject(convID, objectID string, data []byte) error {
	return c.put("/v1/blobs/"+convID+"/objects/"+objectID, data)
}

func (c *Client) PutGrant(convID, grantID string, data []byte) error {
	return c.put("/v1/blobs/"+convID+"/grants/"+grantID, data)
}

func (c *Client) ListBlobs(convID string) ([]BlobEntry, error) {
	resp, err := c.http.Get(c.Base + "/v1/blobs/" + convID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server: %s", resp.Status)
	}
	var out []BlobEntry
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// GetBlob fetches one blob. A missing blob returns os.ErrNotExist so
// callers can treat it the same way as a deleted file in a folder.
func (c *Client) GetBlob(convID, id string) ([]byte, error) {
	resp, err := c.http.Get(c.Base + "/v1/blobs/" + convID + "/" + id)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, os.ErrNotExist
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server: %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// DeleteObject removes a relayed object. sig must be the owner's
// signature over relay.DeleteChallenge(objectID) — the server refuses
// anything else, so this cannot be used against another peer's object.
func (c *Client) DeleteObject(convID, objectID string, sig []byte) error {
	req, err := http.NewRequest(http.MethodDelete,
		c.Base+"/v1/blobs/"+convID+"/objects/"+objectID+"?sig="+hex.EncodeToString(sig), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return os.ErrNotExist
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server: %s", resp.Status)
	}
	return nil
}

// DeleteGrant removes a sealed grant blob (soft revoke).
//
// Unlike an object, a sealed grant carries no signature the server can
// verify, so the server cannot tell the owner from anyone else who knows
// the blob ID. Grant IDs are random and known only to peers who listed
// the conversation, which is the same exposure a shared folder gives —
// but it is weaker than object deletion, and soft revoke is documented as
// the weak tier regardless.
func (c *Client) DeleteGrant(convID, grantID string) error {
	req, err := http.NewRequest(http.MethodDelete, c.Base+"/v1/blobs/"+convID+"/grants/"+grantID, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return os.ErrNotExist
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server: %s", resp.Status)
	}
	return nil
}

func (c *Client) put(path string, data []byte) error {
	req, err := http.NewRequest(http.MethodPut, c.Base+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("server: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

// Events subscribes to change notifications for one conversation and
// invokes onEvent for each. Blocks until ctx is cancelled or the stream
// drops.
func (c *Client) Events(ctx context.Context, convID string, onEvent func()) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.Base+"/v1/events?conversation="+convID, nil)
	if err != nil {
		return err
	}
	stream := &http.Client{} // no timeout: long-lived stream
	resp, err := stream.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server: %s", resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "data:") {
			onEvent()
		}
	}
	return sc.Err()
}
