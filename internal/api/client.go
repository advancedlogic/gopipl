// Package api is the client for the pipl server: identity directory
// lookups, change notifications (POST), and a change-event subscription
// (SSE). Note what is absent: no keys, no content, no capabilities ever
// touch this API.
package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
