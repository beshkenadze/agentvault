// Package client is the av-side RPC client with daemon autostart.
package client

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// Client is a thin RPC client bound to a daemon socket path.
type Client struct{ path string }

// New returns a Client for the daemon socket at path.
func New(path string) *Client { return &Client{path: path} }

// call dials the daemon, sends one request, and returns the response. If the
// initial dial fails (no daemon listening), it autostarts avd detached and then
// retries the dial until the daemon is up or a deadline elapses.
func (c *Client) call(req ipc.Request) (ipc.Response, error) {
	conn, err := transport.Dial(c.path)
	if err != nil {
		if serr := autostart(c.path); serr != nil {
			return ipc.Response{}, fmt.Errorf("dial and autostart failed: %w", serr)
		}
		conn, err = dialRetry(c.path, 2*time.Second)
		if err != nil {
			return ipc.Response{}, err
		}
	}
	defer conn.Close()
	if err := ipc.NewEncoder(conn).Encode(req); err != nil {
		return ipc.Response{}, err
	}
	var resp ipc.Response
	if err := ipc.NewDecoder(conn).Decode(&resp); err != nil {
		return ipc.Response{}, err
	}
	return resp, nil
}

// dialRetry polls transport.Dial every ~100ms until it succeeds or total elapses,
// returning the last dial error on timeout. Used after autostart while the freshly
// spawned daemon binds its socket.
func dialRetry(path string, total time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(total)
	var err error
	for {
		var conn net.Conn
		conn, err = transport.Dial(path)
		if err == nil {
			return conn, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("daemon did not come up within %s: %w", total, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Resolve issues the "resolve" RPC: it sends the profile and the raw
// agentvault.yaml bytes (av stays thin — avd parses and resolves) and returns
// the logical name -> value map. On a daemon error it returns resp.Error (a
// *ipc.RPCError) so the caller can inspect its Code (e.g. CodeLocked/CodeDenied).
func (c *Client) Resolve(profile string, manifestBytes []byte) (map[string]string, error) {
	p, _ := json.Marshal(ipc.ResolveParams{Profile: profile, Manifest: manifestBytes})
	resp, err := c.call(ipc.Request{ID: 1, Method: "resolve", Params: p})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error // caller inspects Code (Locked/Denied)
	}
	var r ipc.ResolveResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, err
	}
	return r.Values, nil
}

// Ping issues the "ping" RPC and returns the daemon's reply (expected "pong").
func (c *Client) Ping() (string, error) {
	resp, err := c.call(ipc.Request{ID: 1, Method: "ping"})
	if err != nil {
		return "", err
	}
	if resp.Error != nil {
		return "", resp.Error
	}
	var pong string
	if err := json.Unmarshal(resp.Result, &pong); err != nil {
		return "", err
	}
	return pong, nil
}
