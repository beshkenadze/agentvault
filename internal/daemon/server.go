// Package daemon implements the avd serve loop. Phase 2 handles only "ping";
// later phases add resolve/scrub/lock/etc. on the same dispatch.
package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// Server owns the unix-socket listener and serves the JSON-RPC dispatch.
type Server struct {
	ln net.Listener
}

// New binds the daemon socket at path. As a single-instance guard (security
// requirement I-1), it first try-dials the existing socket: if a live peer
// answers, it REFUSES to start rather than clobber the running daemon's
// endpoint. transport.Listen removes a stale socket, so the liveness check must
// happen here, before listening.
func New(path string) (*Server, error) {
	if c, err := transport.Dial(path); err == nil {
		c.Close()
		return nil, fmt.Errorf("avd already running at %s", path)
	}
	ln, err := transport.Listen(path)
	if err != nil {
		return nil, err
	}
	return &Server{ln: ln}, nil
}

// Serve accepts connections until the listener is closed, handling each in a
// goroutine.
func (s *Server) Serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handle(c)
	}
}

// handle gates every connection on the peer-credential check FIRST. If the peer
// is unverified, it sends a CodeUnauthorized response and closes the connection
// (reject-and-close) — it never dispatches a request from an unverified peer.
func (s *Server) handle(c net.Conn) {
	defer c.Close()
	if err := transport.CheckPeer(c); err != nil {
		_ = ipc.NewEncoder(c).Encode(ipc.Response{
			Error: &ipc.RPCError{Code: ipc.CodeUnauthorized, Message: "peer rejected"},
		})
		return
	}
	dec := ipc.NewDecoder(c)
	enc := ipc.NewEncoder(c)
	for {
		var req ipc.Request
		if err := dec.Decode(&req); err != nil {
			return // EOF / closed
		}
		if err := enc.Encode(s.dispatch(req)); err != nil {
			return
		}
	}
}

// dispatch routes a request to its handler. Phase 2 knows only "ping".
func (s *Server) dispatch(req ipc.Request) ipc.Response {
	switch req.Method {
	case "ping":
		r, _ := json.Marshal("pong")
		return ipc.Response{ID: req.ID, Result: r}
	default:
		return ipc.Response{ID: req.ID, Error: &ipc.RPCError{
			Code: ipc.CodeBadRequest, Message: "unknown method: " + req.Method,
		}}
	}
}

// Close stops accepting connections. A closed listener is not an error.
func (s *Server) Close() error {
	err := s.ln.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
