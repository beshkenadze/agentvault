// Command avd is the AgentVault broker daemon.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/beshkenadze/agentvault/internal/daemon"
	"github.com/beshkenadze/agentvault/internal/transport"
)

func main() {
	path, err := transport.DefaultSocketPath()
	if err != nil {
		log.Fatalf("avd: socket path: %v", err)
	}
	srv, err := daemon.New(path)
	if err != nil {
		log.Fatalf("avd: listen: %v", err)
	}
	go srv.Serve()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	srv.Close()
	os.Remove(path)
}
