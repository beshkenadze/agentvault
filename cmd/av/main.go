// Command av is the thin AgentVault CLI.
package main

import (
	"fmt"
	"os"

	"github.com/beshkenadze/agentvault/internal/client"
	"github.com/beshkenadze/agentvault/internal/transport"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "ping" {
		fmt.Fprintln(os.Stderr, "usage: av ping")
		os.Exit(2)
	}
	path, err := transport.DefaultSocketPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(1)
	}
	out, err := client.New(path).Ping()
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(1)
	}
	fmt.Println(out)
}
