// vmattach is a minimal host-side client for the microVM guest agent. It dials
// a Firecracker vsock Unix socket, performs the "CONNECT <port>" handshake to
// reach the guest's vsock listener, sends a start request, and bridges stdin
// and stdout to the in-guest PTY.
//
// This is a bring-up/validation tool for Milestone A (prove the vsock dataplane
// end to end). In the product, the daemon's session supervisor speaks this same
// protocol and the existing wss attach server bridges it to the CLI unchanged.
//
// Usage:
//
//	vmattach <vsock-uds> [-- cmd args...]
//
// With no command it runs an interactive /bin/sh. A 60s overall deadline keeps
// a non-interactive run (piped stdin / self-contained command) from hanging.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const guestPort = 1024

type request struct {
	Op   string   `json:"op"`
	Cmd  []string `json:"cmd,omitempty"`
	Env  []string `json:"env,omitempty"`
	Cols int      `json:"cols"`
	Rows int      `json:"rows"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vmattach <vsock-uds> [-- cmd args...]")
		os.Exit(2)
	}
	uds := os.Args[1]
	var cmd []string
	var env []string // forwarded "KEY=VALUE" vars, taken from vmattach's own environment
	for i := 2; i < len(os.Args); i++ {
		switch {
		case os.Args[i] == "--":
			cmd = os.Args[i+1:]
			i = len(os.Args)
		case os.Args[i] == "-e" && i+1 < len(os.Args):
			// forward the NAMED variable's value from our env (keeps the secret out of argv)
			if v, ok := os.LookupEnv(os.Args[i+1]); ok {
				env = append(env, os.Args[i+1]+"="+v)
			}
			i++
		}
	}

	c, err := net.DialTimeout("unix", uds, 10*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))

	// Firecracker vsock handshake: "CONNECT <port>\n" -> "OK <host_port>\n".
	if _, err := fmt.Fprintf(c, "CONNECT %d\n", guestPort); err != nil {
		fmt.Fprintln(os.Stderr, "connect write:", err)
		os.Exit(1)
	}
	r := bufio.NewReader(c)
	status, err := r.ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr, "handshake read:", err)
		os.Exit(1)
	}
	if len(status) < 2 || status[:2] != "OK" {
		fmt.Fprintf(os.Stderr, "handshake refused: %q\n", status)
		os.Exit(1)
	}

	req := request{Op: "start", Cmd: cmd, Env: env, Cols: 120, Rows: 40}
	if err := json.NewEncoder(c).Encode(&req); err != nil { // writes the JSON line + '\n'
		fmt.Fprintln(os.Stderr, "send request:", err)
		os.Exit(1)
	}

	go func() { _, _ = io.Copy(c, os.Stdin) }()
	_, _ = io.Copy(os.Stdout, r)
}
