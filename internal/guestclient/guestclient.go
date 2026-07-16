// Package guestclient is the host-side client for the in-VM interpose-guest
// agent. It reaches the guest over Firecracker's vsock UDS multiplexer: connect
// to the unix socket, do the "CONNECT <port>" handshake, then speak vsockproto.
package guestclient

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/interposehq/interpose-sandbox/internal/vsockproto"
)

// Conn is a live connection to the guest-agent. After a successful start/attach,
// Read/Write carry the raw PTY stream.
type Conn struct {
	net.Conn
	r *bufio.Reader
}

// Read pulls from the buffered reader so bytes buffered during the handshake
// aren't lost.
func (c *Conn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Dial connects to the guest-agent via the sandbox's Firecracker vsock UDS,
// sends req, and returns the connection positioned right after the guest's
// Reply. For "start"/"attach" the raw PTY stream follows on the same Conn.
func Dial(uds string, req vsockproto.Request) (*Conn, vsockproto.Reply, error) {
	raw, err := net.DialTimeout("unix", uds, 10*time.Second)
	if err != nil {
		return nil, vsockproto.Reply{}, fmt.Errorf("dial vsock uds %s: %w", uds, err)
	}
	// Firecracker host-side vsock handshake: "CONNECT <guest_port>\n" → "OK …\n".
	if _, err := fmt.Fprintf(raw, "CONNECT %d\n", vsockproto.Port); err != nil {
		raw.Close()
		return nil, vsockproto.Reply{}, err
	}
	br := bufio.NewReader(raw)
	ack, err := br.ReadString('\n')
	if err != nil {
		raw.Close()
		return nil, vsockproto.Reply{}, fmt.Errorf("vsock connect: %w", err)
	}
	if !strings.HasPrefix(ack, "OK") {
		raw.Close()
		return nil, vsockproto.Reply{}, fmt.Errorf("vsock connect rejected: %q", strings.TrimSpace(ack))
	}
	// Control request → reply.
	b, _ := json.Marshal(req)
	if _, err := raw.Write(append(b, '\n')); err != nil {
		raw.Close()
		return nil, vsockproto.Reply{}, err
	}
	line, err := br.ReadBytes('\n')
	if err != nil {
		raw.Close()
		return nil, vsockproto.Reply{}, err
	}
	var rep vsockproto.Reply
	if err := json.Unmarshal(line, &rep); err != nil {
		raw.Close()
		return nil, vsockproto.Reply{}, err
	}
	if rep.Error != "" {
		raw.Close()
		return nil, rep, fmt.Errorf("guest: %s", rep.Error)
	}
	return &Conn{Conn: raw, r: br}, rep, nil
}
