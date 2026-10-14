//go:build linux

// Command interpose-guest is the in-VM agent that interpose-sandbox drives over
// Firecracker vsock. It runs INSIDE the sandbox microVM (baked into the rootfs,
// started at boot) and:
//
//   - listens on vsock port 1024;
//   - on "start", launches `interpose run <agent>` in a PTY (so the agent is
//     gated by the in-VM BPF-LSM enforcer) and keeps it alive with a scrollback
//     buffer even when nobody is attached;
//   - on "attach", replays scrollback then streams the live PTY both ways — this
//     is what the operator's embedded terminal renders;
//   - "list" / "stop" manage sessions.
//
// The connection carries newline-JSON control (vsockproto) then raw PTY bytes.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"

	"github.com/creack/pty"
	"github.com/mdlayher/vsock"

	"github.com/interposed/interpose-sandbox/internal/vsockproto"
)

const scrollCap = 64 << 10 // per-session scrollback cap

type session struct {
	id     string
	kind   string
	cmd    *exec.Cmd
	ptmx   *os.File
	mu     sync.Mutex
	scroll []byte
	out    io.Writer // currently-attached writer, or nil
	status string    // running | exited
}

// feed appends PTY bytes to scrollback (bounded) and to the attached writer.
func (s *session) feed(p []byte) {
	s.mu.Lock()
	s.scroll = append(s.scroll, p...)
	if len(s.scroll) > scrollCap {
		s.scroll = s.scroll[len(s.scroll)-scrollCap:]
	}
	w := s.out
	s.mu.Unlock()
	if w != nil {
		_, _ = w.Write(p)
	}
}

var (
	reg  = map[string]*session{}
	regM sync.Mutex
	seq  int
)

func main() {
	l, err := vsock.Listen(vsockproto.Port, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "interpose-guest: vsock listen:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "interpose-guest: listening on vsock:%d\n", vsockproto.Port)
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go handle(c)
	}
}

func handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	line, err := br.ReadBytes('\n')
	if err != nil {
		return
	}
	var req vsockproto.Request
	if err := json.Unmarshal(line, &req); err != nil {
		reply(c, vsockproto.Reply{Error: "bad request"})
		return
	}
	switch req.Op {
	case "start":
		doStart(c, br, req)
	case "attach":
		doAttach(c, br, req)
	case "list":
		doList(c)
	case "stop":
		doStop(c, req)
	default:
		reply(c, vsockproto.Reply{Error: "unknown op " + req.Op})
	}
}

func doStart(c net.Conn, in *bufio.Reader, req vsockproto.Request) {
	name := req.Agent
	if name == "" {
		name = "shell"
	}
	// Gate the agent through the in-VM enforcer. "shell" drops to a raw /bin/sh
	// (the sandbox itself is the boundary); named agents run under interpose.
	var cmd *exec.Cmd
	if name == "shell" {
		cmd = exec.Command("/bin/sh")
	} else {
		cmd = exec.Command("interpose", "run", name)
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		reply(c, vsockproto.Reply{Error: "start pty: " + err.Error()})
		return
	}
	regM.Lock()
	seq++
	id := fmt.Sprintf("ag-%d", seq)
	s := &session{id: id, kind: name, cmd: cmd, ptmx: ptmx, status: "running"}
	reg[id] = s
	regM.Unlock()

	// Drain the PTY forever (keeps the agent unblocked with scrollback even when
	// detached); mark exited when the agent ends.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				s.feed(buf[:n])
			}
			if err != nil {
				s.mu.Lock()
				s.status = "exited"
				s.mu.Unlock()
				return
			}
		}
	}()

	reply(c, vsockproto.Reply{OK: true, ID: id})
	streamAttached(c, in, s) // this first connection is attached until it drops
}

func doAttach(c net.Conn, in *bufio.Reader, req vsockproto.Request) {
	regM.Lock()
	s := reg[req.ID]
	regM.Unlock()
	if s == nil {
		reply(c, vsockproto.Reply{Error: "no such agent " + req.ID})
		return
	}
	reply(c, vsockproto.Reply{OK: true, ID: s.id})
	// Replay scrollback so the operator sees context, then go live.
	s.mu.Lock()
	back := append([]byte(nil), s.scroll...)
	s.mu.Unlock()
	_, _ = c.Write(back)
	streamAttached(c, in, s)
}

// streamAttached wires this connection as the session's live terminal: PTY
// output flows to the conn (via feed's s.out), conn input flows to the PTY.
// Returns when the conn drops; the agent keeps running (detached).
func streamAttached(c net.Conn, in *bufio.Reader, s *session) {
	s.mu.Lock()
	s.out = c
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.out == c {
			s.out = nil
		}
		s.mu.Unlock()
	}()
	// Forward operator keystrokes (buffered remainder + live) to the PTY.
	_, _ = io.Copy(s.ptmx, in)
}

func doList(c net.Conn) {
	regM.Lock()
	out := make([]vsockproto.AgentInfo, 0, len(reg))
	for _, s := range reg {
		s.mu.Lock()
		out = append(out, vsockproto.AgentInfo{ID: s.id, Kind: s.kind, Status: s.status})
		s.mu.Unlock()
	}
	regM.Unlock()
	reply(c, vsockproto.Reply{OK: true, Agents: out})
}

func doStop(c net.Conn, req vsockproto.Request) {
	regM.Lock()
	s := reg[req.ID]
	delete(reg, req.ID)
	regM.Unlock()
	if s == nil {
		reply(c, vsockproto.Reply{Error: "no such agent " + req.ID})
		return
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	_ = s.ptmx.Close()
	reply(c, vsockproto.Reply{OK: true, ID: req.ID})
}

func reply(c net.Conn, r vsockproto.Reply) {
	b, _ := json.Marshal(r)
	_, _ = c.Write(append(b, '\n'))
}
