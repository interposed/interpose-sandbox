// Package vsockproto is the tiny control protocol between the interpose-sandbox
// host CLI and the in-VM guest-agent, carried over Firecracker vsock.
//
// Framing: one newline-delimited JSON control message in each direction, then —
// after a successful "start" or "attach" — the connection switches to a raw,
// bidirectional PTY byte stream (what the operator's embedded terminal renders).
package vsockproto

// Port is the vsock port the guest-agent listens on inside the VM.
const Port = 1024

// Request is a control message from host → guest.
type Request struct {
	Op    string `json:"op"`    // "start" | "attach" | "list" | "stop"
	Agent string `json:"agent"` // for start: pi | claude | codex | opencode | shell
	ID    string `json:"id"`    // for attach/stop: the guest agent id
	Cols  int    `json:"cols,omitempty"`
	Rows  int    `json:"rows,omitempty"`
}

// Reply is the guest's response. For "start"/"attach", a Reply with OK=true is
// immediately followed by the raw PTY stream on the same connection.
type Reply struct {
	OK     bool        `json:"ok"`
	ID     string      `json:"id,omitempty"`
	Error  string      `json:"error,omitempty"`
	Agents []AgentInfo `json:"agents,omitempty"`
}

// AgentInfo is one running in-VM agent, returned by "list".
type AgentInfo struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
}
