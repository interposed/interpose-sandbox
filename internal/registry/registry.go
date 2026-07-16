// Package registry is the persisted state of background sandboxes and the
// agents running inside them. Every interpose-sandbox invocation is a separate
// process, so the source of truth lives on disk (registry.json) rather than in
// memory. `new` adds an entry, `ls` reads them, `rm`/`pause`/`resume`/`exec`/
// `agent` mutate them.
//
// Concurrency: the daemon serializes mutations (each Sandbox.* call runs under
// gatedMutation, one at a time), and interactive CLI use is single-operator, so
// a per-process mutex + atomic rename is sufficient today. TODO: flock the file
// if we ever drive it from multiple concurrent writers.
package registry

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrNotFound is returned by Get/Update/Remove for an unknown sandbox id.
var ErrNotFound = errors.New("sandbox not found")

// Agent is a gated session inside a sandbox.
type Agent struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`   // pi | claude | codex | opencode
	Status    string    `json:"status"` // booting | ready | paused
	CreatedAt time.Time `json:"created_at"`
	Approvals int       `json:"approvals"`
	Last      string    `json:"last,omitempty"`
}

// Sandbox is one gated microVM's persisted state.
type Sandbox struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"` // booting | ready | paused | stopped
	Profile   string    `json:"profile"`
	Workspace string    `json:"workspace,omitempty"`
	StateDir  string    `json:"state_dir"`
	APISock   string    `json:"api_sock"`
	VsockUDS  string    `json:"vsock_uds"` // firecracker vsock UDS, for the guest-agent
	PID       int       `json:"pid"`       // firecracker process, for rm/liveness
	CreatedAt time.Time `json:"created_at"`
	Agents    []Agent   `json:"agents"`
}

// Store is a file-backed sandbox registry.
type Store struct {
	path string
	mu   sync.Mutex
}

// Open returns a Store backed by <dir>/registry.json, creating dir if needed.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{path: filepath.Join(dir, "registry.json")}, nil
}

func (s *Store) load() ([]Sandbox, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) || len(b) == 0 {
		return []Sandbox{}, nil
	}
	if err != nil {
		return nil, err
	}
	var list []Sandbox
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (s *Store) save(list []Sandbox) error {
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path) // atomic replace
}

// List returns all sandboxes.
func (s *Store) List() ([]Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

// Add appends a new sandbox.
func (s *Store) Add(sb Sandbox) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load()
	if err != nil {
		return err
	}
	list = append(list, sb)
	return s.save(list)
}

// Get returns the sandbox with id, or (,false,) if absent.
func (s *Store) Get(id string) (Sandbox, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load()
	if err != nil {
		return Sandbox{}, false, err
	}
	for _, sb := range list {
		if sb.ID == id {
			return sb, true, nil
		}
	}
	return Sandbox{}, false, nil
}

// Update applies fn to the sandbox with id and persists the result.
func (s *Store) Update(id string, fn func(*Sandbox) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load()
	if err != nil {
		return err
	}
	for i := range list {
		if list[i].ID == id {
			if err := fn(&list[i]); err != nil {
				return err
			}
			return s.save(list)
		}
	}
	return ErrNotFound
}

// Remove deletes the sandbox with id.
func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load()
	if err != nil {
		return err
	}
	out := make([]Sandbox, 0, len(list))
	found := false
	for _, sb := range list {
		if sb.ID == id {
			found = true
			continue
		}
		out = append(out, sb)
	}
	if !found {
		return ErrNotFound
	}
	return s.save(out)
}
