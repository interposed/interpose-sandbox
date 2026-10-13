// Package pool is the capacity manager for cells: it turns one host into a
// bounded sandbox service. Callers submit jobs; the pool runs at most
// MaxConcurrent cells at once, queuing the rest, applies a default resource
// budget to cells that don't set their own, and emits lifecycle events for the
// governance/observability seam (the operator reads these).
//
// The pool is the "runner is a scheduler" piece of the sovereign sandbox
// primitive. It is isolation-backend agnostic: it drives cell.Run by default,
// but the Runner is injectable so the scheduling logic is testable without a
// sandbox backend, and so a later microVM backend can slot in unchanged.
package pool

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/interposed/interpose-sandbox/pkg/cell"
)

// Runner executes one cell to completion. Defaults to cell.Run.
type Runner func(ctx context.Context, spec cell.Spec) (cell.Result, error)

// Phase is a point in a cell's lifecycle.
type Phase string

const (
	PhaseQueued   Phase = "queued"
	PhaseStarted  Phase = "started"
	PhaseFinished Phase = "finished"
)

// Event is emitted at each lifecycle transition (nil-safe to ignore).
type Event struct {
	CellID string
	Phase  Phase
	At     time.Time
	Result *cell.Result // set on finished
	Err    error        // set on finished when the run failed to start/complete
}

// Config configures a Pool.
type Config struct {
	MaxConcurrent int         // max cells running at once; <1 means 1
	DefaultLimits cell.Limits // applied to a job whose Limits are the zero value
	OnEvent       func(Event) // optional lifecycle hook
	Runner        Runner      // optional; defaults to cell.Run
}

// Stats is a snapshot of pool activity.
type Stats struct {
	MaxConcurrent int
	Active        int   // cells running now
	Waiting       int   // callers blocked waiting for a slot
	Completed     int64 // cells that finished (any exit code)
	Failed        int64 // cells whose run returned an error (setup/exec failure)
}

// Pool bounds concurrent cell execution.
type Pool struct {
	cfg    Config
	runner Runner
	sem    chan struct{}

	active    int64
	waiting   int64
	completed int64
	failed    int64

	mu      sync.Mutex
	running map[string]time.Time // cellID -> started-at, for observability
}

// New builds a Pool.
func New(cfg Config) *Pool {
	if cfg.MaxConcurrent < 1 {
		cfg.MaxConcurrent = 1
	}
	runner := cfg.Runner
	if runner == nil {
		runner = cell.Run
	}
	return &Pool{
		cfg:     cfg,
		runner:  runner,
		sem:     make(chan struct{}, cfg.MaxConcurrent),
		running: make(map[string]time.Time),
	}
}

// Run submits a cell and blocks until it finishes. It first waits (honoring
// ctx) for a concurrency slot, then runs the cell. A cell that runs and exits
// non-zero returns a Result with that ExitCode and a nil error; a nil error
// does not mean the job succeeded, only that it ran - check Result.ExitCode.
func (p *Pool) Run(ctx context.Context, spec cell.Spec) (cell.Result, error) {
	if spec.Limits == (cell.Limits{}) {
		spec.Limits = p.cfg.DefaultLimits
	}
	p.emit(Event{CellID: spec.ID, Phase: PhaseQueued, At: time.Now()})

	atomic.AddInt64(&p.waiting, 1)
	select {
	case p.sem <- struct{}{}:
		atomic.AddInt64(&p.waiting, -1)
	case <-ctx.Done():
		atomic.AddInt64(&p.waiting, -1)
		return cell.Result{}, ctx.Err()
	}
	defer func() { <-p.sem }()

	atomic.AddInt64(&p.active, 1)
	p.mu.Lock()
	p.running[spec.ID] = time.Now()
	p.mu.Unlock()
	p.emit(Event{CellID: spec.ID, Phase: PhaseStarted, At: time.Now()})

	res, err := p.runner(ctx, spec)

	atomic.AddInt64(&p.active, -1)
	atomic.AddInt64(&p.completed, 1)
	if err != nil {
		atomic.AddInt64(&p.failed, 1)
	}
	p.mu.Lock()
	delete(p.running, spec.ID)
	p.mu.Unlock()
	p.emit(Event{CellID: spec.ID, Phase: PhaseFinished, At: time.Now(), Result: &res, Err: err})
	return res, err
}

// Stats returns a snapshot.
func (p *Pool) Stats() Stats {
	return Stats{
		MaxConcurrent: p.cfg.MaxConcurrent,
		Active:        int(atomic.LoadInt64(&p.active)),
		Waiting:       int(atomic.LoadInt64(&p.waiting)),
		Completed:     atomic.LoadInt64(&p.completed),
		Failed:        atomic.LoadInt64(&p.failed),
	}
}

// Running returns the ids of cells running right now.
func (p *Pool) Running() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.running))
	for id := range p.running {
		out = append(out, id)
	}
	return out
}

func (p *Pool) emit(e Event) {
	if p.cfg.OnEvent != nil {
		p.cfg.OnEvent(e)
	}
}

// ErrClosed is reserved for a future Close() path.
var ErrClosed = errors.New("pool: closed")
