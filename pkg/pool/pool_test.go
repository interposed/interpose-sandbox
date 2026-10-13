package pool

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/interposed/interpose-sandbox/pkg/cell"
)

// The pool must never run more than MaxConcurrent cells at once.
func TestPoolRespectsConcurrencyBound(t *testing.T) {
	const max = 3
	var cur, peak int64
	fake := func(ctx context.Context, spec cell.Spec) (cell.Result, error) {
		n := atomic.AddInt64(&cur, 1)
		for {
			p := atomic.LoadInt64(&peak)
			if n <= p || atomic.CompareAndSwapInt64(&peak, p, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		atomic.AddInt64(&cur, -1)
		return cell.Result{ExitCode: 0}, nil
	}
	p := New(Config{MaxConcurrent: max, Runner: fake})

	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = p.Run(context.Background(), cell.Spec{ID: "c"}) }()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&peak); got > max {
		t.Fatalf("peak concurrency %d exceeded max %d", got, max)
	}
	if st := p.Stats(); st.Completed != 30 {
		t.Fatalf("completed = %d, want 30", st.Completed)
	}
}

// A job with no Limits inherits the pool's DefaultLimits.
func TestPoolAppliesDefaultLimits(t *testing.T) {
	want := cell.Limits{PidsMax: 128, MemMaxBytes: 256 << 20}
	var gotLimits cell.Limits
	fake := func(ctx context.Context, spec cell.Spec) (cell.Result, error) {
		gotLimits = spec.Limits
		return cell.Result{}, nil
	}
	p := New(Config{MaxConcurrent: 1, DefaultLimits: want, Runner: fake})
	if _, err := p.Run(context.Background(), cell.Spec{ID: "c"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if gotLimits != want {
		t.Fatalf("default limits not applied: got %+v want %+v", gotLimits, want)
	}

	// An explicit Limits is left untouched.
	explicit := cell.Limits{PidsMax: 7}
	if _, err := p.Run(context.Background(), cell.Spec{ID: "c2", Limits: explicit}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if gotLimits != explicit {
		t.Fatalf("explicit limits overridden: got %+v want %+v", gotLimits, explicit)
	}
}

// Lifecycle events fire in order, and a failed run is counted.
func TestPoolEmitsLifecycleAndCountsFailures(t *testing.T) {
	var mu sync.Mutex
	phases := map[string][]Phase{}
	fake := func(ctx context.Context, spec cell.Spec) (cell.Result, error) {
		if spec.ID == "bad" {
			return cell.Result{ExitCode: -1}, errors.New("boom")
		}
		return cell.Result{ExitCode: 0}, nil
	}
	p := New(Config{MaxConcurrent: 2, Runner: fake, OnEvent: func(e Event) {
		mu.Lock()
		phases[e.CellID] = append(phases[e.CellID], e.Phase)
		mu.Unlock()
	}})

	_, _ = p.Run(context.Background(), cell.Spec{ID: "ok"})
	_, err := p.Run(context.Background(), cell.Spec{ID: "bad"})
	if err == nil {
		t.Fatal("expected error from failing run")
	}

	want := []Phase{PhaseQueued, PhaseStarted, PhaseFinished}
	mu.Lock()
	defer mu.Unlock()
	for _, id := range []string{"ok", "bad"} {
		if got := phases[id]; len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
			t.Fatalf("cell %s phases = %v, want %v", id, got, want)
		}
	}
	if st := p.Stats(); st.Failed != 1 {
		t.Fatalf("failed = %d, want 1", st.Failed)
	}
}

// Waiting for a slot honors context cancellation.
func TestPoolRunCancelWhileQueued(t *testing.T) {
	block := make(chan struct{})
	fake := func(ctx context.Context, spec cell.Spec) (cell.Result, error) {
		<-block // hold the single slot
		return cell.Result{}, nil
	}
	p := New(Config{MaxConcurrent: 1, Runner: fake})
	go func() { _, _ = p.Run(context.Background(), cell.Spec{ID: "holder"}) }()
	time.Sleep(10 * time.Millisecond) // let holder take the slot

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Run(ctx, cell.Spec{ID: "queued"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	close(block)
}
