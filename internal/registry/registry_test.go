package registry

import (
	"testing"
	"time"
)

func TestStoreLifecycle(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Starts empty.
	if list, err := st.List(); err != nil || len(list) != 0 {
		t.Fatalf("empty: %v len=%d", err, len(list))
	}

	// Add.
	if err := st.Add(Sandbox{ID: "sb1", Name: "auth", Status: "ready", Profile: "claude-code", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.List(); len(list) != 1 || list[0].ID != "sb1" {
		t.Fatalf("add: %+v", list)
	}

	// Get present + absent.
	if got, ok, err := st.Get("sb1"); err != nil || !ok || got.Name != "auth" {
		t.Fatalf("get present: %v %v %+v", err, ok, got)
	}
	if _, ok, _ := st.Get("nope"); ok {
		t.Fatal("get absent returned ok")
	}

	// Update: drop an agent in.
	if err := st.Update("sb1", func(s *Sandbox) error {
		s.Agents = append(s.Agents, Agent{ID: "ag1", Kind: "codex", Status: "ready"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := st.Get("sb1"); len(got.Agents) != 1 || got.Agents[0].Kind != "codex" {
		t.Fatalf("update: %+v", got)
	}
	if err := st.Update("nope", func(*Sandbox) error { return nil }); err != ErrNotFound {
		t.Fatalf("update absent: want ErrNotFound, got %v", err)
	}

	// Persists across reopen (separate process simulation).
	st2, _ := Open(dir)
	if list, _ := st2.List(); len(list) != 1 || len(list[0].Agents) != 1 {
		t.Fatalf("persist: %+v", list)
	}

	// Remove present + absent.
	if err := st.Remove("sb1"); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.List(); len(list) != 0 {
		t.Fatalf("remove: %+v", list)
	}
	if err := st.Remove("sb1"); err != ErrNotFound {
		t.Fatalf("remove absent: want ErrNotFound, got %v", err)
	}
}
