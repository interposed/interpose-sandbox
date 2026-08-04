package main

import "testing"

// parseWinch is the sole decision in the local-PTY window-resize path: it turns a
// "rows cols" control line from the daemon into a validated Winsize, or rejects it.
// A malformed or out-of-range frame must NOT drive the PTY to a degenerate size.
func TestParseWinchAcceptsSaneSize(t *testing.T) {
	ws, ok := parseWinch("40 120")
	if !ok {
		t.Fatal("40 120 should parse")
	}
	if ws.Rows != 40 || ws.Cols != 120 {
		t.Fatalf("got rows=%d cols=%d, want 40x120", ws.Rows, ws.Cols)
	}
}

func TestParseWinchRejectsBadFrames(t *testing.T) {
	// Each of these must be dropped: applying any of them would collapse or blow
	// out the TUI's layout, which is exactly what leaves the operator's controls
	// looking unresponsive.
	bad := []string{
		"",           // empty
		"40",         // one field
		"40 120 3",   // three fields
		"0 120",      // zero rows
		"40 0",       // zero cols
		"-1 80",      // negative
		"x y",        // non-numeric
		"40  120  ",  // handled by Fields, but confirm trailing space is fine
		"3000 80",    // rows over ceiling
		"40 5000",    // cols over ceiling
	}
	for _, in := range bad {
		if in == "40  120  " {
			// This one is actually VALID (Fields collapses spaces) — assert that,
			// so the table stays honest about what the boundary is.
			if _, ok := parseWinch(in); !ok {
				t.Errorf("%q should parse (Fields collapses whitespace)", in)
			}
			continue
		}
		if ws, ok := parseWinch(in); ok {
			t.Errorf("%q should be rejected, got %v", in, ws)
		}
	}
}

func TestParseWinchAtBounds(t *testing.T) {
	if _, ok := parseWinch("1 1"); !ok {
		t.Error("1 1 is the minimum valid size, should parse")
	}
	if _, ok := parseWinch("2000 2000"); !ok {
		t.Error("2000 2000 is the ceiling, should parse")
	}
	if _, ok := parseWinch("2001 2000"); ok {
		t.Error("2001 rows is past the ceiling, should be rejected")
	}
}
