package procbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The escape suite is the CI gate: a process under procbox.Apply must be able
// to work in its allowed dir but MUST NOT read secrets or write outside it.
// Because Apply is irreversible + self-sandboxing, each check runs in a fresh
// re-exec of the test binary (NONO_ESCAPE_CHILD), which applies the policy
// then performs one operation and exits with a distinct code.
func TestEscapeSuite(t *testing.T) {
	if b, err := Current(); err != nil {
		t.Skipf("no procbox backend available here: %v", err)
	} else {
		t.Logf("backend: %s", b.Name())
	}

	home, _ := os.UserHomeDir()
	work := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(sshDir, 0o700)
	secret := filepath.Join(sshDir, "id_nono_escape_test")
	if err := os.WriteFile(secret, []byte("TOP-SECRET"), 0o600); err != nil {
		t.Skipf("cannot stage ~/.ssh probe: %v", err)
	}
	defer os.Remove(secret)

	child := func(op string) *exec.Cmd {
		c := exec.Command(os.Args[0], "-test.run=TestEscapeSuite")
		c.Env = append(os.Environ(),
			"NONO_ESCAPE_CHILD="+op, "NONO_ESCAPE_WORK="+work, "NONO_ESCAPE_SECRET="+secret)
		return c
	}

	// 1. Allowed: work in the sandbox dir.
	if err := child("work").Run(); err != nil {
		t.Fatalf("in-sandbox work should succeed: %v", err)
	}
	// 2. Denied: read the ~/.ssh secret.
	if err := child("read-secret").Run(); err == nil {
		t.Fatal("reading ~/.ssh from the sandbox MUST fail")
	}
	// 3. Denied: write outside the declared dir.
	if err := child("write-home").Run(); err == nil {
		t.Fatal("writing outside the sandbox MUST fail")
	}
}

// TestMain runs the escape "child" ops in a sandboxed subprocess when asked.
func TestMain(m *testing.M) {
	op := os.Getenv("NONO_ESCAPE_CHILD")
	if op == "" {
		os.Exit(m.Run())
	}
	work := os.Getenv("NONO_ESCAPE_WORK")
	secret := os.Getenv("NONO_ESCAPE_SECRET")
	policy := PolicySpec{FS: FSPolicy{RW: []string{work}, DenyDefault: true}, Net: NetPolicy{Mode: NetOff}}
	if _, err := Apply(policy); err != nil {
		os.Exit(3) // no backend / apply failed — parent treats as skip via Current()
	}
	switch op {
	case "work":
		if err := os.WriteFile(filepath.Join(work, "f"), []byte("hi"), 0o600); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case "read-secret":
		if _, err := os.ReadFile(secret); err != nil {
			os.Exit(1) // correctly denied
		}
		os.Exit(0) // LEAK
	case "write-home":
		home, _ := os.UserHomeDir()
		if err := os.WriteFile(filepath.Join(home, ".nono_escape_probe"), []byte("x"), 0o600); err != nil {
			os.Exit(1) // correctly denied
		}
		os.Remove(filepath.Join(home, ".nono_escape_probe"))
		os.Exit(0) // LEAK
	}
	os.Exit(0)
}
