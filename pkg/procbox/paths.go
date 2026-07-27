package procbox

import (
	"os"
	"path/filepath"
	"strings"
)

// existing filters a path list to those that actually exist on disk —
// Landlock rejects a ruleset that references a missing path, so we drop
// them (a policy naming an absent dir just means "nothing to allow there").
func existing(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		p = expand(p)
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// expand resolves $HOME / ~ and $CWD so profiles stay portable across
// machines and users.
func expand(p string) string {
	if p == "." || p == "./" {
		if cwd, err := os.Getwd(); err == nil {
			return cwd
		}
	}
	if strings.HasPrefix(p, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return os.ExpandEnv(p)
}

// isDir reports whether path is a directory (expanded).
func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// dirsOnly / filesOnly split a path list by kind — Landlock's RODirs/RWDirs
// take directories, ROFiles/RWFiles take files.
func dirsOnly(paths []string) []string {
	var out []string
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

func filesOnly(paths []string) []string {
	var out []string
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// runtimePaths expands runtime group names (node, python, go, rust) into the
// standard read paths those toolchains need: interpreters, caches, module
// dirs. Kept intentionally broad-but-read-only so agents can run their tools
// without hand-listing every path. Missing paths are dropped by existing().
func runtimePaths(runtimes []string) []string {
	var out []string
	for _, r := range runtimes {
		switch strings.ToLower(strings.TrimSpace(r)) {
		case "node":
			out = append(out, "~/.npm", "~/.node-gyp", "~/.nvm", "/usr/local/lib/node_modules", "/opt/homebrew/lib/node_modules")
		case "python":
			out = append(out, "~/.cache/pip", "~/.pyenv", "/usr/lib/python3", "/opt/homebrew/lib/python3.12")
		case "go":
			out = append(out, "~/go/pkg/mod", "~/.cache/go-build", "/usr/local/go", "/opt/homebrew/Cellar/go")
		case "rust":
			out = append(out, "~/.cargo", "~/.rustup")
		}
	}
	return existing(out)
}
