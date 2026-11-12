//go:build !windows

package cfprobe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNodeTokenExplicitReinstallWorldReadableLegacyConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.conf")
	traffic := filepath.Join(dir, "traffic.dat")
	old := []byte("SECRET=old\nWORKER_URL=https://untrusted.invalid/update\nTERMINAL_ENABLED=1\n")
	if err := os.WriteFile(path, old, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(traffic, []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	existing, _, err := readInstallConfig(Paths{ConfigFile: path})
	if err == nil || existing.WorkerURL != "" {
		t.Fatal("untrusted legacy bytes were read")
	}
	opts := InstallOptions{Config: Config{NodeToken: testNodeToken, WorkerURL: "https://example.com/update", ServerID: "node"}, Explicit: map[string]bool{"token": true, "url": true, "id": true}}
	if err := prepareInstallCredentials(&opts, existing, err); err != nil {
		t.Fatal(err)
	}
	if opts.TerminalEnabled {
		t.Fatal("recovery preserved untrusted consent")
	}
	if err := writeConfig(path, opts.Config); err != nil {
		t.Fatal(err)
	}
	if cfg, err := readConfig(path); err != nil || cfg.NodeToken != testNodeToken {
		t.Fatal("migration did not recover", err)
	}
	data, _ := os.ReadFile(traffic)
	if string(data) != "retained" {
		t.Fatal("traffic changed")
	}
}
