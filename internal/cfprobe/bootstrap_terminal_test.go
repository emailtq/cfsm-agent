//go:build linux

package cfprobe

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapTerminalTokenFile(t *testing.T) {
	for _, tc := range []struct {
		name, supported, flag string
		ok                    bool
	}{
		{"supported", "1", "-terminal=1", true},
		{"unsupported-on", "0", "-terminal=1", false},
		{"unsupported-off", "0", "-terminal=0", true},
		{"noexec", "126", "-terminal=1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			data, err := os.ReadFile("../../install.sh")
			if err != nil {
				t.Fatal(err)
			}
			source := strings.ReplaceAll(string(data), "\r\n", "\n")
			start := strings.Index(source, "run_payload() {")
			if start < 0 {
				t.Fatal("bootstrap function missing")
			}
			end := strings.Index(source[start:], "\nrun_payload_checked()")
			if end < 0 {
				t.Fatal("bootstrap function missing")
			}
			fake := filepath.Join(dir, "payload")
			body := `#!/bin/sh
if [ "$SUPPORTED" = 126 ]; then exit 126; fi
if [ "$1" = help ]; then [ "$SUPPORTED" = 0 ] || echo ' -terminal-token-file=PATH'; exit 0; fi
printf '%s\n' "$@" > "$RESULT/args"
for arg do case "$arg" in -terminal-token-file=*) f=${arg#*=}; cat "$f" > "$RESULT/token"; stat -c %a "$f" > "$RESULT/mode"; printf '%s' "$f" > "$RESULT/path" ;; esac; done
`
			if err := os.WriteFile(fake, []byte(body), 0700); err != nil {
				t.Fatal(err)
			}
			token := strings.Repeat("a", 64)
			value := ""
			if tc.supported == "1" {
				value = token
			}
			script := "die() { echo error >&2; exit 1; }; os_name=linux; cmd=install; INSTALL_TERMINAL_TOKEN='" + value + "'\n" + source[start:start+end] + "\nrun_payload \"$PAYLOAD\" install --install-terminal-token='" + value + "' " + tc.flag
			cmd := exec.Command("sh", "-c", script)
			cmd.Env = append(os.Environ(), "PAYLOAD="+fake, "RESULT="+dir, "SUPPORTED="+tc.supported, "TMPDIR="+dir)
			output, err := cmd.CombinedOutput()
			if (err == nil) != tc.ok {
				t.Fatalf("success=%v, want %v: %s", err == nil, tc.ok, output)
			}
			if tc.name == "noexec" {
				if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 126 {
					t.Fatalf("noexec must preserve staging fallback, got %v", err)
				}
			}
			if strings.Contains(string(output), token) {
				t.Fatal("credential was logged")
			}
			if !tc.ok {
				return
			}
			args, _ := os.ReadFile(filepath.Join(dir, "args"))
			if strings.Contains(string(args), "--install-terminal-token") {
				t.Fatal("bootstrap token option reached binary")
			}
			if tc.supported == "0" {
				if strings.Contains(string(args), "-terminal=0") {
					t.Fatal("old binary received unsupported flag")
				}
				return
			}
			got, _ := os.ReadFile(filepath.Join(dir, "token"))
			if string(got) != token {
				t.Fatal("token not delivered through file")
			}
			mode, _ := os.ReadFile(filepath.Join(dir, "mode"))
			if strings.TrimSpace(string(mode)) != "600" {
				t.Fatalf("mode=%s", mode)
			}
			file, _ := os.ReadFile(filepath.Join(dir, "path"))
			if _, err := os.Stat(string(file)); !os.IsNotExist(err) {
				t.Fatal("temporary credential file left behind")
			}
		})
	}
}
