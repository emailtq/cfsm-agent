//go:build linux

package cfprobe

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseWorkflowPublication(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.ReplaceAll(string(data), "\r\n", "\n")
	start := strings.LastIndex(source, "        run:")
	if start < 0 {
		t.Fatal("release script missing")
	}
	lines := strings.Split(source[start:], "\n")
	script := ""
	if strings.Contains(lines[0], "run: |") {
		for _, line := range lines[1:] {
			if strings.HasPrefix(line, "          ") {
				script += strings.TrimPrefix(line, "          ") + "\n"
			}
		}
	} else {
		script = strings.TrimPrefix(lines[0], "        run: ")
	}
	// The hosted runner resolves workflow expressions before invoking bash.
	script = strings.ReplaceAll(script, "${{ github.event.release.tag_name }}", "v1.1.4")
	script = strings.ReplaceAll(script, "${{ github.repository }}", "emailtq/cfsm-agent")
	for _, tc := range []struct {
		name, event, fail, existing string
		want                        []string
		ok                          bool
	}{
		{"tag", "push", "", "", []string{"create", "upload", "edit"}, true},
		{"published", "release", "", "", []string{"upload"}, true},
		{"create-failure", "push", "create", "", []string{"create"}, false},
		{"upload-failure", "push", "upload", "", []string{"create", "upload"}, false},
		{"retry-draft", "push", "", "true", []string{"upload", "edit"}, true},
		{"existing-published", "push", "", "false", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "dist"), 0700); err != nil {
				t.Fatal(err)
			}
			for _, file := range []string{"cf-probe-linux-amd64", "checksums.txt"} {
				if err := os.WriteFile(filepath.Join(dir, "dist", file), []byte("synthetic"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			fake := `#!/bin/sh
if [ "$2" = view ]; then
  [ "$1" = release ] && [ "$3" = v1.1.4 ] || exit 2
  [ -n "$EXISTING" ] || exit 1
  printf '%s\n' "$EXISTING"
  exit 0
fi
printf '%s\n' "$*" >> "$RESULT"
[ "$1" = release ] && [ "$3" = v1.1.4 ] || exit 2
case " $* " in *' --repo emailtq/cfsm-agent '*) ;; *) exit 3 ;; esac
[ "$2" != "$FAIL" ] || exit 7
`
			if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(fake), 0700); err != nil {
				t.Fatal(err)
			}
			result := filepath.Join(dir, "calls")
			cmd := exec.Command("bash", "-c", script)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "RESULT="+result, "FAIL="+tc.fail, "EXISTING="+tc.existing, "VERSION=v1.1.4", "GITHUB_REF_NAME=v1.1.4", "GITHUB_REPOSITORY=emailtq/cfsm-agent", "GITHUB_EVENT_NAME="+tc.event)
			output, err := cmd.CombinedOutput()
			if (err == nil) != tc.ok {
				t.Fatalf("success=%v want %v: %s", err == nil, tc.ok, output)
			}
			calls, _ := os.ReadFile(result)
			var observed []string
			if len(calls) > 0 {
				observed = strings.Split(strings.TrimSpace(string(calls)), "\n")
			}
			if len(observed) != len(tc.want) {
				t.Fatalf("calls=%q want %v", observed, tc.want)
			}
			for i, want := range tc.want {
				if !strings.HasPrefix(observed[i], "release "+want+" v1.1.4 ") {
					t.Fatalf("call=%q want %s", observed[i], want)
				}
			}
			if tc.event == "push" && tc.ok && (!strings.Contains(observed[len(observed)-1], "--draft=false") || (tc.existing == "" && (!strings.Contains(observed[0], "--draft") || !strings.Contains(observed[0], "--verify-tag")))) {
				t.Fatalf("release not draft-until-uploaded: %q", calls)
			}
		})
	}
}
