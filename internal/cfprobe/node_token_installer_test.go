package cfprobe

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fixtureShell(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return "D:/Extra_Downloads/APPs/Git/bin/bash.exe"
	}
	path, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNodeTokenShellInstallerPrivateStaging(t *testing.T) {
	data, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.ReplaceAll(string(data), "\r\n", "\n")
	start := strings.Index(source, "run_payload() {")
	end := strings.Index(source[start:], "\nrun_payload_checked()")
	for _, tc := range []struct {
		name, osName, supported, flags string
		ok                             bool
	}{
		{"monitor", "darwin", "1", "--install-node-token=$TOKEN -terminal=0", true},
		{"terminal", "linux", "1", "-token=$TOKEN -terminal=1", true},
		{"obsolete", "linux", "0", "--install-node-token=$TOKEN", false},
		{"legacy", "linux", "1", "-secret=$TOKEN", false},
		{"noexec", "linux", "126", "--install-node-token=$TOKEN", false},
		{"mac-terminal", "darwin", "1", "--install-node-token=$TOKEN -terminal=1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.ToSlash(t.TempDir())
			payload := filepath.Join(dir, "payload")
			stub := `#!/bin/sh
if [ "$SUPPORTED" = 126 ]; then exit 126; fi
if [ "$1" = help ]; then [ "$SUPPORTED" = 0 ] || printf '%s\n' ' -token-file=PATH' ' -register-key=KEY'; exit 0; fi
printf '%s\n' "$@" > "$RESULT/args"
for arg do case "$arg" in -token-file=*) f=${arg#*=}; cat "$f" > "$RESULT/token"; printf '%s' "$f" > "$RESULT/path" ;; esac; done
exit "${PAYLOAD_CODE:-0}"
`
			if err := os.WriteFile(payload, []byte(stub), 0700); err != nil {
				t.Fatal(err)
			}
			value := ""
			if strings.Contains(tc.flags, "--install-node-token=") {
				value = testNodeToken
			}
			script := "set -eu; umask 077; die(){ echo error >&2; exit 1; }; os_name=" + tc.osName + "; cmd=install; INSTALL_NODE_TOKEN='" + value + "'\n" + source[start:start+end] + "\nrun_payload \"$PAYLOAD\" install " + tc.flags
			if tc.name == "terminal" {
				// A non-executable /tmp triggers another run with the original arguments.
				script = "set -eu; umask 077; die(){ echo error >&2; exit 1; }; os_name=linux; cmd=install; INSTALL_NODE_TOKEN=''\n" + source[start:start+end] + "\nPAYLOAD_CODE=126; export PAYLOAD_CODE; if run_payload \"$PAYLOAD\" install " + tc.flags + "; then exit 1; else [ $? = 126 ]; fi\nPAYLOAD_CODE=0; export PAYLOAD_CODE; run_payload \"$PAYLOAD\" install " + tc.flags
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, fixtureShell(t), "-c", script)
			cmd.Env = append(os.Environ(), "PAYLOAD="+filepath.ToSlash(payload), "RESULT="+dir, "SUPPORTED="+tc.supported, "TOKEN="+testNodeToken, "TMPDIR="+dir)
			output, err := cmd.CombinedOutput()
			if (err == nil) != tc.ok {
				t.Fatalf("installer success=%v want %v: %s", err == nil, tc.ok, output)
			}
			if strings.Contains(string(output), testNodeToken) {
				t.Fatal("installer logged token")
			}
			if !tc.ok {
				return
			}
			args, _ := os.ReadFile(filepath.Join(dir, "args"))
			if strings.Contains(string(args), testNodeToken) || strings.Contains(string(args), "--install-node-token=") {
				t.Fatal("token reached binary command line")
			}
			token, _ := os.ReadFile(filepath.Join(dir, "token"))
			if string(token) != testNodeToken {
				t.Fatal("staged token missing")
			}
			path, _ := os.ReadFile(filepath.Join(dir, "path"))
			if _, err := os.Stat(string(path)); !os.IsNotExist(err) {
				t.Fatal("staged file left behind")
			}
		})
	}
}

func TestNodeTokenDockerEntrypointFailBeforeConfigMutation(t *testing.T) {
	source, err := os.ReadFile("../../entrypoint.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, initial, token, url string
		ok                        bool
	}{
		{"first", "", testNodeToken, "https://example.com/update", true},
		{"bad-token", "REPORT_INTERVAL=123\n", "bad", "https://example.com/update", false},
		{"plaintext", "REPORT_INTERVAL=123\n", testNodeToken, "http://127.0.0.1/update", false},
		{"legacy-no-token", "SECRET=old\nREPORT_INTERVAL=123\n", "", "https://example.com/update", false},
		{"legacy-explicit-token", "SECRET=old\nTERMINAL_TOKEN=obsolete\nREPORT_INTERVAL=123\nUA=old/1\n", testNodeToken, "https://example.com/update", true},
		{"injected-url", "REPORT_INTERVAL=123\n", testNodeToken, "https://example.com/update\nSECRET=bad", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			config := filepath.Join(dir, "config.conf")
			if tc.initial != "" {
				if err := os.WriteFile(config, []byte(tc.initial), 0600); err != nil {
					t.Fatal(err)
				}
			}
			stub := filepath.ToSlash(filepath.Join(dir, "payload"))
			if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
				t.Fatal(err)
			}
			body := strings.ReplaceAll(string(source), "\r\n", "\n")
			body = strings.Replace(body, "BIN=\"/app/cf-probe\"", "BIN=\""+stub+"\"", 1)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, fixtureShell(t), "-c", body)
			cmd.Env = append(os.Environ(), "CF_PROBE_DATA_DIR="+filepath.ToSlash(dir), "SERVER_ID=node", "WORKER_URL="+tc.url, "UA=new/2")
			if tc.token != "" {
				cmd.Env = append(cmd.Env, "NODE_TOKEN="+tc.token)
			}
			output, err := cmd.CombinedOutput()
			if (err == nil) != tc.ok {
				t.Fatalf("success=%v want %v: %s", err == nil, tc.ok, output)
			}
			got, _ := os.ReadFile(config)
			if !tc.ok {
				if string(got) != tc.initial {
					t.Fatal("failed entrypoint overwrote working config")
				}
				return
			}
			if strings.Contains(string(got), "SECRET=") || strings.Contains(string(got), "TERMINAL_TOKEN=") || !strings.Contains(string(got), "NODE_TOKEN=\""+testNodeToken+"\"") {
				t.Fatal("Docker credential migration failed")
			}
			if !strings.Contains(string(got), "AUTO_UPDATE=\"0\"") || !strings.Contains(string(got), "TERMINAL_ENABLED=\"0\"") {
				t.Fatal("Docker enabled terminal or auto-update")
			}
			if tc.name == "legacy-explicit-token" && (!strings.Contains(string(got), "REPORT_INTERVAL=123") || !strings.Contains(string(got), "UA=old/1")) {
				t.Fatal("Docker lost volume collection/UA state")
			}
		})
	}
}

func TestNodeTokenPowerShellInstallerPrivateStaging(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows ACL test")
	}
	data, err := os.ReadFile("../../install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	start := strings.Index(source, "function Test-PrivateNodeTokenParent")
	end := strings.Index(source[start:], "$command =")
	dir := t.TempDir()
	script := filepath.Join(dir, "fixture.ps1")
	pathFile := filepath.Join(dir, "path")
	body := source[start:start+end] + "\n$f=New-PrivateNodeTokenFile '" + testNodeToken + "'\n[IO.File]::WriteAllText('" + pathFile + "',$f)\n$argsOut=@(Get-PayloadArguments @('install','--install-node-token=unused','-terminal=0') $true $f)\nif ($argsOut -contains '--install-node-token=unused' -or -not ($argsOut -contains ('-token-file='+$f))) { throw 'payload mismatch' }\n"
	if err := os.WriteFile(script, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script)
	// Do not hand Windows PowerShell 5 the host pwsh 7 module search path.
	for _, env := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(env), "PSMODULEPATH=") {
			cmd.Env = append(cmd.Env, env)
		}
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("PS private staging: %v\n%s", err, output)
	}
	path, err := os.ReadFile(pathFile)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(filepath.Dir(string(path)))
	got, err := readNodeTokenFile(string(path))
	if err != nil || got != testNodeToken {
		t.Fatal("PowerShell token ACL/bytes", err)
	}
}
