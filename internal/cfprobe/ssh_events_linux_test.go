//go:build linux

package cfprobe

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSSHJournalControlledCommandAndRecovery(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "records")
	args := filepath.Join(dir, "args")
	t.Setenv("CFSM_JOURNAL_RECORDS", data)
	t.Setenv("CFSM_JOURNAL_ARGS", args)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$CFSM_JOURNAL_ARGS\"\nif [ \"$CFSM_JOURNAL_ERROR\" != '' ]; then printf '%s\\n' \"$CFSM_JOURNAL_ERROR\" >&2; exit 1; fi\n/bin/cat \"$CFSM_JOURNAL_RECORDS\"\n"
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	record := func(cursor string) {
		t.Helper()
		body := `{"__CURSOR":"` + cursor + `","__REALTIME_TIMESTAMP":"1794830400000000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted publickey for alice from 127.0.0.1 port 50 ssh2"}` + "\n"
		if err := os.WriteFile(data, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{ServerID: "fixture", WorkerURL: "https://example.test/update", NodeToken: "fixture-identity", SSHLoginEnabled: true}
	c := newSSHEventCollector(filepath.Join(dir, "state.json"))
	now := time.Now()
	record("cursor0")
	c.collectJournal(cfg, now)
	if c.snapshot().State != "watching" || len(c.snapshot().Events) != 0 {
		t.Fatalf("baseline %+v", c.snapshot())
	}
	record("cursor1")
	c.collectJournal(cfg, now)
	if len(c.snapshot().Events) != 1 {
		t.Fatalf("journal success %+v", c.snapshot())
	}
	actual, _ := os.ReadFile(args)
	for _, arg := range []string{"--identifier=sshd\n", "--identifier=sshd-session\n", "--after-cursor=cursor0\n", "--no-tail\n"} {
		if !strings.Contains(string(actual), arg) {
			t.Fatalf("missing controlled arg %q in %s", arg, actual)
		}
	}
	c = newSSHEventCollector(filepath.Join(dir, "state.json"))
	record("cursor2")
	c.collectJournal(cfg, now)
	if len(c.snapshot().Events) != 2 {
		t.Fatal("journal restart queue lost")
	}
	t.Setenv("CFSM_JOURNAL_ERROR", "Failed to seek to cursor: Cannot assign requested address")
	c.collectJournal(cfg, now)
	if c.snapshot().State != "rotation_gap" {
		t.Fatal("vacuum gap hidden")
	}
	t.Setenv("CFSM_JOURNAL_ERROR", "")
	record("cursor3")
	c.collectJournal(cfg, now)
	if len(c.snapshot().Events) != 2 || c.snapshot().State != "rotation_gap" {
		t.Fatal("vacuum replayed old SSH")
	}
	t.Setenv("CFSM_JOURNAL_ERROR", "Hint: You are currently not seeing messages from other users and the system.")
	c.collectJournal(cfg, now)
	if c.snapshot().State != "permission_denied" {
		t.Fatal("journal permissions hidden")
	}
	initial := newSSHEventCollector(filepath.Join(dir, "initial-denied.json"))
	initial.collectJournal(cfg, now)
	if initial.snapshotForConfig(cfg).State != "permission_denied" {
		t.Fatal("initial journal denial became disabled/unavailable in actual report")
	}
}

func TestSSHPrivateStateFailureIsNotReportedAsDisabled(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	if err := os.WriteFile(state, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{ServerID: "fixture", WorkerURL: "https://example.test/update", NodeToken: "fixture-identity", SSHLoginEnabled: true}
	c := newSSHEventCollector(state)
	c.collect(cfg, time.Now())
	report := c.snapshotForConfig(cfg)
	if report.State != "state_error" || len(report.Events) != 0 {
		t.Fatalf("private-state failure hidden: %+v", report)
	}
}

func TestSSHInstalledJournalReadOnlySourceStatus(t *testing.T) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		t.Skip("journalctl unavailable on this Linux host")
	}
	c := newSSHEventCollector(filepath.Join(t.TempDir(), "state.json"))
	c.collectJournal(Config{ServerID: "fixture", WorkerURL: "https://example.test/update", NodeToken: "fixture-identity", SSHLoginEnabled: true}, time.Now())
	state := c.snapshot().State
	if state != "watching" && state != "permission_denied" && state != "unavailable" {
		t.Fatalf("unexpected real journal status %s", state)
	}
	t.Logf("installed journalctl fixed sshd-filter read-only baseline: state=%s, events=%d", state, len(c.snapshot().Events))
}

func TestSSHLogRejectsSymlinkAndInsecureWriter(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "auth.log")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(file, []byte("log\n"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0666); err != nil {
		t.Fatal(err)
	}
	if f, _, err := openSSHLog(file); err == nil {
		f.Close()
		t.Fatal("world-writable auth source trusted")
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if f, _, err := openSSHLog(link); err == nil {
		f.Close()
		t.Fatal("source symlink trusted")
	}
}

func TestSSHEventsActualTerminalOutputFixture(t *testing.T) {
	path := os.Getenv("CFSM_TERMINAL_STREAM_FIXTURE")
	if path == "" {
		t.Skip("set CFSM_TERMINAL_STREAM_FIXTURE for the xterm integration receipt")
	}
	t.Setenv("HOME", t.TempDir())
	p := linuxSessionStart(t, 80, 24)
	output := linuxSessionCommand(t, p, "printf '\\nWelcome to Alpine!\\n/opt/komari # '", "/opt/komari # ")
	if !strings.Contains(output, "Welcome to Alpine!") {
		t.Fatal("actual PTY stdout missing probe text")
	}
	if err := os.WriteFile(path, []byte(output), 0600); err != nil {
		t.Fatal(err)
	}
}
