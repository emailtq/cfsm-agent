package cfprobe

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestTerminalUpdateExitHelper(t *testing.T) {
	dir := os.Getenv("CFSM_UPDATE_EXIT_HELPER")
	if dir == "" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &Agent{terminalCancel: cancel, terminalDone: make(chan struct{})}
	go func() {
		<-ctx.Done()
		_ = os.WriteFile(filepath.Join(dir, "joined"), []byte("clean"), 0o600)
		close(a.terminalDone)
	}()
	bin := filepath.Join(dir, "download")
	if err := os.WriteFile(bin, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	var callback func()
	_, err := scheduleUserModeUpdateWithExit(Paths{BinaryFile: filepath.Join(dir, "installed")}, bin, a.stopTerminal, func(_ time.Duration, fn func()) { callback = fn }, os.Exit)
	if err != nil || callback == nil {
		t.Fatal("cannot schedule fixture exit")
	}
	callback()
	t.Fatal("exit42 did not terminate")
}

func TestTerminalUpdateRealExit42AfterWorkerJoin(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestTerminalUpdateExitHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CFSM_UPDATE_EXIT_HELPER="+dir)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 42 {
		t.Fatalf("exit order fixture: %v %s", err, out)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "joined")); err != nil || string(data) != "clean" {
		t.Fatal("exit preceded worker join")
	}
}

func TestTerminalUpdateSelfReplaceJoinsBeforeExit42(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "download")
	if err := os.WriteFile(bin, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	var callback func()
	var order []string
	method, err := scheduleUserModeUpdateWithExit(Paths{BinaryFile: filepath.Join(dir, "installed")}, bin,
		func() { order = append(order, "cancel_join") },
		func(delay time.Duration, fn func()) {
			if delay != 60*time.Second {
				t.Fatal("changed update delay")
			}
			callback = fn
		},
		func(code int) {
			if code != 42 {
				t.Fatal("changed update exit code")
			}
			order = append(order, "exit")
		})
	if err != nil || method != "self-replace" || callback == nil {
		t.Fatalf("schedule: %s %v", method, err)
	}
	if len(order) != 0 {
		t.Fatal("selfreplace cleanup did not wait for scheduled exit")
	}
	callback()
	if !reflect.DeepEqual(order, []string{"cancel_join", "exit"}) {
		t.Fatalf("wrong exit order %v", order)
	}
}

func TestTerminalUpdateServiceCleanupOnlyAfterSuccess(t *testing.T) {
	for _, user := range []bool{false, true} {
		for _, fail := range []bool{false, true} {
			var order []string
			failure := error(nil)
			if fail {
				failure = errors.New("fixture failure")
			}
			ops := updateInstallers{
				windows: func(Paths, string) (string, error) { order = append(order, "schedule"); return "service", failure },
				unix: func(string, string, string, int64) (string, error) {
					order = append(order, "schedule")
					return "service", failure
				},
				user: func(Paths, string, func()) (string, error) {
					order = append(order, "selfreplace")
					return "self-replace", failure
				},
			}
			_, err := scheduleUpdateWithInstallers(Paths{UserMode: user}, "fixture", 1, func() { order = append(order, "cancel_join") }, ops)
			if (err != nil) != fail {
				t.Fatal("schedule error changed")
			}
			if order[0] == "selfreplace" {
				if len(order) != 1 {
					t.Fatal("selfreplace must own timed cleanup")
				}
			} else if !fail && !reflect.DeepEqual(order, []string{"schedule", "cancel_join"}) {
				t.Fatalf("service cleanup order %v", order)
			} else if fail && len(order) != 1 {
				t.Fatal("failed scheduling stopped terminal")
			}
		}
	}
}
