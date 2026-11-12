//go:build linux

package cfprobe

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTerminalDisableLinuxOwnedPTYBeforeACKReloadAndReinstall(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	file := filepath.Join(home, "config")
	cfg := Config{TerminalEnabled: true, NodeToken: strings.Repeat("a", 64), ServerID: "node", WorkerURL: "https://example.invalid/update"}
	if err := writeConfig(file, cfg); err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: cfg, paths: Paths{ConfigFile: file}, log: newLogger(false)}
	control := newSessionTestPeer()
	opts := defaultTerminalControlOptions()
	opts.dial = func(context.Context, Config, string, string, bool) (terminalPeer, error) { return control, nil }
	var processes []*linuxTerminalProcess
	manager := newTerminalManager(4, func(cols, rows uint16) (terminalProcess, error) {
		p, err := newTerminalProcess(cols, rows)
		if p != nil {
			processes = append(processes, p.(*linuxTerminalProcess))
		}
		return p, err
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); a.terminalGeneration(ctx, cfg, 1, manager, opts) }()
	defer func() { cancel(); <-done; manager.CloseAll("test_end") }()
	_ = sessionFrame(t, control)
	control.send(wsOpcodeText, []byte(disableBinding))
	for _, id := range []string{"owned-a", "owned-b"} {
		peer := newSessionTestPeer()
		if err := manager.Open(ctx, id, peer, 80, 24); err != nil {
			t.Fatal(err)
		}
		sessionReady(t, peer)
	}
	if len(processes) != 2 {
		t.Fatal("missing actual owned PTYs")
	}
	type identity struct {
		PID                   int
		StartTime, Executable string
	}
	identities := make([]identity, 0, 2)
	for _, p := range processes {
		exe, err := os.Readlink("/proc/" + strconv.Itoa(p.cmd.Process.Pid) + "/exe")
		if err != nil {
			t.Fatal(err)
		}
		if p.shellStart == "" {
			t.Fatal("missing process temporal identity")
		}
		identities = append(identities, identity{p.cmd.Process.Pid, p.shellStart, exe})
	}
	control.send(wsOpcodeText, []byte(disableRequest))
	frame := sessionFrame(t, control)
	var ack map[string]any
	if err := json.Unmarshal(frame.data, &ack); err != nil || ack["type"] != "disabled" {
		t.Fatalf("missing matched disabled ACK: %s", frame.data)
	}
	for _, p := range processes {
		select {
		case <-p.waitDone:
		default:
			t.Fatal("ACK preceded OWN PTY reap")
		}
		if _, err := os.Stat("/proc/" + strconv.Itoa(p.cmd.Process.Pid)); !os.IsNotExist(err) {
			t.Fatal("owned PTY survivor or unverified recycled PID")
		}
	}
	persisted, err := readConfig(file)
	if err != nil || persisted.TerminalEnabled {
		t.Fatal("restart configuration not durably false")
	}
	var dials atomic.Int32
	restart := &Agent{cfg: persisted, paths: Paths{ConfigFile: file}, log: newLogger(false)}
	restartOpts := defaultTerminalControlOptions()
	restartOpts.configInterval = time.Millisecond
	restartOpts.dial = func(context.Context, Config, string, string, bool) (terminalPeer, error) {
		dials.Add(1)
		return nil, nil
	}
	restartCtx, stop := context.WithTimeout(t.Context(), 50*time.Millisecond)
	restart.runTerminalWorker(restartCtx, restartOpts)
	stop()
	if dials.Load() != 0 {
		t.Fatal("restart reconnected while locally disabled")
	}
	next := persisted
	next.TerminalEnabled = true
	next.NodeToken = strings.Repeat("c", 64)
	if err := writeConfig(file, next); err != nil {
		t.Fatal(err)
	}
	a.setConfig(next)
	fresh := newSessionTestPeer()
	opts.dial = func(context.Context, Config, string, string, bool) (terminalPeer, error) { return fresh, nil }
	freshCtx, stopFresh := context.WithCancel(t.Context())
	freshDone := make(chan struct{})
	go func() {
		defer close(freshDone)
		a.terminalGeneration(freshCtx, next, 2, newTerminalManager(4, newTerminalProcess), opts)
	}()
	_ = sessionFrame(t, fresh)
	if !a.configSnapshot().TerminalEnabled {
		t.Fatal("new explicit local installation not available")
	}
	stopFresh()
	<-freshDone
	bytes, _ := json.Marshal(map[string]any{"ownedIdentities": identities, "survivors": 0, "configPath": file, "persistedFalseBeforeACK": true, "restartDials": dials.Load(), "freshAuthenticatedSyntheticControl": true})
	t.Logf("ISOLATED_PTY_EVIDENCE %s", bytes)
}
