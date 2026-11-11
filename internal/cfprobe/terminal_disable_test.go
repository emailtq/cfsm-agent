package cfprobe

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTerminalDisableRemoteConfigCannotRestoreStaleLocalTrue(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config")
	cfg := Config{TerminalEnabled: true, TerminalToken: strings.Repeat("a", 64), ServerID: "node", WorkerURL: "https://example.invalid/update", ConfigMD5: "none"}
	a := &Agent{cfg: cfg, paths: Paths{ConfigFile: file}, log: newLogger(false)}
	if err := writeConfig(file, cfg); err != nil {
		t.Fatal(err)
	}
	a.configWriteMu.Lock()
	done := make(chan error, 1)
	go func() {
		done <- a.applyRemoteConfigWithOptions([]byte("collect_interval=1&report_interval=60&wss_report_interval=1&reset_day=1&schema_version="+configSchemaVersion+"&connection_mode=http&ping_mode=tcp"), http.Header{}, true)
	}()
	// Hold the existing writer queue while an ordinary config update takes its snapshot.
	time.Sleep(50 * time.Millisecond)
	next := cfg
	next.TerminalEnabled = false
	if err := writeConfig(file, next); err != nil {
		a.configWriteMu.Unlock()
		t.Fatal(err)
	}
	a.setConfig(next)
	a.configWriteMu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	persisted, err := readConfig(file)
	if err != nil || persisted.TerminalEnabled || a.configSnapshot().TerminalEnabled {
		t.Fatal("ordinary remote config restored stale localtrue after disable")
	}
}

const disableBinding = `{"type":"bound","serverId":"node","connectionId":"control-1","generation":2,"credentialVersion":1}`
const disableRequest = `{"type":"disable","operationId":"operation-1","serverId":"node","connectionId":"control-1","generation":2,"credentialVersion":1}`

func TestTerminalDisableProtocol(t *testing.T) {
	for _, item := range []struct{ text, role string }{{disableBinding, "broker-control"}, {disableRequest, "broker-control"}, {strings.Replace(disableRequest, `"disable"`, `"disabled"`, 1), "agent-control"}} {
		if _, err := parseTerminalControl([]byte(item.text), item.role); err != nil {
			t.Fatalf("new negotiated frame rejected: %v", err)
		}
	}
	for _, text := range []string{strings.Replace(disableRequest, `"disable"`, `"enable"`, 1), strings.Replace(disableRequest, `"generation":2`, `"generation":0`, 1), strings.Replace(disableRequest, `"credentialVersion":1`, `"credentialVersion":"1"`, 1), strings.Replace(disableRequest, `}`, `,"extra":true}`, 1)} {
		if _, err := parseTerminalControl([]byte(text), "broker-control"); err == nil {
			t.Fatal("bad disable accepted")
		}
	}
	for _, role := range []string{"agent-control", "browser", "agent", "broker"} {
		if _, err := parseTerminalControl([]byte(disableRequest), role); err == nil {
			t.Fatal("sender impersonation accepted")
		}
	}
}

func TestTerminalDisablePersistsBeforeACKAndRejectsStaleConfig(t *testing.T) {
	for _, mode := range []string{"online", "persist_fail", "fresh_install", "disk_install", "old_generation", "old_version"} {
		t.Run(mode, func(t *testing.T) {
			cfg := Config{TerminalEnabled: true, TerminalToken: strings.Repeat("a", 64), ServerID: "node", WorkerURL: "https://example.invalid/update"}
			file := filepath.Join(t.TempDir(), "config")
			if err := writeConfig(file, cfg); err != nil {
				t.Fatal(err)
			}
			a := &Agent{cfg: cfg, paths: Paths{ConfigFile: file}, log: newLogger(false)}
			control := newSessionTestPeer()
			opts := defaultTerminalControlOptions()
			opts.dial = func(context.Context, Config, string, string, bool) (terminalPeer, error) { return control, nil }
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			manager := newTerminalManager(4, func(uint16, uint16) (terminalProcess, error) { return newSessionTestProcess(), nil })
			go func() { defer close(done); a.terminalGeneration(ctx, cfg, 1, manager, opts) }()
			defer func() { cancel(); <-done; manager.CloseAll("test_end") }()
			_ = sessionFrame(t, control)
			control.send(wsOpcodeText, []byte(disableBinding))
			if mode == "persist_fail" {
				a.paths.ConfigFile = filepath.Join(file, "cannot-write")
			}
			if mode == "fresh_install" {
				next := cfg
				next.TerminalToken = strings.Repeat("c", 64)
				if err := writeConfig(file, next); err != nil {
					t.Fatal(err)
				}
				a.setConfig(next)
			}
			if mode == "disk_install" {
				next := cfg
				next.TerminalToken = strings.Repeat("c", 64)
				if err := writeConfig(file, next); err != nil {
					t.Fatal(err)
				}
			}
			request := disableRequest
			if mode == "old_generation" {
				request = strings.Replace(request, `"generation":2`, `"generation":1`, 1)
			}
			if mode == "old_version" {
				request = strings.Replace(request, `"credentialVersion":1`, `"credentialVersion":2`, 1)
			}
			control.send(wsOpcodeText, []byte(request))
			if mode == "online" {
				var ack map[string]any
				f := sessionFrame(t, control)
				if err := json.Unmarshal(f.data, &ack); err != nil {
					t.Fatal(err)
				}
				if ack["type"] != "disabled" || ack["operationId"] != "operation-1" {
					t.Fatalf("invalid ACK %s", f.data)
				}
				persisted, err := readConfig(file)
				if err != nil || persisted.TerminalEnabled || a.configSnapshot().TerminalEnabled {
					t.Fatalf("ACK before durablefalse: %v", err)
				}
				if persisted.TerminalToken != cfg.TerminalToken {
					t.Fatal("disable replaced token")
				}
			} else {
				select {
				case f := <-control.out:
					t.Fatalf("false successful ACK %s", f.data)
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("invalid disable did not end control")
				}
				persisted, err := readConfig(file)
				if err != nil || !persisted.TerminalEnabled {
					t.Fatal("invalid disable changed durable config")
				}
				if mode == "disk_install" && persisted.TerminalToken != strings.Repeat("c", 64) {
					t.Fatal("old control overwrote fresh on-disk installation")
				}
			}
		})
	}
}
