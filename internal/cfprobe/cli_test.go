package cfprobe

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTerminalInstallFlags(t *testing.T) {
	for _, args := range [][]string{nil, {"-terminal=0"}} {
		got, err := parseInstallOptions(args)
		if err != nil || got.TerminalEnabled || got.TerminalToken != "" {
			t.Fatal("disabled install requires no token")
		}
	}
	for _, value := range []string{"", "2", "true", " 1"} {
		if _, err := parseInstallOptions([]string{"-terminal=" + value}); err == nil {
			t.Fatal("invalid terminal flag accepted")
		}
	}
	token := strings.Repeat("a", 64)
	if _, err := parseInstallOptions([]string{"-terminal-token=" + token}); err == nil || strings.Contains(err.Error(), token) {
		t.Fatal("plaintext token flag accepted or leaked")
	}
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := parseInstallOptions([]string{"-terminal=1", "-terminal-token-file=" + path})
	if runtime.GOOS == "linux" {
		if err != nil || !got.TerminalEnabled || got.TerminalToken != token || !got.Explicit["terminal_token_file"] {
			t.Fatal("owner-only token not read")
		}
	} else if err == nil {
		t.Fatal("unsupported platform accepted token file")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("source token deleted")
	}
}

func TestTerminalInvalidOptionsDoNotReplaceConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.conf")
	original := []byte("SERVER_ID=preserved\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"-terminal=invalid"}, {"-terminal-token-file=relative"}, {"-terminal-token-file="}} {
		if _, err := parseInstallOptions(args); err == nil {
			t.Fatal("invalid options accepted")
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != string(original) {
			t.Fatal("original config changed")
		}
	}
}

func TestParseUninstallArgsAllowsNoArgs(t *testing.T) {
	if err := parseUninstallArgs(nil); err != nil {
		t.Fatalf("parseUninstallArgs(nil) error = %v", err)
	}
}

func TestParseInstallOptionsRejectsCustomPathAndService(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "install dir underscore", args: []string{"-install_dir=/tmp/cf-probe"}},
		{name: "install dir hyphen", args: []string{"-install-dir=/tmp/cf-probe"}},
		{name: "service name underscore", args: []string{"-service_name=probe-a"}},
		{name: "service name hyphen", args: []string{"-service-name=probe-a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseInstallOptions(tt.args); err == nil {
				t.Fatalf("parseInstallOptions(%v) expected error", tt.args)
			}
		})
	}
}

func TestParseUninstallArgsRejectsExtraArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "service name underscore", args: []string{"-service_name=probe-a"}},
		{name: "service name hyphen", args: []string{"-service-name=probe-a"}},
		{name: "positional arg", args: []string{"probe-a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := parseUninstallArgs(tt.args); err == nil {
				t.Fatalf("parseUninstallArgs(%v) expected error", tt.args)
			}
		})
	}
}

func TestParseInstallOptionsAutoUpdateDefaultOff(t *testing.T) {
	got, err := parseInstallOptions(nil)
	if err != nil {
		t.Fatalf("parseInstallOptions(nil) error = %v", err)
	}
	if got.AutoUpdate {
		t.Fatal("AutoUpdate = true, want false")
	}
}

func TestParseInstallOptionsAutoUpdateEnabled(t *testing.T) {
	got, err := parseInstallOptions([]string{"-auto_update=1"})
	if err != nil {
		t.Fatalf("parseInstallOptions(-auto_update=1) error = %v", err)
	}
	if !got.AutoUpdate {
		t.Fatal("AutoUpdate = false, want true")
	}
}

func TestParseInstallOptionsInstallProxy(t *testing.T) {
	got, err := parseInstallOptions([]string{"--install-ghproxy=https://gh-proxy.example.com"})
	if err != nil {
		t.Fatalf("parseInstallOptions(--install-ghproxy) error = %v", err)
	}
	if got.UpdateProxy != "https://gh-proxy.example.com" {
		t.Fatalf("UpdateProxy = %q", got.UpdateProxy)
	}
}

func TestParseInstallOptionsConnectionMode(t *testing.T) {
	got, err := parseInstallOptions([]string{"-connection_mode=http"})
	if err != nil {
		t.Fatalf("parseInstallOptions(-connection_mode=http) error = %v", err)
	}
	if got.ConnectionMode != connectionModeHTTP {
		t.Fatalf("ConnectionMode = %q, want %q", got.ConnectionMode, connectionModeHTTP)
	}

	got, err = parseInstallOptions([]string{"--connection-mode=websocket"})
	if err != nil {
		t.Fatalf("parseInstallOptions(--connection-mode=websocket) error = %v", err)
	}
	if got.ConnectionMode != connectionModeAuto {
		t.Fatalf("ConnectionMode = %q, want %q", got.ConnectionMode, connectionModeAuto)
	}

	if _, err := parseInstallOptions([]string{"-connection_mode=bad"}); err == nil {
		t.Fatal("parseInstallOptions(-connection_mode=bad) expected error")
	}
}

func TestParseInstallOptionsPingMode(t *testing.T) {
	got, err := parseInstallOptions([]string{"-ping_mode=icmp"})
	if err != nil {
		t.Fatalf("parseInstallOptions(-ping_mode=icmp) error = %v", err)
	}
	if got.PingMode != pingModeICMP {
		t.Fatalf("PingMode = %q, want %q", got.PingMode, pingModeICMP)
	}

	got, err = parseInstallOptions([]string{"--ping-mode=tcp"})
	if err != nil {
		t.Fatalf("parseInstallOptions(--ping-mode=tcp) error = %v", err)
	}
	if got.PingMode != pingModeTCP {
		t.Fatalf("PingMode = %q, want %q", got.PingMode, pingModeTCP)
	}

	if _, err := parseInstallOptions([]string{"-ping_mode=bad"}); err == nil {
		t.Fatal("parseInstallOptions(-ping_mode=bad) expected error")
	}
}

func TestParseInstallOptionsTracksExplicitFlags(t *testing.T) {
	got, err := parseInstallOptions([]string{"-auto_update=1", "--auto-update=1", "-collect=5", "-connection_mode=http", "-ping_mode=icmp", "--install-ghproxy=https://gh-proxy.example.com"})
	if err != nil {
		t.Fatalf("parseInstallOptions() error = %v", err)
	}
	for _, name := range []string{"auto_update", "collect_interval", "connection_mode", "ping_mode", "install_ghproxy"} {
		if !got.Explicit[name] {
			t.Fatalf("Explicit[%q] = false, want true (all: %v)", name, got.Explicit)
		}
	}
	if got.Explicit["reset_day"] || got.Explicit["interface"] {
		t.Fatalf("unexpected explicit flags: %v", got.Explicit)
	}
}
