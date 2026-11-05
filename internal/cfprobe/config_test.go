package cfprobe

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type terminalTokenInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (i terminalTokenInfo) Mode() os.FileMode { return i.mode }

func TestTerminalTokenValidationAndFilesystem(t *testing.T) {
	for _, token := range []string{strings.Repeat("a", 64), strings.Repeat("0", 64)} {
		if !validTerminalToken(token) {
			t.Fatal("valid token rejected")
		}
	}
	for _, token := range []string{"", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("a", 64) + "\n", strings.Repeat("g", 64)} {
		if validTerminalToken(token) {
			t.Fatal("invalid token accepted")
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if err := validateTerminalTokenInfo(terminalTokenInfo{mode: mode}); err != nil {
			t.Fatal("owner-only mode rejected")
		}
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o606, os.ModeSymlink | 0o600, os.ModeDir | 0o600, os.ModeNamedPipe | 0o600, os.ModeSetuid | 0o600} {
		if err := validateTerminalTokenInfo(terminalTokenInfo{mode: mode}); err == nil {
			t.Fatal("unsafe file metadata accepted")
		}
	}
	if _, err := readTerminalTokenFile("relative"); err == nil {
		t.Fatal("relative path accepted")
	}
	path := filepath.Join(t.TempDir(), "token")
	token := strings.Repeat("a", 64)
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "linux" {
		if _, err := readTerminalTokenFile(path); err == nil {
			t.Fatal("non-Linux permission check bypassed")
		}
		return
	}
	got, err := readTerminalTokenFile(path)
	if err != nil || got != token {
		t.Fatal("real Linux token read failed")
	}
	if err := os.Symlink(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	if _, err := readTerminalTokenFile(path + ".link"); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := readTerminalTokenFile(filepath.Dir(path)); err == nil {
		t.Fatal("directory accepted")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTerminalTokenFile(path); err == nil {
		t.Fatal("world-readable file accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{token + "\n", strings.Repeat("A", 64), strings.Repeat("a", 1024)} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readTerminalTokenFile(path); err == nil || strings.Contains(err.Error(), content) {
			t.Fatal("invalid source accepted or leaked")
		}
	}
}

func TestTerminalTokenOpenerRejectsSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "linux" {
		if file, err := openTerminalTokenFile(path); err == nil {
			file.Close()
			t.Fatal("unsupported platform opened token")
		}
		return
	}
	file, err := openTerminalTokenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := os.Symlink(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	if file, err := openTerminalTokenFile(path + ".link"); err == nil {
		file.Close()
		t.Fatal("kernel token opener followed symlink")
	}
}

func TestTerminalConfigAtomicWriteIgnoresPreexistingTemp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.conf")
	if err := os.WriteFile(path+".tmp", []byte("unrelated"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	cfg.TerminalToken = strings.Repeat("a", 64)
	if err := writeConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	temp, err := os.ReadFile(path + ".tmp")
	if err != nil || string(temp) != "unrelated" {
		t.Fatal("predictable temp replaced or exposed credential")
	}
	if runtime.GOOS == "linux" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("config is not owner-only")
		}
	}
}

func TestTerminalConfigDefaultLegacyAndRoundTrip(t *testing.T) {
	cfg := defaultConfig()
	if cfg.TerminalEnabled || cfg.TerminalToken != "" {
		t.Fatal("terminal must default off")
	}
	path := filepath.Join(t.TempDir(), "config.conf")
	if err := os.WriteFile(path, []byte("SERVER_ID=legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy, err := readConfig(path)
	if err != nil || legacy.TerminalEnabled || legacy.TerminalToken != "" {
		t.Fatal("legacy opt-in changed")
	}
	cfg.TerminalEnabled = true
	cfg.TerminalToken = strings.Repeat("a", 64)
	if err := writeConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := readConfig(path)
	if err != nil || !got.TerminalEnabled || got.TerminalToken != cfg.TerminalToken {
		t.Fatal("terminal roundtrip failed")
	}
	cfg.TerminalEnabled = false
	if err := writeConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	got, err = readConfig(path)
	if err != nil || got.TerminalEnabled || got.TerminalToken != cfg.TerminalToken {
		t.Fatal("disabled credential lost")
	}
}

func TestNormalizeInterfaceList(t *testing.T) {
	got, err := normalizeInterfaceList(" eth0,ens3,eth0, pppoe-wan ")
	if err != nil {
		t.Fatalf("normalizeInterfaceList returned error: %v", err)
	}
	if got != "eth0,ens3,pppoe-wan" {
		t.Fatalf("unexpected normalized interfaces: %q", got)
	}
}

func TestNormalizeInterfaceListRejectsBadName(t *testing.T) {
	if _, err := normalizeInterfaceList("eth0, bad/name"); err == nil {
		t.Fatal("expected invalid interface name to be rejected")
	}
}

func TestNormalizeInterfaceListAllowsGlob(t *testing.T) {
	got, err := normalizeInterfaceList(" eth*,en[ops]* ")
	if err != nil {
		t.Fatalf("normalizeInterfaceList returned error: %v", err)
	}
	if got != "eth*,en[ops]*" {
		t.Fatalf("unexpected normalized interfaces: %q", got)
	}
}

func TestConfigPersistsUpdateProxy(t *testing.T) {
	path := t.TempDir() + "/config.conf"
	cfg := defaultConfig()
	cfg.ServerID = "sid"
	cfg.Secret = "secret"
	cfg.WorkerURL = "https://worker.example.com/report"
	cfg.AutoUpdate = true
	cfg.UpdateProxy = "https://gh-proxy.example.com"
	cfg.ConnectionMode = connectionModeHTTP
	cfg.PingMode = pingModeICMP

	if err := writeConfig(path, cfg); err != nil {
		t.Fatalf("writeConfig returned error: %v", err)
	}
	got, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig returned error: %v", err)
	}
	if got.UpdateProxy != cfg.UpdateProxy {
		t.Fatalf("UpdateProxy = %q, want %q", got.UpdateProxy, cfg.UpdateProxy)
	}
	if !got.AutoUpdate {
		t.Fatal("AutoUpdate = false, want true")
	}
	if got.ConnectionMode != connectionModeHTTP {
		t.Fatalf("ConnectionMode = %q, want %q", got.ConnectionMode, connectionModeHTTP)
	}
	if got.PingMode != pingModeICMP {
		t.Fatalf("PingMode = %q, want %q", got.PingMode, pingModeICMP)
	}
}

func TestReadConfigDefaultsConnectionModeAuto(t *testing.T) {
	path := t.TempDir() + "/config.conf"
	data := []byte("SERVER_ID=\"sid\"\nSECRET=\"secret\"\nWORKER_URL=\"https://worker.example.com/update\"\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
	got, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig returned error: %v", err)
	}
	if got.ConnectionMode != connectionModeAuto {
		t.Fatalf("ConnectionMode = %q, want %q", got.ConnectionMode, connectionModeAuto)
	}
	if got.PingMode != pingModeTCP {
		t.Fatalf("PingMode = %q, want %q", got.PingMode, pingModeTCP)
	}
	if got.UA != defaultUserAgent {
		t.Fatalf("UA = %q, want default %q", got.UA, defaultUserAgent)
	}
}

func TestNormalizeUserAgentValue(t *testing.T) {
	accepted := []string{
		"cfsm",
		"MyAgent/1.0",
		"cfsm (edge)",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
	}
	for _, value := range accepted {
		if got := normalizeUserAgentValue(value); got != value {
			t.Fatalf("normalizeUserAgentValue(%q) = %q", value, got)
		}
	}

	rejected := []string{
		"",
		"ua\"quote",
		"ua\\backslash",
		"ua'single",
		"ua$var",
		"ua&other",
		"ua|pipe",
		"ua%20",
		"中文UA",
		"ua\r\nInjected: 1",
	}
	for _, value := range rejected {
		if got := normalizeUserAgentValue(value); got != defaultUserAgent {
			t.Fatalf("normalizeUserAgentValue(%q) = %q, want %q", value, got, defaultUserAgent)
		}
	}

	longest := ""
	for len(longest) < maxUserAgentLength {
		longest += "a"
	}
	if got := normalizeUserAgentValue(longest); got != longest {
		t.Fatalf("max length UA should be accepted")
	}
	if got := normalizeUserAgentValue(longest + "a"); got != defaultUserAgent {
		t.Fatalf("over-long UA should fall back to default")
	}
}

func TestConfigPersistsUserAgent(t *testing.T) {
	path := t.TempDir() + "/config.conf"
	cfg := defaultConfig()
	cfg.ServerID = "sid"
	cfg.Secret = "secret"
	cfg.WorkerURL = "https://worker.example.com/update"
	cfg.UA = "MyAgent/1.0"

	if err := writeConfig(path, cfg); err != nil {
		t.Fatalf("writeConfig returned error: %v", err)
	}
	got, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig returned error: %v", err)
	}
	if got.UA != cfg.UA {
		t.Fatalf("UA = %q, want %q", got.UA, cfg.UA)
	}
}

func TestApplyRemoteUserAgentUpdatesConfigOnce(t *testing.T) {
	tmp := t.TempDir()
	configFile := tmp + "/config.conf"
	agent := Agent{
		cfg: Config{
			ServerID:       "sid",
			Secret:         "secret",
			WorkerURL:      "https://worker.example.com/update",
			ReportInterval: 60,
			ResetDay:       1,
			ConnectionMode: connectionModeAuto,
			PingMode:       pingModeTCP,
			UA:             defaultUserAgent,
			ConfigMD5:      "none",
		},
		paths: Paths{ConfigFile: configFile, TrafficFile: tmp + "/traffic.dat"},
		log:   newLogger(false),
	}
	if err := writeConfig(configFile, agent.cfg); err != nil {
		t.Fatalf("writeConfig returned error: %v", err)
	}

	agent.applyRemoteUserAgent("MyAgent/1.0")
	if got := agent.configSnapshot().UA; got != "MyAgent/1.0" {
		t.Fatalf("in-memory UA = %q", got)
	}
	persisted, err := readConfig(configFile)
	if err != nil {
		t.Fatalf("readConfig returned error: %v", err)
	}
	if persisted.UA != "MyAgent/1.0" {
		t.Fatalf("persisted UA = %q", persisted.UA)
	}

	// 相同值不应重复写盘（避免每个上报周期写 flash）。
	before, err := os.Stat(configFile)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	agent.applyRemoteUserAgent("MyAgent/1.0")
	after, err := os.Stat(configFile)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("config file rewritten for identical UA")
	}

	// 非法值直接忽略，不能把已有 UA 打回默认值。
	agent.applyRemoteUserAgent("bad\"ua")
	if got := agent.configSnapshot().UA; got != "MyAgent/1.0" {
		t.Fatalf("UA after invalid input = %q", got)
	}
}
