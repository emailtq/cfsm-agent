package cfprobe

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testNodeToken = strings.Repeat("a", 64)

func TestNodeTokenCLI(t *testing.T) {
	opts, err := parseInstallOptions([]string{"-token=" + testNodeToken, "-url=https://example.com/update"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.TerminalEnabled {
		t.Fatal("monitoring token enabled local terminal")
	}
}

func TestNodeTokenRejectsLegacyConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.conf")
	if err := writePrivateTestFile(path, []byte("SECRET=old\nWORKER_URL=https://example.com/update\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(path); err == nil || !strings.Contains(strings.ToLower(err.Error()), "reinstall") {
		t.Fatalf("old config must require reinstall, got %v", err)
	}
}

func TestNodeTokenHeadersAndNoReportCredential(t *testing.T) {
	cfg := defaultConfig()
	cfg.ServerID, cfg.WorkerURL = "node-1", "https://example.com/update"
	cfg.NodeToken = testNodeToken
	a := &Agent{cfg: cfg}
	req, _ := http.NewRequest(http.MethodPost, cfg.WorkerURL, nil)
	a.setAgentHeaders(req, cfg)
	if req.Header.Get("Authorization") != "Bearer "+testNodeToken {
		t.Fatal("report lacks bearer node token")
	}
	headers, err := terminalWebSocketHeaders(cfg, "")
	if err != nil || headers.Get("Authorization") != req.Header.Get("Authorization") {
		t.Fatal("terminal and reporting must share one token", err)
	}
	body, _, err := a.buildReportBodyForConfig(cfg, Metrics{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"secret", "token", "node_token", "terminal_token"} {
		if _, ok := payload[key]; ok {
			t.Fatalf("credential key %s in report", key)
		}
	}
	if strings.Contains(string(body), testNodeToken) {
		t.Fatal("token in report JSON")
	}
}

func TestNodeTokenUnixOwnerAndReplaceableParent(t *testing.T) {
	for _, tc := range []struct {
		mode               os.FileMode
		uid                uint32
		directory, allowed bool
	}{
		{0600, 1000, false, true}, {0600, 1001, false, false}, {0640, 1000, false, false},
		{0755, 1000, true, true}, {0755, 0, true, true}, {0755, 1001, true, false},
		{0777, 1000, true, false}, {0770, 1000, true, false}, {0777 | os.ModeSticky, 0, true, true},
		{0777 | os.ModeSticky, 1001, true, false}, {0777 | os.ModeSticky, 1000, true, false},
	} {
		if err := validateUnixPrivatePermissions(tc.mode, tc.uid, 1000, tc.directory); (err == nil) != tc.allowed {
			t.Fatalf("mode=%v uid=%d directory=%v accepted=%v", tc.mode, tc.uid, tc.directory, err == nil)
		}
	}
}

func TestNodeTokenNeverLoggedFromServerResponse(t *testing.T) {
	var output bytes.Buffer
	l := newLogger(true)
	l.l = log.New(&output, "", 0)
	a := &Agent{cfg: Config{NodeToken: testNodeToken}, log: l}
	a.handleTimedReportResponse(401, []byte("echo token="+testNodeToken), http.Header{}, time.Now(), time.Now())
	if strings.Contains(output.String(), testNodeToken) {
		t.Fatal("server response leaked node token")
	}
}

func TestNodeTokenOldFlagsRejectedWithoutCredentialEcho(t *testing.T) {
	for _, flag := range []string{"-secret=", "-terminal-token-file=", "--install-terminal-token="} {
		if _, err := parseInstallOptions([]string{flag + testNodeToken}); err == nil || strings.Contains(err.Error(), testNodeToken) {
			t.Fatal("legacy flag accepted or leaked credential", err)
		}
	}
}

func TestNodeTokenConfigRejectsInjectedLineBeforeReplacingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.conf")
	cfg := Config{NodeToken: testNodeToken, Name: "safe"}
	if err := writeConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	cfg.Name = "evil\nNODE_TOKEN=wrong"
	if err := writeConfig(path, cfg); err == nil {
		t.Fatal("configuration injection accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed validation replaced working config")
	}
}

func TestNodeTokenExplicitReinstallDiscardsRejectedConfig(t *testing.T) {
	rejected := Config{NodeToken: "untrusted", ServerID: "stolen", WorkerURL: "https://attacker.invalid/update", CTNode: "untrusted", TerminalEnabled: true}
	newCfg := defaultConfig()
	newCfg.NodeToken = testNodeToken
	newCfg.ServerID = "node"
	newCfg.WorkerURL = "https://example.com/update"
	opts := InstallOptions{Config: newCfg, Explicit: map[string]bool{"token": true, "id": true, "url": true}}
	if err := prepareInstallCredentials(&opts, rejected, errors.New("private config rejected")); err != nil {
		t.Fatal("explicit replacement still blocked", err)
	}
	if opts.Config != newCfg {
		t.Fatal("reinstall reused untrusted config contents")
	}
	opts = InstallOptions{Config: defaultConfig(), Explicit: map[string]bool{}}
	if err := prepareInstallCredentials(&opts, rejected, errors.New("private config rejected")); err == nil {
		t.Fatal("implicit unsafe migration allowed")
	}
}

func TestNodeTokenLegacyConfigFailurePrecedesMissing(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "absent.conf")
	bad := filepath.Join(dir, "bad.conf")
	if err := writePrivateTestFile(bad, []byte("NODE_TOKEN=invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good.conf")
	if err := writeConfig(good, Config{NodeToken: testNodeToken}); err != nil {
		t.Fatal(err)
	}
	for _, candidates := range [][]string{{bad}, {bad, good}} {
		_, path, err := readInstallConfigCandidates(Paths{ConfigFile: current}, candidates)
		if err == nil || errors.Is(err, os.ErrNotExist) || path != bad {
			t.Fatal("legacy config rejection masked by absence or later success", path, err)
		}
	}
}

func TestNodeTokenMissingConfigDirectoryRemainsNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-created", "config.conf")
	_, _, err := readInstallConfigCandidates(Paths{ConfigFile: path}, nil)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("first registration install blocked by misclassified missing directory", err)
	}
}

func TestNodeRegistrationCLI(t *testing.T) {
	if _, err := parseInstallOptions([]string{"-register-key=" + testNodeToken, "-url=https://example.com/update"}); err != nil {
		t.Fatal(err)
	}
	if _, err := parseInstallOptions([]string{"-register-key=" + testNodeToken, "-token=" + testNodeToken}); err == nil {
		t.Fatal("conflicting credentials accepted")
	}
}

func TestNodeTokenConfigRejectsSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.conf")
	if err := writeConfig(path, Config{NodeToken: testNodeToken}); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, path+".link"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := readConfig(path + ".link"); err == nil {
		t.Fatal("credential config followed symlink")
	}
}
