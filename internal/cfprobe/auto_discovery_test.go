package cfprobe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newDiscoveryTestAgent(t *testing.T, cfg Config) *Agent {
	t.Helper()
	dir := t.TempDir()
	return &Agent{
		cfg:             cfg,
		log:             newLogger(false),
		wake:            make(chan struct{}, 1),
		terminalChanged: make(chan struct{}, 1),
		paths:           Paths{ConfigDir: dir, ConfigFile: filepath.Join(dir, "config.conf"), TrafficFile: filepath.Join(dir, "traffic.dat")},
	}
}

func TestNodeRegistrationExchangeAndPersistence(t *testing.T) {
	key := strings.Repeat("b", 64)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/agent/register" || r.Header.Get("Authorization") != "Bearer "+key || r.Header.Get("Content-Type") != "application/json" {
			t.Error("registration request contract")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["name"] != "hk-1" {
			t.Error("registration body must contain only optional name")
		}
		json.NewEncoder(w).Encode(map[string]string{"serverId": "node-1", "token": testNodeToken})
	}))
	defer server.Close()
	cfg := defaultConfig()
	cfg.Name = "hk-1"
	cfg.WorkerURL = server.URL + "/update"
	got, err := registerNode(t.Context(), cfg, key, server.Client())
	if err != nil || got.NodeToken != testNodeToken || got.ServerID != "node-1" || got.TerminalEnabled {
		t.Fatal("registration failed or enabled terminal", err)
	}
	path := filepath.Join(t.TempDir(), "config.conf")
	if err := writeConfig(path, got); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), key) || strings.Contains(string(data), "SECRET=") || strings.Contains(string(data), "TERMINAL_TOKEN=") {
		t.Fatal("registration key or obsolete credential persisted")
	}
	a := newDiscoveryTestAgent(t, got)
	body, _, _ := a.buildReportBody(Metrics{}, time.Now())
	if strings.Contains(string(body), key) || strings.Contains(string(body), testNodeToken) {
		t.Fatal("credential in initial report")
	}
}

func TestNodeRegistrationInvalidResponseAndNoMutation(t *testing.T) {
	for _, body := range []string{`null`, `[]`, `{}`, `{"serverId":1,"token":"x"}`, `{"serverId":"../node","token":"` + testNodeToken + `"}`, `{"serverId":"node","token":"` + strings.Repeat("A", 64) + `"}`, `{"serverId":"node","token":"` + testNodeToken + `","secret":"x"}`, `{"serverId":"node","token":"` + testNodeToken + `"} {}`, strings.Repeat(" ", 4097), `{"serverId":null,"token":null}`, `{"serverId":"node","serverId":"other","token":"` + testNodeToken + `"}`, `{"serverId":"node","token":"` + testNodeToken + `","token":"` + testNodeToken + `"}`} {
		t.Run(body[:min(len(body), 30)], func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer server.Close()
			cfg := Config{WorkerURL: server.URL + "/update", ServerID: "existing", ReportInterval: 123}
			got, err := registerNode(t.Context(), cfg, testNodeToken, server.Client())
			if err == nil || got != cfg || strings.Contains(err.Error(), testNodeToken) {
				t.Fatal("malformed response mutated config or leaked token", err)
			}
		})
	}
}

func TestNodeRegistrationHTTPSAndRedirect(t *testing.T) {
	targetHits := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetHits++ }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL+"/steal", 307) }))
	defer server.Close()
	for _, raw := range []string{server.URL + "/update", "http://127.0.0.1/update", "https://user:token@example.com/update", "https://example.com/update?token=x", "https://example.com/other", "https://example.com/update#secret"} {
		_, err := registerNode(t.Context(), Config{WorkerURL: raw}, testNodeToken, server.Client())
		if err == nil {
			t.Fatal("unsafe endpoint or redirect accepted")
		}
	}
	if targetHits != 0 {
		t.Fatal("credential followed cross-origin redirect")
	}
	if _, err := registerNode(t.Context(), Config{WorkerURL: server.URL + "/update"}, testNodeToken, &http.Client{}); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
}

func TestNodeRegistrationHTTPFailureAndNameBound(t *testing.T) {
	for _, code := range []int{400, 401, 403, 409, 429, 500} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code); w.Write([]byte(testNodeToken)) }))
		_, err := registerNode(t.Context(), Config{WorkerURL: server.URL + "/update"}, testNodeToken, server.Client())
		server.Close()
		if err == nil || strings.Contains(err.Error(), testNodeToken) {
			t.Fatal("HTTP error accepted or leaked")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := registerNode(ctx, Config{WorkerURL: "https://example.com/update", Name: strings.Repeat("\U0001F600", 51)}, testNodeToken, &http.Client{})
	if err == nil {
		t.Fatal("oversized name accepted")
	}
}

func TestNodeRegistrationReinstallReuseAndLegacyMigration(t *testing.T) {
	saved := Config{WorkerURL: "https://example.invalid/update", ServerID: "node", NodeToken: testNodeToken, TerminalEnabled: false, ReportInterval: 123, CTNode: "keep"}
	opts := InstallOptions{Config: defaultConfig(), RegisterKey: strings.Repeat("b", 64), Explicit: map[string]bool{"register_key": true}}
	if err := prepareInstallCredentials(&opts, saved, nil); err != nil || opts.Config != saved || opts.RegisterKey != "" {
		t.Fatal("reinstall registered again or lost local config", err)
	}
	legacy := saved
	legacy.NodeToken = ""
	opts = InstallOptions{Config: Config{NodeToken: testNodeToken}, Explicit: map[string]bool{"token": true}}
	if err := prepareInstallCredentials(&opts, legacy, errLegacyCredential); err != nil || opts.ReportInterval != 123 || opts.CTNode != "keep" || opts.TerminalEnabled {
		t.Fatal("explicit migration lost collection/local consent", err)
	}
	opts = InstallOptions{Config: defaultConfig(), Explicit: map[string]bool{}}
	if err := prepareInstallCredentials(&opts, legacy, errLegacyCredential); err == nil {
		t.Fatal("legacy credential fallback")
	}
}

func TestNodeTokenServerCannotBindIdentityFromReportHeaders(t *testing.T) {
	cfg := Config{ServerID: "original", NodeToken: testNodeToken, WorkerURL: "https://example.invalid/update"}
	a := newDiscoveryTestAgent(t, cfg)
	a.handleTimedReportResponse(200, []byte("OK"), http.Header{"X-Cfsm-Auto-Discovery": {"created"}, "X-Cfsm-Server-Id": {"other"}}, time.Now(), time.Now())
	if a.configSnapshot().ServerID != "original" {
		t.Fatal("report response changed credential identity")
	}
}
