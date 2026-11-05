package cfprobe

import (
	"strings"
	"testing"
)

func TestTerminalProtocolRolesAndValues(t *testing.T) {
	for _, tt := range []struct{ role, text string }{
		{"agent-control", `{"type":"hello","protocol":1,"platform":"linux","capabilities":["terminal.pty.v1"]}`},
		{"broker-control", `{"type":"open","protocol":1,"sessionId":"S_1","ticket":"` + strings.Repeat("a", 64) + `","cols":80,"rows":24}`},
		{"broker-control", `{"type":"close","sessionId":"S_1","reason":"user_close"}`},
		{"broker", `{"type":"start","cols":1,"rows":500}`},
		{"browser", `{"type":"resize","cols":500,"rows":1}`},
		{"agent", `{"type":"ack","bytes":9007199254740991}`},
		{"browser", `{"type":"ack","bytes":0}`},
		{"broker", `{"type":"ack","bytes":4096.0}`},
		{"agent", `{"type":"exit","code":-1}`},
		{"broker", `{"type":"exit","code":255}`},
		{"agent", `{"type":"error","code":"pty_start_failed"}`},
		{"agent", `{"type":"ready"}`},
		{"broker", `{"type":"ready"}`},
		{"agent-control", `{"type":"ping"}`},
		{"broker-control", `{"type":"pong"}`},
	} {
		if _, err := parseTerminalControl([]byte(tt.text), tt.role); err != nil {
			t.Fatalf("valid %s control rejected: %v", tt.role, err)
		}
	}
	for _, tt := range []struct{ role, text string }{
		{"browser", `{"type":"start","cols":80,"rows":24}`},
		{"agent-control", `{"type":"ready"}`},
		{"agent", `{"type":"close","sessionId":"S1","reason":"user_close"}`},
		{"unknown", `{"type":"ping"}`},
		{"broker", `{"type":"start","cols":0,"rows":24}`},
		{"broker", `{"type":"start","cols":501,"rows":24}`},
		{"broker", `{"type":"resize","cols":80.5,"rows":24}`},
		{"broker", `{"type":"resize","cols":"80","rows":24}`},
		{"broker", `{"type":"resize","cols":80}`},
		{"agent", `{"type":"ack","bytes":-1}`},
		{"agent", `{"type":"ack","bytes":1.5}`},
		{"agent", `{"type":"ack","bytes":9007199254740992}`},
		{"agent", `{"type":"ack","bytes":null}`},
		{"agent", `{"type":"exit","code":256}`},
		{"agent", `{"type":"exit","code":-2}`},
		{"agent", `{"type":"error","code":"untrusted error text"}`},
		{"agent", `{"type":"ready","extra":1}`},
		{"agent", `{"type":"constructor"}`},
		{"agent", `[]`}, {"agent", `null`}, {"agent", `{"type":`},
		{"agent-control", `{"type":"hello","protocol":2,"platform":"linux","capabilities":["terminal.pty.v1"]}`},
		{"agent-control", `{"type":"hello","protocol":1,"platform":"windows","capabilities":["terminal.pty.v1"]}`},
		{"agent-control", `{"type":"hello","protocol":1,"platform":"linux","capabilities":["terminal.pty.v1","other"]}`},
		{"broker-control", `{"type":"open","protocol":1,"sessionId":"../s","ticket":"` + strings.Repeat("a", 64) + `","cols":80,"rows":24}`},
		{"broker-control", `{"type":"open","protocol":1,"sessionId":"s","ticket":"` + strings.Repeat("A", 64) + `","cols":80,"rows":24}`},
		{"broker-control", `{"type":"close","sessionId":"s","reason":"TOKEN"}`},
		{"agent", strings.Repeat(" ", 4097)},
		{"agent", `{"type":"error","code":"` + strings.Repeat("\u00e9", 800) + `"}`},
	} {
		if _, err := parseTerminalControl([]byte(tt.text), tt.role); err == nil {
			t.Fatalf("invalid %s control accepted: %s", tt.role, tt.text)
		}
	}
	frame, err := parseTerminalControl([]byte(`{"type":"ack","bytes":9007199254740991}`), "broker")
	if err != nil || frame.Bytes != 9007199254740991 {
		t.Fatal("safe cumulative ack corrupted")
	}
}

func TestTerminalEndpointAndIndependentHeaders(t *testing.T) {
	for _, tt := range []struct{ raw, session, want string }{
		{"https://worker.example/update", "", "wss://worker.example/api/agent/terminal/control"},
		{"https://worker.example:8443/update?secret=discarded#fragment", "S_1", "wss://worker.example:8443/api/agent/terminal/session/S_1"},
		{"https://[::1]:8443/update", "", "wss://[::1]:8443/api/agent/terminal/control"},
	} {
		got, err := terminalWebSocketURL(tt.raw, tt.session)
		if err != nil || got != tt.want {
			t.Fatalf("endpoint = %q, err=%v", got, err)
		}
	}
	for _, raw := range []string{"http://worker.example/update", "wss://worker.example/update", "https://user@worker.example/update", "https://test:%61@worker.example/update", "https:///update", "https://worker.example:bad/update", "https://worker.example/%zz"} {
		if _, err := terminalWebSocketURL(raw, ""); err == nil || strings.Contains(err.Error(), raw) {
			t.Fatal("unsafe endpoint accepted or leaked")
		}
	}
	for _, id := range []string{"../s", "s?token=1", strings.Repeat("a", 129)} {
		if _, err := terminalWebSocketURL("https://worker.example/update", id); err == nil {
			t.Fatal("unsafe session path accepted")
		}
	}
	cfg := Config{ServerID: "node1", Secret: "reporting-secret", TerminalToken: strings.Repeat("a", 64)}
	h, err := terminalWebSocketHeaders(cfg, "")
	if err != nil || h.Get("Authorization") != "Bearer "+cfg.TerminalToken || h.Get("X-CFSM-Server-Id") != "node1" || strings.Contains(h.Get("Authorization"), cfg.Secret) {
		t.Fatal("independent node authentication failed")
	}
	h, err = terminalWebSocketHeaders(cfg, strings.Repeat("b", 64))
	if err != nil || h.Get("X-CFSM-Terminal-Ticket") != strings.Repeat("b", 64) {
		t.Fatal("header ticket missing")
	}
	for _, bad := range []Config{{ServerID: "node1", Secret: cfg.Secret}, {ServerID: "bad\r\n", TerminalToken: cfg.TerminalToken}} {
		if _, err := terminalWebSocketHeaders(bad, ""); err == nil {
			t.Fatal("invalid node identity accepted")
		}
	}
	if _, err := terminalWebSocketHeaders(cfg, "invalid"); err == nil {
		t.Fatal("invalid ticket accepted")
	}
}
