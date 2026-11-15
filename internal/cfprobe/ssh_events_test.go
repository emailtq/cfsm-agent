package cfprobe

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSSHAcceptedOnly(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	good := []string{
		"Nov 16 12:00:00 fixture sshd[42]: Accepted publickey for alice from 127.0.0.1 port 50000 ssh2: RSA SHA256:private-fingerprint",
		"2026-11-16T12:00:00+00:00 fixture sshd-session[42]: Accepted password for root from ::1 port 50000 ssh2",
		"2026-11-16T12:00:00+00:00 fixture sshd-auth[42]: Accepted publickey for 域\\用户 from fe80::1%eth0 port 50000 ssh2",
	}
	for _, line := range good {
		e, ok := parseSSHAccepted(line, now)
		if !ok || e.User == "" || e.Address == "" {
			t.Fatalf("not accepted: %q", line)
		}
		b, _ := json.Marshal(e)
		if string(b) == line {
			t.Fatal("raw log exposed")
		}
	}
	for _, line := range []string{"Failed password for root from 127.0.0.1", "fixture app[42]: Accepted publickey for alice from 127.0.0.1 port 50 ssh2", "Nov 16 12:00:00 fixture sshd[42]: pam_unix(sshd:session): session opened for user root", "Welcome to Alpine!"} {
		if _, ok := parseSSHAccepted(line, now); ok {
			t.Fatalf("false SSH success %q", line)
		}
	}
}

func TestSSHHTTPSActualTransportOnlyReleasesDurablyAcknowledgedQueue(t *testing.T) {
	if runReportTLSFixture(t) {
		return
	}
	acknowledge := false
	var stream string
	token := strings.Repeat("a", 64)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("SSH report did not use node bearer")
		}
		var p struct {
			SSH sshEventReport `json:"ssh_events"`
		}
		if json.NewDecoder(r.Body).Decode(&p) != nil || len(p.SSH.Events) != 1 {
			t.Error("real transport omitted queued SSH success")
		}
		if acknowledge {
			encoded, _ := json.Marshal(sshEventAck{Stream: stream, Sequence: 1})
			w.Header().Set("X-CFSM-Ssh-Ack", string(encoded))
		}
		w.Write([]byte("OK"))
	}))
	defer server.Close()
	cfg := Config{ServerID: "node-a", WorkerURL: server.URL + "/update", NodeToken: token, SSHLoginEnabled: true}
	c := newSSHEventCollector(filepath.Join(t.TempDir(), "state.json"))
	stream = "https-fixture"
	c.state = sshCollectorState{Identity: sshConfigIdentity(cfg), Stream: stream, Events: []sshLoginEvent{{Sequence: 1, OccurredAt: time.Now().UnixMilli(), User: "fixture", Address: "127.0.0.1", Method: "password"}}}
	a := &Agent{cfg: cfg, sshEvents: c}
	body, _, err := a.buildReportBodyForConfig(cfg, Metrics{CPU: "1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if status, err := a.postReportBody(cfg, body, 0, false); err != nil || status != 200 {
		t.Fatalf("HTTPS transport %d %v", status, err)
	}
	if len(c.snapshot().Events) != 1 {
		t.Fatal("HTTPS 200 without event receipt lost queue")
	}
	acknowledge = true
	if status, err := a.postReportBody(cfg, body, 0, false); err != nil || status != 200 {
		t.Fatalf("HTTPS ACK %d %v", status, err)
	}
	if len(c.snapshot().Events) != 0 {
		t.Fatal("real HTTPS event ACK did not release queue")
	}
}

func TestSSHReportUsesExistingClockCalibrationWithoutChangingQueueIdentity(t *testing.T) {
	now := time.Now()
	cfg := Config{ServerID: "fixture", WorkerURL: "https://example.test/update", NodeToken: "fixture-identity", SSHLoginEnabled: true}
	c := newSSHEventCollector(filepath.Join(t.TempDir(), "state.json"))
	c.state = sshCollectorState{Identity: sshConfigIdentity(cfg), Stream: "fixture", Events: []sshLoginEvent{{Sequence: 1, OccurredAt: now.UnixMilli(), User: "alice", Address: "127.0.0.1", Method: "password"}}}
	a := &Agent{cfg: cfg, sshEvents: c}
	a.clock.updateDate(now.Add(-time.Hour).UnixMilli(), time.Millisecond, now)
	body, _, err := a.buildReportBodyForConfig(cfg, Metrics{}, now)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		SSH sshEventReport `json:"ssh_events"`
	}
	json.Unmarshal(body, &p)
	if p.SSH.Events[0].OccurredAt >= now.Add(-59*time.Minute).UnixMilli() {
		t.Fatal("SSH time ignored the existing calibrated Date offset")
	}
	if c.state.Events[0].OccurredAt != now.UnixMilli() || p.SSH.Events[0].Sequence != 1 {
		t.Fatal("calibration mutated durable queue/identity")
	}
}

func TestSSHActualReportBodyAndHTTPWSSAck(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "auth.log")
	state := filepath.Join(dir, "state.json")
	cfg := Config{ServerID: "node-a", WorkerURL: "https://example.test/update", NodeToken: strings.Repeat("a", 64), SSHLoginEnabled: true}
	now := time.Now()
	if err := os.WriteFile(log, nil, 0600); err != nil {
		t.Fatal(err)
	}
	c := newSSHEventCollector(state)
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	line := now.Format("Jan 2 15:04:05") + " fixture sshd[42]: Accepted publickey for fixture-user from 127.0.0.1 port 50 ssh2: RSA SHA256:not-reported\n"
	if err := os.WriteFile(log, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: cfg, sshEvents: c}
	body, _, err := a.buildReportBodyForConfig(cfg, Metrics{CPU: "5"}, now)
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]json.RawMessage
	if err = json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(report["metrics"]), "fixture-user") || strings.Contains(string(body), "not-reported") {
		t.Fatal("SSH details exposed in metrics/raw fingerprint")
	}
	if path := os.Getenv("CFSM_SSH_REPORT_FIXTURE"); path != "" {
		if err = os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	a.handleReportResponse(200, []byte("OK"), http.Header{})
	if len(c.snapshot().Events) != 1 {
		t.Fatal("ordinary HTTP 2xx silently discarded event")
	}
	ack := sshEventAck{Stream: c.snapshot().Stream, Sequence: 1}
	encoded, _ := json.Marshal(ack)
	a.handleReportResponse(200, []byte("OK"), http.Header{"X-Cfsm-Ssh-Ack": []string{string(encoded)}})
	if len(c.snapshot().Events) != 0 {
		t.Fatal("durable HTTP event ACK not consumed")
	}
	if err = os.WriteFile(log, []byte(line+line), 0600); err != nil {
		t.Fatal(err)
	}
	if err = c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	next := c.snapshot()
	ack.Sequence = next.Events[0].Sequence
	for _, hint := range []bool{true, false} {
		packet, _ := json.Marshal(map[string]any{"type": "ack", "realtimeHint": hint, "ssh_ack": ack})
		client, server := net.Pipe()
		conn := &webSocketConn{conn: client, reader: bufio.NewReader(client)}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			server.Write(terminalTestFrame(wsOpcodeText, true, packet))
		}()
		(&reportTransport{agent: a}).readLoop(context.Background(), conn)
		client.Close()
		<-done
		if hint && len(c.snapshot().Events) != 1 {
			t.Fatal("realtime hint consumed unconfirmed event")
		}
	}
	if len(c.snapshot().Events) != 0 {
		t.Fatal("actual WSS ACK frame did not release queue")
	}
	changed := cfg
	changed.NodeToken = strings.Repeat("b", 64)
	if len(c.snapshotForConfig(changed).Events) != 0 {
		t.Fatal("old credential events crossed new reporting identity")
	}
}

func TestSSHLongPartialLogAndDisableKeepUnconfirmedQueue(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "auth.log")
	state := filepath.Join(dir, "state.json")
	if err := os.WriteFile(log, nil, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{ServerID: "fixture", WorkerURL: "https://example.test/update", NodeToken: "fixture-identity", SSHLoginEnabled: true}
	c := newSSHEventCollector(state)
	now := time.Now()
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	line := now.Format("Jan 2 15:04:05") + " fixture sshd[42]: Accepted password for alice from 127.0.0.1 port 50 ssh2\n"
	if err := os.WriteFile(log, []byte(strings.Repeat("x", 140000)+"\n"+line), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := c.collectFile(cfg, log, now); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.snapshot().Events) != 1 {
		t.Fatal("oversized non-SSH line stalled collector")
	}
	cfg.SSHLoginEnabled = false
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	if len(c.snapshot().Events) != 1 {
		t.Fatal("disable silently lost an unconfirmed event")
	}
}

func TestSSHCopytruncateRegrownBeforePollIsVisible(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "auth.log")
	c := newSSHEventCollector(filepath.Join(dir, "state.json"))
	now := time.Now()
	cfg := Config{ServerID: "fixture", WorkerURL: "https://example.test/update", NodeToken: "fixture-identity", SSHLoginEnabled: true}
	os.WriteFile(log, nil, 0600)
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	old := now.Format("Jan 2 15:04:05") + " fixture sshd[42]: Accepted publickey for alice from 127.0.0.1 port 50 ssh2\n"
	os.WriteFile(log, []byte(old), 0600)
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	fresh := now.Format("Jan 2 15:04:05") + " fixture sshd[43]: Accepted password for bob from 127.0.0.2 port 51 ssh2\n" + strings.Repeat("z", len(old)) + "\n"
	os.WriteFile(log, []byte(fresh), 0600)
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	report := c.snapshot()
	if report.State != "rotation_gap" || len(report.Events) != 2 || report.Events[1].User != "bob" {
		t.Fatalf("unobserved truncate/regrow lost event: %+v", report)
	}
}

func TestSSHQueueIsBoundedAndCannotAckUnreportedEvents(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "auth.log")
	c := newSSHEventCollector(filepath.Join(dir, "state.json"))
	now := time.Now()
	cfg := Config{ServerID: "fixture", WorkerURL: "https://example.test/update", NodeToken: "fixture-identity", SSHLoginEnabled: true}
	os.WriteFile(log, nil, 0600)
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	line := now.Format("Jan 2 15:04:05") + " fixture sshd[42]: Accepted password for alice from 127.0.0.1 port 50 ssh2\n"
	os.WriteFile(log, []byte(strings.Repeat(line, sshQueueLimit+10)), 0600)
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	first := c.snapshot()
	if len(c.state.Events) != sshQueueLimit || len(first.Events) != 32 || first.State != "queue_full" {
		t.Fatal("unbounded SSH queue/report")
	}
	c.ack(sshEventAck{Stream: first.Stream, Sequence: 1000})
	if len(c.state.Events) != sshQueueLimit {
		t.Fatal("ACK released events never offered to Worker")
	}
	c.ack(sshEventAck{Stream: first.Stream, Sequence: 32})
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	if c.state.Sequence != sshQueueLimit+10 || len(c.state.Events) != sshQueueLimit+10-32 {
		t.Fatal("queue backpressure lost unread log records")
	}
}

func TestSSHIdleStatusUsesExistingConfigHeartbeatAndStateChanges(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "auth.log")
	c := newSSHEventCollector(filepath.Join(dir, "state.json"))
	now := time.Now()
	cfg := Config{ServerID: "fixture", WorkerURL: "https://example.test/update", NodeToken: "fixture-identity", SSHLoginEnabled: true}
	os.WriteFile(log, nil, 0600)
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: cfg, sshEvents: c}
	read := func(at time.Time) map[string]json.RawMessage {
		body, _, err := a.buildReportBodyForConfig(cfg, Metrics{}, at)
		if err != nil {
			t.Fatal(err)
		}
		var p map[string]json.RawMessage
		json.Unmarshal(body, &p)
		return p
	}
	if read(now)["ssh_events"] == nil {
		t.Fatal("initial source status absent")
	}
	if read(now.Add(time.Second))["ssh_events"] != nil {
		t.Fatal("idle 2s metrics report added a D1 event-status write")
	}
	c.code = "permission_denied"
	if read(now.Add(2 * time.Second))["ssh_events"] == nil {
		t.Fatal("permission failure waited for next heartbeat")
	}
	if read(now.Add(time.Minute))["ssh_events"] == nil {
		t.Fatal("source heartbeat absent")
	}
}

func TestSSHFileCursorQueueRestartRotationAndAck(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "ssh-events.json")
	log := filepath.Join(dir, "auth.log")
	cfg := Config{ServerID: "fixture", WorkerURL: "https://example.test/update", NodeToken: "fixture-identity", SSHLoginEnabled: true}
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	line := "Nov 16 12:00:00 fixture sshd[42]: Accepted publickey for alice from 127.0.0.1 port 50 ssh2\n"
	if err := os.WriteFile(log, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	c := newSSHEventCollector(state)
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	if len(c.snapshot().Events) != 0 {
		t.Fatal("replayed pre-enable login")
	}
	appendLog := func(path, text string) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err = f.WriteString(text); err != nil {
			t.Fatal(err)
		}
	}
	appendLog(log, line)
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	one := c.snapshot()
	if len(one.Events) != 1 || one.Events[0].Sequence != 1 {
		t.Fatalf("event %+v", one)
	}
	c = newSSHEventCollector(state)
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	if len(c.snapshot().Events) != 1 {
		t.Fatal("restart lost or duplicated unconfirmed event")
	}
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	appendLog(log+".1", line)
	if err := os.WriteFile(log, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	all := c.snapshot()
	if len(all.Events) != 3 {
		t.Fatalf("rotation event count %d", len(all.Events))
	}
	c.ack(sshEventAck{Stream: all.Stream, Sequence: 2})
	if len(c.snapshot().Events) != 1 {
		t.Fatal("ACK did not release exact queue prefix")
	}
	c.ack(sshEventAck{Stream: "other", Sequence: 3})
	if len(c.snapshot().Events) != 1 {
		t.Fatal("foreign stream ACK released event")
	}
	c = newSSHEventCollector(state)
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	if len(c.snapshot().Events) != 1 || c.snapshot().Events[0].Sequence != 3 {
		t.Fatal("ACK state not durable")
	}
	if err := os.WriteFile(log, []byte("short\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.collectFile(cfg, log, now); err != nil {
		t.Fatal(err)
	}
	if c.snapshot().State != "rotation_gap" {
		t.Fatal("copytruncate gap not visible")
	}
}

func TestSSHJournalStructuredCursor(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	c := newSSHEventCollector(filepath.Join(dir, "ssh-events.json"))
	cfg := Config{ServerID: "fixture", WorkerURL: "https://example.test/update", NodeToken: "fixture-identity", SSHLoginEnabled: true}
	baseline := []byte(`{"__CURSOR":"cursor0","__REALTIME_TIMESTAMP":"1794830400000000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted publickey for alice from 127.0.0.1 port 50 ssh2"}` + "\n")
	if err := c.collectJournalRecords(cfg, baseline, true, now); err != nil {
		t.Fatal(err)
	}
	next := []byte(`{"__CURSOR":"cursor1","__REALTIME_TIMESTAMP":"1794830400000000","SYSLOG_IDENTIFIER":"sshd-session","MESSAGE":"Accepted password for alice from 127.0.0.1 port 50 ssh2"}` + "\n")
	if err := c.collectJournalRecords(cfg, next, false, now); err != nil {
		t.Fatal(err)
	}
	if len(c.snapshot().Events) != 1 || c.state.JournalCursor != "cursor1" {
		t.Fatal("journal cursor not committed with queue")
	}
	if err := c.collectJournalRecords(cfg, next, false, now); err != nil {
		t.Fatal(err)
	}
	if len(c.snapshot().Events) != 1 {
		t.Fatal("journal duplicate replay")
	}
	nonText := []byte(`{"__CURSOR":"cursor2","__REALTIME_TIMESTAMP":"1794830400000000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":[255,254,0]}` + "\n")
	fresh := []byte(strings.Replace(string(next), "cursor1", "cursor3", 1))
	if err := c.collectJournalRecords(cfg, append(nonText, fresh...), false, now); err != nil {
		t.Fatal("non-text journal record stalled later authentication:", err)
	}
	if len(c.snapshot().Events) != 2 || c.state.JournalCursor != "cursor3" {
		t.Fatal("non-authentication journal record changed success or cursor semantics")
	}
}
