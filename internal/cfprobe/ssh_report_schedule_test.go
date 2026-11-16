package cfprobe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func sshScheduleRow(sequence int, now time.Time) []byte {
	return []byte(fmt.Sprintf(`{"__CURSOR":"cursor-%d","__REALTIME_TIMESTAMP":"%d","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted password for fixture-user from 127.0.0.1 port 50 ssh2"}`+"\n", sequence, now.UnixMicro()))
}

func TestSSHCollectorWakeDrainsRealReportLoopHTTPWSS(t *testing.T) {
	for _, mode := range []string{"http", "wss", "fallback", "schedule-http"} {
		t.Run(mode, func(t *testing.T) {
			if runReportTLSFixture(t) {
				return
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			type receipt struct {
				at     time.Time
				report sshEventReport
			}
			received := make(chan receipt, 8)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer "+testNodeToken {
					t.Error("missing node bearer")
					return
				}
				accept := func(body []byte) []byte {
					var p struct {
						SSH sshEventReport `json:"ssh_events"`
					}
					if json.Unmarshal(body, &p) != nil || len(p.SSH.Events) == 0 {
						t.Error("unexpected idle/empty event report")
						return nil
					}
					received <- receipt{time.Now(), p.SSH}
					ack, _ := json.Marshal(sshEventAck{Stream: p.SSH.Stream, Sequence: p.SSH.Events[len(p.SSH.Events)-1].Sequence})
					return ack
				}
				if r.Method == http.MethodPost {
					var body json.RawMessage
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						t.Error("invalid HTTP body")
						return
					}
					w.Header().Set("X-CFSM-Ssh-Ack", string(accept(body)))
					fmt.Fprint(w, "OK")
					return
				}
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", expectedWebSocketAccept(r.Header.Get("Sec-WebSocket-Key")))
				if rw.Flush() != nil {
					return
				}
				ws := &webSocketConn{conn: conn, reader: rw.Reader}
				ws.writeFrame(wsOpcodeText, []byte(`{"type":"hello","ts":1,"protocol":"update"}`), time.Second)
				for {
					body, _, err := ws.ReadDataMessage()
					if err != nil {
						return
					}
					packet := append([]byte(`{"type":"ack","ssh_ack":`), accept(body)...)
					if ws.writeFrame(wsOpcodeText, append(packet, '}'), time.Second) != nil {
						return
					}
				}
			}))
			defer server.Close()
			cfg := defaultConfig()
			cfg.WorkerURL, cfg.ServerID, cfg.NodeToken = server.URL+"/update", "node-a", testNodeToken
			cfg.ReportInterval, cfg.CollectInterval, cfg.SSHLoginEnabled = 180, 0, true
			if mode == "http" {
				cfg.ConnectionMode = connectionModeHTTP
			}
			now := time.Now()
			c := newSSHEventCollector(filepath.Join(t.TempDir(), "ssh-events.json"))
			if err := c.collectJournalRecords(cfg, nil, true, now); err != nil {
				t.Fatal(err)
			}
			a := &Agent{cfg: cfg, ctx: ctx, sshEvents: c, log: newLogger(false), wake: make(chan struct{}, 1), lastPost: now, lastPostAttempt: now, lastReport: now, fullAt: now}
			c.wake = a.wake
			a.reporter = newReportTransport(a)
			a.reporter.setNextReportAfterMs(180000)
			var readerDone chan struct{}
			if mode == "wss" {
				conn, _, _, _, err := a.reporter.dial(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if _, err := a.reporter.waitHello(conn); err != nil {
					t.Fatal(err)
				}
				a.reporter.conn = conn
				readerDone = make(chan struct{})
				go func() { defer close(readerDone); a.reporter.readLoop(ctx, conn) }()
			}
			if mode == "schedule-http" {
				a.disableWSSRuntime(agentWSSScheduleInactive)
			}
			loopDone := make(chan struct{})
			go func() { defer close(loopDone); a.loop(ctx) }()
			defer func() {
				cancel()
				<-loopDone
				if readerDone != nil {
					<-readerDone
				}
			}()
			startedAt := time.Now()
			// A normal collector poll persists 65 authentications before waking the single report writer.
			time.Sleep(time.Second)
			var rows []byte
			for i := 1; i <= 65; i++ {
				rows = append(rows, sshScheduleRow(i, now)...)
			}
			if err := c.collectJournalRecords(cfg, rows, false, now); err != nil {
				t.Fatal(err)
			}
			queuedAt := time.Now()
			var lastAt time.Time
			for batch, count := range []int{32, 32, 1} {
				select {
				case got := <-received:
					if len(got.report.Events) != count || got.report.Events[0].Sequence != int64(batch*32+1) {
						t.Fatal("ACK did not advance offered prefix")
					}
					if !lastAt.IsZero() && got.at.Sub(lastAt) < 900*time.Millisecond {
						t.Fatal("backlog report burst bypassed pacing")
					}
					t.Logf("%s batch=%d append/poll-to-receive=%s durable-queue-to-receive=%s", mode, batch, got.at.Sub(startedAt), got.at.Sub(queuedAt))
					lastAt = got.at
				case <-time.After(15 * time.Second):
					t.Fatal("new events/backlog waited for regular 180s interval")
				}
			}
			deadline := time.Now().Add(time.Second)
			for len(c.snapshot().Events) > 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if len(c.snapshot().Events) != 0 {
				t.Fatal("ACK did not durably drain queue")
			}
			t.Logf("%s final durable ACK after queue=%s", mode, time.Since(queuedAt))
			select {
			case <-received:
				t.Fatal("empty queue increased idle report rate")
			case <-time.After(1200 * time.Millisecond):
			}
			if a.tickInterval() != 180*time.Second {
				t.Fatal("idle metrics cadence changed")
			}
		})
	}
}

func TestSSHUnchangedQueueDisabledIdentityAndFailedPersistenceDoNotWake(t *testing.T) {
	cfg := Config{WorkerURL: "https://example.test/update", ServerID: "node-a", NodeToken: testNodeToken, SSHLoginEnabled: true}
	c := newSSHEventCollector(filepath.Join(t.TempDir(), "state.json"))
	c.wake = make(chan struct{}, 1)
	now := time.Now()
	if err := c.collectJournalRecords(cfg, nil, true, now); err != nil {
		t.Fatal(err)
	}
	if len(c.wake) != 0 {
		t.Fatal("baseline created unnecessary wake")
	}
	if err := c.collectJournalRecords(cfg, sshScheduleRow(1, now), false, now); err != nil {
		t.Fatal(err)
	}
	if len(c.wake) != 1 {
		t.Fatal("durable event did not wake")
	}
	<-c.wake
	if err := c.collectJournalRecords(cfg, sshScheduleRow(1, now), false, now); err != nil {
		t.Fatal(err)
	}
	if len(c.wake) != 0 {
		t.Fatal("unchanged queue woke reporting")
	}
	for _, other := range []Config{func() Config { x := cfg; x.SSHLoginEnabled = false; return x }(), func() Config { x := cfg; x.NodeToken = "other"; return x }()} {
		if c.pendingReport(other, sshEventAck{}).Sequence != 0 {
			t.Fatal("disabled/mismatched identity forced queue report")
		}
	}
	bad := newSSHEventCollector(filepath.Join(t.TempDir(), "parent", "state.json"))
	if err := os.WriteFile(filepath.Dir(bad.path), nil, 0600); err != nil {
		t.Fatal(err)
	}
	bad.loaded = true
	bad.state = c.state
	bad.wake = c.wake
	if err := bad.collectJournalRecords(cfg, sshScheduleRow(2, now), false, now); err == nil {
		t.Fatal("state failure accepted")
	}
	if len(bad.wake) != 0 || len(bad.state.Events) != 1 {
		t.Fatal("unpersisted event woke or changed queue")
	}
}

func TestSSHNewEventReportsBeforeHighHTTPInterval(t *testing.T) {
	if runReportTLSFixture(t) {
		return
	}
	received := make(chan time.Time, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body json.RawMessage
		var payload struct {
			SSH sshEventReport `json:"ssh_events"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || json.Unmarshal(body, &payload) != nil || len(payload.SSH.Events) != 1 {
			t.Error("scheduled report omitted SSH event")
			return
		}
		if file := os.Getenv("CFSM_SSH_REPORT_FIXTURE"); file != "" {
			if err := os.WriteFile(file, body, 0600); err != nil {
				t.Error(err)
			}
		}
		received <- time.Now()
		ack, _ := json.Marshal(sshEventAck{Stream: payload.SSH.Stream, Sequence: 1})
		w.Header().Set("X-CFSM-Ssh-Ack", string(ack))
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()
	cfg := defaultConfig()
	cfg.WorkerURL, cfg.ServerID, cfg.NodeToken = server.URL+"/update", "node-a", testNodeToken
	cfg.ConnectionMode, cfg.ReportInterval, cfg.CollectInterval, cfg.SSHLoginEnabled = connectionModeHTTP, 180, 0, true
	now := time.Now()
	c := newSSHEventCollector(filepath.Join(t.TempDir(), "ssh-events.json"))
	if err := c.collectJournalRecords(cfg, nil, true, now); err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: cfg, sshEvents: c, log: newLogger(false), lastPost: now.Add(-2 * time.Second), lastPostAttempt: now.Add(-2 * time.Second), fullAt: now}
	row := fmt.Sprintf(`{"__CURSOR":"new","__REALTIME_TIMESTAMP":"%d","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted password for fixture-user from 127.0.0.1 port 50 ssh2"}`+"\n", now.UnixMicro())
	if err := c.collectJournalRecords(cfg, []byte(row), false, now); err != nil {
		t.Fatal(err)
	}
	queuedAt := time.Now()
	a.tick()
	select {
	case sentAt := <-received:
		t.Logf("durable enqueue to real HTTPS receive=%s", sentAt.Sub(queuedAt))
		limit := 3 * time.Second
		if runtime.GOOS == "windows" {
			limit = 10 * time.Second
		}
		if sentAt.Sub(queuedAt) > limit {
			t.Fatal("event not sent promptly")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("new SSH event waited for the 180s metrics interval")
	}
	if len(c.snapshot().Events) != 0 {
		t.Fatal("real HTTPS ACK did not clear queue")
	}
}

func TestSSHNewEventsRespectFailedPOSTProtocolPauseAndReportBreaker(t *testing.T) {
	if runReportTLSFixture(t) {
		return
	}
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; http.Error(w, "fixture failure", 503) }))
	defer server.Close()
	cfg := defaultConfig()
	cfg.WorkerURL, cfg.ServerID, cfg.NodeToken = server.URL+"/update", "node-a", testNodeToken
	cfg.ConnectionMode, cfg.ReportInterval, cfg.CollectInterval, cfg.SSHLoginEnabled = connectionModeHTTP, 180, 0, true
	now := time.Now()
	c := newSSHEventCollector(filepath.Join(t.TempDir(), "state.json"))
	if err := c.collectJournalRecords(cfg, nil, true, now); err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: cfg, sshEvents: c, log: newLogger(false), fullAt: now}
	if result := a.sendReport(cfg, Metrics{CPU: "1"}, false, true, 180*time.Second); result.ok {
		t.Fatal("failed POST reported success")
	}
	if err := c.collectJournalRecords(cfg, sshScheduleRow(1, now), false, now); err != nil {
		t.Fatal(err)
	}
	a.tick()
	if requests != 1 || a.tickInterval() < 170*time.Second {
		t.Fatal("new event bypassed existing failure throttle")
	}
	a.lastPostAttempt = now.Add(-181 * time.Second)
	a.reporter = newReportTransport(a)
	a.setConfig(func() Config { x := cfg; x.ConnectionMode = connectionModeAuto; return x }())
	a.reporter.delayProtocol("fixture rejected protocol")
	a.tick()
	if requests != 1 {
		t.Fatal("SSH bypassed protocol fallback pause")
	}
	a.setConfig(cfg)
	a.reportPausedUntil = now.Add(time.Minute)
	a.tick()
	if requests != 1 {
		t.Fatal("SSH bypassed report circuit breaker")
	}
	a.reportPausedUntil = time.Time{}
	a.tick()
	if requests != 2 || len(c.snapshot().Events) != 1 {
		t.Fatal("due retry failed to preserve unacknowledged queue")
	}
	// No new candidate or ACK: do not create an immediate retry loop.
	a.tick()
	if requests != 2 {
		t.Fatal("unchanged old queue retried immediately")
	}
}
