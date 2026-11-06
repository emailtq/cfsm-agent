package cfprobe

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type controlTLSAttachment struct {
	id, node, auth, ticket, query string
	peer                          *webSocketConn
}

type controlTLSFixture struct {
	server   *httptest.Server
	attached chan controlTLSAttachment
	mu       sync.Mutex
	conns    []net.Conn
}

func newControlTLSFixture(t *testing.T) *controlTLSFixture {
	t.Helper()
	f := &controlTLSFixture{attached: make(chan controlTLSAttachment, 64)}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.conns = append(f.conns, conn)
		f.mu.Unlock()
		_, err = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", expectedWebSocketAccept(r.Header.Get("Sec-WebSocket-Key")))
		if err != nil || rw.Flush() != nil {
			_ = conn.Close()
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/agent/terminal/session/")
		if r.URL.Path == "/api/agent/terminal/control" {
			id = ""
		}
		f.attached <- controlTLSAttachment{id: id, node: r.Header.Get("X-CFSM-Server-Id"), auth: r.Header.Get("Authorization"), ticket: r.Header.Get("X-CFSM-Terminal-Ticket"), query: r.URL.RawQuery, peer: &webSocketConn{conn: conn, reader: rw.Reader}}
	}))
	t.Cleanup(func() {
		f.server.Close()
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, c := range f.conns {
			_ = c.Close()
		}
	})
	return f
}

func (f *controlTLSFixture) next(t *testing.T) controlTLSAttachment {
	t.Helper()
	select {
	case a := <-f.attached:
		return a
	case <-time.After(2 * time.Second):
		t.Fatal("missing TLS attachment")
	}
	return controlTLSAttachment{}
}

func controlTLSRead(t *testing.T, p *webSocketConn) sessionTestFrame {
	t.Helper()
	_ = p.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame, err := p.readFrame()
	if err != nil {
		t.Fatalf("TLS read: %v", err)
	}
	if !frame.fin || len(frame.payload) > 16384 {
		t.Fatal("invalid client frame")
	}
	return sessionTestFrame{data: frame.payload, op: frame.opcode}
}

func controlTLSSend(t *testing.T, p *webSocketConn, op byte, text string) {
	t.Helper()
	_ = p.conn.SetWriteDeadline(time.Now().Add(time.Second))
	if err := writeAll(p.conn, terminalTestFrame(op, true, []byte(text))); err != nil {
		t.Fatal(err)
	}
	_ = p.conn.SetWriteDeadline(time.Time{})
}

func controlOpen(id string) string {
	return `{"type":"open","protocol":1,"sessionId":"` + id + `","ticket":"` + strings.Repeat("b", 64) + `","cols":80,"rows":24}`
}

// Trusted fixture roots exist only in this child process; product TLS is unchanged.
func TestTerminalControlTLS(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestTerminalControlTLSHelper$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "GODEBUG=x509usefallbackroots=1", "CFSM_CONTROL_TLS_HELPER=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("TLS helper: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

func TestTerminalControlTLSHelper(t *testing.T) {
	if os.Getenv("CFSM_CONTROL_TLS_HELPER") != "1" {
		return
	}
	f := newControlTLSFixture(t)
	roots := x509.NewCertPool()
	cert, err := x509.ParseCertificate(f.server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(cert)
	x509.SetFallbackRoots(roots)
	for _, mode := range []string{"disabled", "http_reporting", "inactive_reporting", "binding", "replacement", "control_loss", "capacity_timeout", "protocol_error", "oversize", "data_disconnect", "two_sessions_bounds"} {
		t.Run(mode, func(t *testing.T) {
			cfg := Config{TerminalEnabled: true, TerminalToken: strings.Repeat("a", 64), ServerID: "node", WorkerURL: f.server.URL + "/update?report_secret=discard", ConnectionMode: connectionModeHTTP}
			if mode == "binding" {
				cfg.ServerID = ""
			}
			if mode == "disabled" {
				cfg.TerminalEnabled = false
			}
			a := newDiscoveryTestAgent(t, cfg)
			a.terminalChanged = make(chan struct{}, 1)
			a.reporter = &reportTransport{agent: a}
			a.reportPausedUntil = time.Now().Add(time.Hour)
			if mode == "inactive_reporting" {
				a.disableWSSRuntime(agentWSSScheduleInactive)
			}
			var mu sync.Mutex
			var processes []*sessionTestProcess
			opts := defaultTerminalControlOptions()
			opts.preflight = func(context.Context) error { return nil }
			opts.retryMin = 5 * time.Millisecond
			opts.retryMax = 10 * time.Millisecond
			opts.startTimeout = 100 * time.Millisecond
			opts.heartbeat = time.Hour
			opts.factory = func(uint16, uint16) (terminalProcess, error) {
				p := newSessionTestProcess()
				mu.Lock()
				processes = append(processes, p)
				mu.Unlock()
				return p, nil
			}
			count := func() int { mu.Lock(); defer mu.Unlock(); return len(processes) }
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() { defer close(done); a.runTerminalWorker(ctx, opts) }()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Error("TLS worker did not join")
				}
			}()
			if mode == "disabled" {
				time.Sleep(30 * time.Millisecond)
				if len(f.attached) != 0 {
					t.Fatal("disabled terminal connected TLS")
				}
				return
			}
			if mode == "binding" {
				time.Sleep(30 * time.Millisecond)
				if len(f.attached) != 0 {
					t.Fatal("connected before boundID")
				}
				a.applyAutoDiscoveryHeaders(discoveryHeaders(agentAutoDiscoveryCreated, "node"))
			}
			control := f.next(t)
			if control.id != "" || control.auth != "Bearer "+strings.Repeat("a", 64) || control.node != "node" || control.ticket != "" || control.query != "" {
				t.Fatal("control identity/header isolation")
			}
			if frame := controlTLSRead(t, control.peer); string(frame.data) != `{"type":"hello","protocol":1,"platform":"linux","capabilities":["terminal.pty.v1"]}` {
				t.Fatalf("hello %s", frame.data)
			}
			defer control.peer.Close()
			if mode == "protocol_error" || mode == "oversize" {
				text := `{"type":"open","protocol":2}`
				if mode == "oversize" {
					text = strings.Repeat("x", 4097)
				}
				controlTLSSend(t, control.peer, wsOpcodeText, text)
				next := f.next(t)
				_ = controlTLSRead(t, next.peer)
				_ = next.peer.Close()
				if count() != 0 {
					t.Fatal("invalid control spawned PTY")
				}
				return
			}
			controlTLSSend(t, control.peer, wsOpcodeText, controlOpen("S1"))
			data := f.next(t)
			defer data.peer.Close()
			if data.id != "S1" || data.ticket != strings.Repeat("b", 64) || data.query != "" || data.auth != control.auth {
				t.Fatal("session ticket/header isolation")
			}
			if count() != 0 {
				t.Fatal("PTY before start")
			}
			if mode == "capacity_timeout" {
				controlTLSSend(t, control.peer, wsOpcodeText, controlOpen("S1"))
				for _, id := range []string{"S2", "S3", "S4"} {
					controlTLSSend(t, control.peer, wsOpcodeText, controlOpen(id))
					p := f.next(t)
					defer p.peer.Close()
				}
				controlTLSSend(t, control.peer, wsOpcodeText, controlOpen("S5"))
				time.Sleep(30 * time.Millisecond)
				if len(f.attached) != 0 || count() != 0 {
					t.Fatal("duplicate/fifth admitted")
				}
				time.Sleep(120 * time.Millisecond)
				controlTLSSend(t, control.peer, wsOpcodeText, controlOpen("REUSE"))
				next := f.next(t)
				defer next.peer.Close()
				if next.id != "REUSE" {
					t.Fatal("timeout did not release slots")
				}
				controlTLSSend(t, next.peer, wsOpcodeText, `{"type":"start","cols":80,"rows":24}`)
				if string(controlTLSRead(t, next.peer).data) != `{"type":"ready"}` {
					t.Fatal("reuse not ready")
				}
				return
			}
			if mode == "replacement" || mode == "control_loss" {
				if mode == "replacement" {
					next := a.configSnapshot()
					next.TerminalToken = strings.Repeat("c", 64)
					next.ServerID = "node2"
					a.setConfig(next)
				} else {
					_ = control.peer.Close()
				}
				next := f.next(t)
				defer next.peer.Close()
				_ = controlTLSRead(t, next.peer)
				if mode == "replacement" && (next.node != "node2" || next.auth != "Bearer "+strings.Repeat("c", 64)) {
					t.Fatal("replacement used old identity")
				}
				_ = data.peer.SetReadDeadline(time.Now().Add(time.Second))
				if _, _, err := data.peer.ReadDataMessageLimit(4096); err == nil {
					t.Fatal("stale pending survived")
				}
				if count() != 0 {
					t.Fatal("stale pending spawned")
				}
				return
			}
			controlTLSSend(t, data.peer, wsOpcodeText, `{"type":"start","cols":80,"rows":24}`)
			if string(controlTLSRead(t, data.peer).data) != `{"type":"ready"}` {
				t.Fatal("missing ready")
			}
			if mode == "two_sessions_bounds" {
				mu.Lock()
				slow := processes[0]
				mu.Unlock()
				generated := make(chan struct{})
				go func() {
					defer close(generated)
					_, _ = slow.output.Write([]byte(strings.Repeat("x", 3*terminalCreditBytes)))
				}()
				defer func() {
					cancel()
					<-done
					select {
					case <-generated:
					case <-time.After(time.Second):
						t.Error("producer fixture leaked")
					}
				}()
				sessionEventually(t, func() bool { return slow.reads.Load() == 262144 })
				controlTLSSend(t, control.peer, wsOpcodeText, controlOpen("S2"))
				fastData := f.next(t)
				defer fastData.peer.Close()
				controlTLSSend(t, fastData.peer, wsOpcodeText, `{"type":"start","cols":80,"rows":24}`)
				if string(controlTLSRead(t, fastData.peer).data) != `{"type":"ready"}` {
					t.Fatal("S1 credit blocked S2 start")
				}
				mu.Lock()
				fast := processes[1]
				mu.Unlock()
				start := time.Now()
				controlTLSSend(t, fastData.peer, wsOpcodeBinary, "key")
				sessionEventually(t, func() bool { return fast.text() == "key" })
				go func() { _, _ = fast.output.Write([]byte("echo")) }()
				for {
					frame := controlTLSRead(t, fastData.peer)
					if frame.op == wsOpcodeBinary {
						if string(frame.data) != "echo" {
							t.Fatal("TLS echo changed")
						}
						break
					}
				}
				elapsed := time.Since(start)
				if elapsed > 100*time.Millisecond {
					t.Fatalf("TLS S2 interaction blocked: %s", elapsed)
				}
				for i := 0; i < 100; i++ {
					controlTLSSend(t, fastData.peer, wsOpcodeBinary, "x")
				}
				var ack int64
				events := 0
				for ack < 103 {
					frame := controlTLSRead(t, fastData.peer)
					c, err := parseTerminalControl(frame.data, "agent")
					if err != nil || c.Type != "ack" {
						t.Fatal("invalid consumed-input ACK")
					}
					ack = c.Bytes
					events++
				}
				if events >= 20 || slow.reads.Load() != 262144 {
					t.Fatalf("unbounded producer/unbatched ACK: slow=%d ACK events=%d", slow.reads.Load(), events)
				}
				t.Logf("real TLS: stalled S1 outstanding=262144; S2 keyboard+echo=%s; 100 one-byte inputs => %d ACK events", elapsed, events)
				return
			}
			controlTLSSend(t, data.peer, wsOpcodeBinary, "keyboard")
			mu.Lock()
			p := processes[0]
			mu.Unlock()
			sessionEventually(t, func() bool { return p.text() == "keyboard" })
			if mode == "data_disconnect" {
				_ = data.peer.Close()
				sessionEventually(t, func() bool {
					select {
					case <-p.closed:
						return true
					default:
						return false
					}
				})
			}
			if a.reportPauseRemaining(time.Now()) <= 0 {
				t.Fatal("terminal changed reporting pause")
			}
		})
		// Discard cancelled retry handshakes before the next independent scenario.
		for {
			select {
			case a := <-f.attached:
				_ = a.peer.Close()
			default:
				goto drained
			}
		}
	drained:
	}
}

func TestTerminalControlNonStartDataCannotSpawn(t *testing.T) {
	for _, invalid := range []sessionTestFrame{
		{op: wsOpcodeText, data: []byte(`{"type":"resize","cols":80,"rows":24}`)},
		{op: wsOpcodeText, data: []byte(`{"type":"start","cols":0,"rows":24}`)},
		{op: wsOpcodeBinary, data: []byte("input before ready")},
		{op: wsOpcodeText, data: []byte(strings.Repeat("x", 4097))},
	} {
		control, data := newSessionTestPeer(), newSessionTestPeer()
		var factories atomic.Int32
		opts := defaultTerminalControlOptions()
		opts.preflight = func(context.Context) error { return nil }
		opts.heartbeat = time.Hour
		opts.factory = func(uint16, uint16) (terminalProcess, error) { factories.Add(1); return newSessionTestProcess(), nil }
		opts.dial = func(_ context.Context, _ Config, id, _ string, _ bool) (terminalPeer, error) {
			if id == "" {
				return control, nil
			}
			return data, nil
		}
		a := &Agent{cfg: Config{TerminalEnabled: true, TerminalToken: strings.Repeat("a", 64), ServerID: "node", WorkerURL: "https://example.invalid"}, log: newLogger(false)}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { defer close(done); a.runTerminalWorker(ctx, opts) }()
		_ = sessionFrame(t, control)
		control.send(wsOpcodeText, []byte(controlOpen("S1")))
		data.send(invalid.op, invalid.data)
		sessionEventually(t, func() bool {
			select {
			case <-data.closed:
				return true
			default:
				return false
			}
		})
		cancel()
		<-done
		if factories.Load() != 0 {
			t.Fatal("non-start/premature input created PTY")
		}
	}
}

func TestTerminalControlCoalescedIdentityChangesReplaceGeneration(t *testing.T) {
	attached := make(chan *sessionTestPeer, 4)
	opts := defaultTerminalControlOptions()
	opts.preflight = func(context.Context) error { return nil }
	opts.heartbeat = time.Hour
	opts.configInterval = time.Hour
	opts.retryMin = time.Millisecond
	opts.retryMax = time.Millisecond
	opts.dial = func(context.Context, Config, string, string, bool) (terminalPeer, error) {
		p := newSessionTestPeer()
		attached <- p
		return p, nil
	}
	a := &Agent{cfg: Config{TerminalEnabled: true, TerminalToken: strings.Repeat("a", 64), ServerID: "node", WorkerURL: "https://example.invalid"}, log: newLogger(false)}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); a.runTerminalWorker(ctx, opts) }()
	defer func() { cancel(); <-done }()
	first := <-attached
	_ = sessionFrame(t, first)
	original := a.configSnapshot()
	changed := original
	changed.TerminalToken = strings.Repeat("c", 64)
	a.setConfig(changed)
	a.setConfig(original)
	select {
	case next := <-attached:
		_ = sessionFrame(t, next)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("coalesced A-B-A identity change retained old control generation")
	}
	select {
	case <-first.closed:
	default:
		t.Fatal("old generation peer remained active")
	}
}

func TestTerminalControlEligibilityAndUnavailable(t *testing.T) {
	base := Config{TerminalEnabled: true, TerminalToken: strings.Repeat("a", 64), ServerID: "node", WorkerURL: "https://example.invalid/update"}
	for _, kind := range []string{"disabled", "token", "unbound", "http", "unavailable"} {
		t.Run(kind, func(t *testing.T) {
			cfg := base
			switch kind {
			case "disabled":
				cfg.TerminalEnabled = false
			case "token":
				cfg.TerminalToken = ""
			case "unbound":
				cfg.ServerID = ""
			case "http":
				cfg.WorkerURL = "http://example.invalid/update"
			}
			var calls atomic.Int32
			a := &Agent{cfg: cfg, log: newLogger(false)}
			opts := defaultTerminalControlOptions()
			opts.preflight = func(context.Context) error { return errors.New("unavailable") }
			opts.dial = func(context.Context, Config, string, string, bool) (terminalPeer, error) {
				calls.Add(1)
				return nil, errors.New("unexpected dial")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
			defer cancel()
			a.runTerminalWorker(ctx, opts)
			if calls.Load() != 0 {
				t.Fatal("ineligible terminal connected")
			}
			if a.reportPauseRemaining(time.Now()) > 0 {
				t.Fatal("terminal failure paused reports")
			}
		})
	}
}

func TestTerminalControlStartAdmissionAndCancellation(t *testing.T) {
	control, data := newSessionTestPeer(), newSessionTestPeer()
	var factories, dials atomic.Int32
	opts := defaultTerminalControlOptions()
	opts.preflight = func(context.Context) error { return nil }
	opts.factory = func(uint16, uint16) (terminalProcess, error) { factories.Add(1); return newSessionTestProcess(), nil }
	opts.dial = func(ctx context.Context, cfg Config, id, ticket string, dns bool) (terminalPeer, error) {
		if id == "" {
			return control, nil
		}
		dials.Add(1)
		if id != "S1" || ticket != strings.Repeat("b", 64) {
			return nil, errors.New("binding")
		}
		return data, nil
	}
	a := &Agent{cfg: Config{TerminalEnabled: true, TerminalToken: strings.Repeat("a", 64), ServerID: "node", WorkerURL: "https://example.invalid/update", ConnectionMode: connectionModeHTTP}, log: newLogger(false)}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); a.runTerminalWorker(ctx, opts) }()
	defer func() { cancel(); <-done }()
	f := sessionFrame(t, control)
	if string(f.data) != `{"type":"hello","protocol":1,"platform":"linux","capabilities":["terminal.pty.v1"]}` {
		t.Fatalf("hello=%s", f.data)
	}
	open := []byte(`{"type":"open","protocol":1,"sessionId":"S1","ticket":"` + strings.Repeat("b", 64) + `","cols":80,"rows":24}`)
	control.send(wsOpcodeText, open)
	sessionEventually(t, func() bool { return dials.Load() == 1 })
	if factories.Load() != 0 {
		t.Fatal("PTY before broker start")
	}
	data.send(wsOpcodeText, []byte(`{"type":"start","cols":80,"rows":24}`))
	sessionReady(t, data)
	if factories.Load() != 1 {
		t.Fatal("missing single PTY")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker failed to join")
	}
	select {
	case <-data.closed:
	default:
		t.Fatal("data peer not closed")
	}
}

func TestTerminalControlSlowDialAndWriterDoNotBlockOtherSession(t *testing.T) {
	for _, slowWriter := range []bool{false, true} {
		t.Run(fmt.Sprint(slowWriter), func(t *testing.T) {
			control, s1, s2 := newSessionTestPeer(), newSessionTestPeer(), newSessionTestPeer()
			if slowWriter {
				s1.block = make(chan struct{})
			}
			entered := make(chan struct{})
			var once sync.Once
			var mu sync.Mutex
			var procs []*sessionTestProcess
			opts := defaultTerminalControlOptions()
			opts.preflight = func(context.Context) error { return nil }
			opts.heartbeat = time.Hour
			opts.factory = func(uint16, uint16) (terminalProcess, error) {
				p := newSessionTestProcess()
				mu.Lock()
				procs = append(procs, p)
				mu.Unlock()
				return p, nil
			}
			opts.dial = func(ctx context.Context, _ Config, id, _ string, _ bool) (terminalPeer, error) {
				switch id {
				case "":
					return control, nil
				case "S1":
					once.Do(func() { close(entered) })
					if !slowWriter {
						<-ctx.Done()
						return nil, ctx.Err()
					}
					return s1, nil
				case "S2":
					return s2, nil
				}
				return nil, errors.New("unexpected")
			}
			a := &Agent{cfg: Config{TerminalEnabled: true, TerminalToken: strings.Repeat("a", 64), ServerID: "node", WorkerURL: "https://example.invalid"}, log: newLogger(false)}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() { defer close(done); a.runTerminalWorker(ctx, opts) }()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("slow admission not joined")
				}
			}()
			_ = sessionFrame(t, control)
			control.send(wsOpcodeText, []byte(controlOpen("S1")))
			<-entered
			if slowWriter {
				s1.send(wsOpcodeText, []byte(`{"type":"start","cols":80,"rows":24}`))
				sessionEventually(t, func() bool { return s1.writes.Load() > 0 })
			}
			start := time.Now()
			control.send(wsOpcodeText, []byte(controlOpen("S2")))
			s2.send(wsOpcodeText, []byte(`{"type":"start","cols":80,"rows":24}`))
			sessionReady(t, s2)
			s2.send(wsOpcodeBinary, []byte("key"))
			var p *sessionTestProcess
			sessionEventually(t, func() bool {
				mu.Lock()
				defer mu.Unlock()
				for _, q := range procs {
					if q.text() == "key" {
						p = q
						return true
					}
				}
				return false
			})
			if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
				t.Fatalf("S2 blocked by S1: %s", elapsed)
			} else {
				t.Logf("slow S1 writer=%v; S2 ready+input=%s", slowWriter, elapsed)
			}
			go func() { _, _ = p.output.Write([]byte("echo")) }()
			for {
				f := sessionFrame(t, s2)
				if f.op == wsOpcodeBinary {
					if string(f.data) != "echo" {
						t.Fatal("output mismatch")
					}
					break
				}
			}
			_ = control.Close()
			sessionEventually(t, func() bool {
				select {
				case <-p.closed:
					return true
				default:
					return false
				}
			})
		})
	}
}

type controlDeadlinePeer struct {
	*sessionTestPeer
	mu        sync.Mutex
	deadlines []time.Time
}

func (p *controlDeadlinePeer) SetReadDeadline(d time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deadlines = append(p.deadlines, d)
	return nil
}

func TestTerminalControlExactHeartbeatAndReadDeadline(t *testing.T) {
	peer := &controlDeadlinePeer{sessionTestPeer: newSessionTestPeer()}
	opts := defaultTerminalControlOptions()
	opts.preflight = func(context.Context) error { return nil }
	opts.heartbeat = 20 * time.Millisecond
	opts.dial = func(context.Context, Config, string, string, bool) (terminalPeer, error) { return peer, nil }
	a := &Agent{cfg: Config{TerminalEnabled: true, TerminalToken: strings.Repeat("a", 64), ServerID: "node", WorkerURL: "https://example.invalid"}, log: newLogger(false)}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); a.runTerminalWorker(ctx, opts) }()
	defer func() { cancel(); <-done }()
	_ = sessionFrame(t, peer.sessionTestPeer)
	peer.send(wsOpcodeText, []byte(`{"type":"ping"}`))
	if f := sessionFrame(t, peer.sessionTestPeer); string(f.data) != `{"type":"pong"}` {
		t.Fatalf("pong has extra/missing fields: %s", f.data)
	}
	if f := sessionFrame(t, peer.sessionTestPeer); string(f.data) != `{"type":"ping"}` {
		t.Fatalf("ping has extra/missing fields: %s", f.data)
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if len(peer.deadlines) < 2 {
		t.Fatal("missing refreshed read deadline")
	}
	for _, d := range peer.deadlines {
		if remaining := time.Until(d); remaining < 74*time.Second || remaining > 75*time.Second {
			t.Fatalf("wrong read deadline %s", remaining)
		}
	}
}

func TestTerminalControlCancelledAdmissionRejectsLateStart(t *testing.T) {
	control, data := newSessionTestPeer(), newSessionTestPeer()
	var calls atomic.Int32
	arrived := make(chan struct{})
	opts := defaultTerminalControlOptions()
	opts.preflight = func(context.Context) error { return nil }
	opts.heartbeat = time.Hour
	opts.factory = func(uint16, uint16) (terminalProcess, error) { calls.Add(1); return newSessionTestProcess(), nil }
	opts.dial = func(_ context.Context, _ Config, id, _ string, _ bool) (terminalPeer, error) {
		if id == "" {
			return control, nil
		}
		close(arrived)
		return data, nil
	}
	a := &Agent{cfg: Config{TerminalEnabled: true, TerminalToken: strings.Repeat("a", 64), ServerID: "node", WorkerURL: "https://example.invalid"}, log: newLogger(false)}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); a.runTerminalWorker(ctx, opts) }()
	defer func() { cancel(); <-done }()
	_ = sessionFrame(t, control)
	control.send(wsOpcodeText, []byte(controlOpen("S1")))
	<-arrived
	control.send(wsOpcodeText, []byte(`{"type":"close","sessionId":"S1","reason":"closed"}`))
	sessionEventually(t, func() bool {
		select {
		case <-data.closed:
			return true
		default:
			return false
		}
	})
	data.send(wsOpcodeText, []byte(`{"type":"start","cols":80,"rows":24}`))
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("late start spawned PTY")
	}
}
