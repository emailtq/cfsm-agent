package cfprobe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type terminalDeadlineConn struct {
	net.Conn
	failure   error
	deadlines []time.Time
}

func (c *terminalDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	if c.failure != nil {
		return c.failure
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func TestTerminalWriteDeadlineFailureAndDefault(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	failure := errors.New("cannot set deadline")
	tracked := &terminalDeadlineConn{Conn: left, failure: failure}
	ws := &webSocketConn{conn: tracked}
	// If the setter error is ignored, this test still terminates via the pipe's deadline.
	_ = left.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	if err := ws.WriteBinary([]byte("x"), time.Second); !errors.Is(err, failure) {
		t.Fatalf("deadline failure not propagated: %v", err)
	}
	tracked.failure = nil
	tracked.deadlines = nil
	read := make(chan error, 1)
	go func() { _, err := io.CopyN(io.Discard, right, 7); read <- err }()
	start := time.Now()
	if err := ws.WriteBinary([]byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	if len(tracked.deadlines) != 2 || tracked.deadlines[0].Sub(start) < 7900*time.Millisecond || tracked.deadlines[0].Sub(start) > 8100*time.Millisecond || !tracked.deadlines[1].IsZero() {
		t.Fatal("default eight-second deadline not set/reset")
	}
}

func TestTerminalHandshakeCancellationAfterUpgradeRequest(t *testing.T) {
	arrived := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { arrived <- struct{}{}; <-release }))
	defer server.Close()
	defer close(release)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		ws, _, _, _, err := dialReportWebSocket(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), http.Header{}, false, 2*time.Second)
		if ws != nil {
			ws.Close()
		}
		done <- err
	}()
	select {
	case <-arrived:
	case <-time.After(time.Second):
		t.Fatal("upgrade not received")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled handshake succeeded")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("handshake ignored context cancellation")
	}
}

// Fallback roots are confined to a child test process, not the host trust store.
func TestTerminalTLSHelper(t *testing.T) {
	certFile := os.Getenv("CFSM_TERMINAL_TEST_ROOT")
	if certFile == "" {
		return
	}
	data, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		t.Fatal("bad fixture certificate")
	}
	x509.SetFallbackRoots(roots)
	cfg := Config{WorkerURL: os.Getenv("CFSM_TERMINAL_TEST_URL") + "/update?reporting_secret=discarded", ServerID: "node1", TerminalToken: strings.Repeat("a", 64)}
	mode := os.Getenv("CFSM_TERMINAL_TEST_MODE")
	ws, err := dialTerminalWebSocket(t.Context(), cfg, "S_1", strings.Repeat("b", 64), false)
	if mode == "redirect" {
		if ws != nil {
			ws.Close()
		}
		if err == nil || strings.Contains(err.Error(), cfg.TerminalToken) || strings.Contains(err.Error(), strings.Repeat("b", 64)) {
			t.Fatal("redirect accepted or echoed credential")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	data, opcode, err := ws.ReadDataMessageLimit(4096)
	if err != nil || opcode != wsOpcodeText {
		t.Fatal("TLS control read failed")
	}
	if _, err := parseTerminalControl(data, "broker"); err != nil {
		t.Fatal(err)
	}
	if err := ws.WriteBinary([]byte(`{"type":"exit"}`), time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestTerminalAuthenticatedTLSAndCrossOriginRedirect(t *testing.T) {
	for _, mode := range []string{"session", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			targetHits := make(chan struct{}, 1)
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetHits <- struct{}{}; w.WriteHeader(500) }))
			defer target.Close()
			verified := make(chan error, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/agent/terminal/session/S_1" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) || r.Header.Get("X-CFSM-Server-Id") != "node1" || r.Header.Get("X-CFSM-Terminal-Ticket") != strings.Repeat("b", 64) {
					verified <- errors.New("endpoint/header binding wrong")
					w.WriteHeader(400)
					return
				}
				if mode == "redirect" {
					w.Header().Set("Location", target.URL+"/stolen")
					w.WriteHeader(http.StatusFound)
					_, _ = w.Write([]byte(strings.Repeat("a", 64)))
					verified <- nil
					return
				}
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					verified <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, err = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", expectedWebSocketAccept(r.Header.Get("Sec-WebSocket-Key")))
				if err == nil {
					err = rw.Flush()
				}
				if err == nil {
					err = writeAll(conn, terminalTestFrame(wsOpcodeText, true, []byte(`{"type":"ready"}`)))
				}
				if err == nil {
					peer := &webSocketConn{conn: conn, reader: rw.Reader}
					frame, e := peer.readFrame()
					err = e
					if err == nil && (frame.opcode != wsOpcodeBinary || string(frame.payload) != `{"type":"exit"}`) {
						err = errors.New("typed input became control")
					}
				}
				verified <- err
			}))
			defer server.Close()
			root := filepath.Join(t.TempDir(), "root.pem")
			if err := os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestTerminalTLSHelper$", "-test.count=1")
			cmd.Env = append(os.Environ(), "GODEBUG=x509usefallbackroots=1", "CFSM_TERMINAL_TEST_ROOT="+root, "CFSM_TERMINAL_TEST_URL="+server.URL, "CFSM_TERMINAL_TEST_MODE="+mode)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("TLS child failed: %v\n%s", err, output)
			}
			select {
			case err := <-verified:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("TLS endpoint not exercised")
			}
			select {
			case <-targetHits:
				t.Fatal("node credentials followed cross-origin redirect")
			default:
			}
		})
	}
}

func terminalTestFrame(opcode byte, fin bool, payload []byte) []byte {
	first := opcode
	if fin {
		first |= 0x80
	}
	frame := []byte{first}
	switch {
	case len(payload) < 126:
		frame = append(frame, byte(len(payload)))
	case len(payload) <= 65535:
		frame = append(frame, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		frame = append(frame, 127)
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(payload)))
		frame = append(frame, size[:]...)
	}
	return append(frame, payload...)
}

func TestTerminalBoundedReadBinaryAndFragments(t *testing.T) {
	typed := []byte(`{"type":"exit","code":0}`)
	for _, tt := range []struct {
		wire, want []byte
		opcode     byte
		limit      int
	}{
		{terminalTestFrame(wsOpcodeBinary, true, typed), typed, wsOpcodeBinary, 16384},
		{terminalTestFrame(wsOpcodeBinary, true, bytes.Repeat([]byte("x"), 16384)), bytes.Repeat([]byte("x"), 16384), wsOpcodeBinary, 16384},
		{append(terminalTestFrame(wsOpcodeText, false, []byte(`{"type":`)), terminalTestFrame(wsOpcodeContinuation, true, []byte(`"ready"}`))...), []byte(`{"type":"ready"}`), wsOpcodeText, 4096},
		{append(terminalTestFrame(wsOpcodeBinary, false, bytes.Repeat([]byte("a"), 8192)), terminalTestFrame(wsOpcodeContinuation, true, bytes.Repeat([]byte("b"), 8192))...), append(bytes.Repeat([]byte("a"), 8192), bytes.Repeat([]byte("b"), 8192)...), wsOpcodeBinary, 16384},
	} {
		ws := &webSocketConn{reader: bufio.NewReader(bytes.NewReader(tt.wire))}
		got, opcode, err := ws.ReadDataMessageLimit(tt.limit)
		if err != nil || opcode != tt.opcode || !bytes.Equal(got, tt.want) {
			t.Fatalf("bounded message mismatch opcode=%d err=%v", opcode, err)
		}
	}
}

func TestTerminalRejectsOversizeBeforeReadingPayload(t *testing.T) {
	for _, wire := range [][]byte{
		{0x82, 126, 0x40, 0x01},
		{0x81, 126, 0x10, 0x01},
		append(terminalTestFrame(wsOpcodeBinary, false, bytes.Repeat([]byte("x"), 16384)), 0x80, 1),
		append(terminalTestFrame(wsOpcodeText, false, bytes.Repeat([]byte(" "), 4096)), 0x80, 1),
	} {
		ws := &webSocketConn{reader: bufio.NewReader(bytes.NewReader(wire))}
		if _, _, err := ws.ReadDataMessageLimit(16384); err == nil || !strings.Contains(err.Error(), "large") {
			t.Fatalf("oversize must fail at header, not truncated body: %v", err)
		}
	}
}

func TestTerminalRejectsMalformedAndTruncatedFrames(t *testing.T) {
	for _, wire := range [][]byte{
		{}, {0x82}, {0x82, 126, 0}, {0x82, 127, 0}, {0x82, 2, 'x'},
		{0xc2, 0}, {0x82, 0x80, 0, 0, 0, 0}, {0x80, 0}, {0x83, 0},
		{0x09, 0}, {0x89, 126, 0, 126}, {0x88, 1, 0},
		{0x82, 126, 0, 1, 'x'}, {0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0},
		append(terminalTestFrame(wsOpcodeBinary, false, []byte("x")), terminalTestFrame(wsOpcodeText, true, []byte("x"))...),
	} {
		ws := &webSocketConn{reader: bufio.NewReader(bytes.NewReader(wire))}
		if _, _, err := ws.ReadDataMessageLimit(16384); err == nil {
			t.Fatalf("malformed frame accepted: %x", wire)
		}
	}
	ws := &webSocketConn{reader: bufio.NewReader(bytes.NewReader(nil))}
	if _, _, err := ws.ReadDataMessageLimit(0); err == nil {
		t.Fatal("zero limit accepted")
	}
}

func TestTerminalFragmentedPingAndClose(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	ws := &webSocketConn{conn: left, reader: bufio.NewReader(left)}
	server := &webSocketConn{conn: right, reader: bufio.NewReader(right)}
	_ = left.SetDeadline(time.Now().Add(2 * time.Second))
	_ = right.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() {
		if err := writeAll(right, append(terminalTestFrame(wsOpcodeBinary, false, []byte("a")), terminalTestFrame(wsOpcodePing, true, []byte("pulse"))...)); err != nil {
			done <- err
			return
		}
		pong, err := server.readFrame()
		if err != nil || pong.opcode != wsOpcodePong || string(pong.payload) != "pulse" {
			done <- errors.New("ping echo lost")
			return
		}
		if err := writeAll(right, terminalTestFrame(wsOpcodeContinuation, true, []byte("b"))); err != nil {
			done <- err
			return
		}
		if err := writeAll(right, terminalTestFrame(wsOpcodeClose, true, []byte{3, 232})); err != nil {
			done <- err
			return
		}
		closeFrame, err := server.readFrame()
		if err == nil && closeFrame.opcode != wsOpcodeClose {
			err = errors.New("close not echoed")
		}
		done <- err
	}()
	got, opcode, err := ws.ReadDataMessageLimit(2)
	if err != nil || opcode != wsOpcodeBinary || string(got) != "ab" {
		t.Fatal("control interrupted fragment accounting")
	}
	_, _, err = ws.ReadDataMessageLimit(2)
	var closed *wsCloseError
	if !errors.As(err, &closed) || closed.Code != 1000 {
		t.Fatalf("close mismatch: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTerminalCloseErrorDoesNotEchoPeerCredential(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(time.Second))
	_ = right.SetDeadline(time.Now().Add(time.Second))
	ws := &webSocketConn{conn: left, reader: bufio.NewReader(left)}
	peer := &webSocketConn{conn: right, reader: bufio.NewReader(right)}
	done := make(chan error, 1)
	go func() {
		if err := writeAll(right, terminalTestFrame(wsOpcodeClose, true, append([]byte{3, 232}, []byte(strings.Repeat("a", 64))...))); err != nil {
			done <- err
			return
		}
		_, err := peer.readFrame()
		done <- err
	}()
	_, _, err := ws.ReadDataMessageLimit(16384)
	if err == nil || strings.Contains(err.Error(), strings.Repeat("a", 64)) {
		t.Fatal("terminal close surfaced credential-bearing peer reason")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTerminalWriteBinaryMaskAndPerConnectionSerialization(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	ws := &webSocketConn{conn: left, reader: bufio.NewReader(left)}
	_ = right.SetReadDeadline(time.Now().Add(2 * time.Second))
	const count = 12
	done := make(chan error, 1)
	go func() {
		for i := 0; i < count; i++ {
			var head [6]byte
			if _, err := io.ReadFull(right, head[:]); err != nil {
				done <- err
				return
			}
			if head[0] != 0x82 || head[1] != 0x83 {
				done <- errors.New("unmasked/interleaved binary header")
				return
			}
			var payload [3]byte
			if _, err := io.ReadFull(right, payload[:]); err != nil {
				done <- err
				return
			}
			for j := range payload {
				payload[j] ^= head[2+j%4]
			}
			if !bytes.Equal(payload[:], []byte("key")) {
				done <- errors.New("interleaved payload")
				return
			}
		}
		done <- nil
	}()
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- ws.WriteBinary([]byte("key"), time.Second) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := ws.WriteBinary(make([]byte, 16385), time.Second); err == nil {
		t.Fatal("unbounded binary write accepted")
	}
}

func TestTerminalSocketDeadlinesCancellationAndIndependentWriters(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	ws := &webSocketConn{conn: left, reader: bufio.NewReader(left)}
	blocked := make(chan error, 1)
	go func() { blocked <- ws.WriteBinary([]byte("blocked"), 80*time.Millisecond) }()
	otherLeft, otherRight := net.Pipe()
	defer otherLeft.Close()
	defer otherRight.Close()
	other := &webSocketConn{conn: otherLeft, reader: bufio.NewReader(otherLeft)}
	read := make(chan error, 1)
	go func() { _, err := io.CopyN(io.Discard, otherRight, 9); read <- err }()
	if err := other.WriteBinary([]byte("key"), time.Second); err != nil {
		t.Fatal("slow peer blocked another connection")
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	var timeout net.Error
	if err := <-blocked; !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("write not deadline bounded: %v", err)
	}
	_ = ws.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := ws.ReadDataMessageLimit(16384); !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("read deadline ignored: %v", err)
	}
	_ = ws.SetReadDeadline(time.Time{})
	ctx, cancel := context.WithCancel(t.Context())
	stop := context.AfterFunc(ctx, func() { _ = ws.Close() })
	defer stop()
	reading := make(chan error, 1)
	go func() { _, _, err := ws.ReadDataMessageLimit(16384); reading <- err }()
	cancel()
	select {
	case err := <-reading:
		if err == nil {
			t.Fatal("cancellation accepted read")
		}
	case <-time.After(time.Second):
		t.Fatal("read not cancelled by close")
	}
}

func TestTerminalDialRejectsUntrustedTLSAndCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS reached HTTP handler") }))
	defer server.Close()
	cfg := Config{WorkerURL: server.URL + "/update", ServerID: "node1", TerminalToken: strings.Repeat("a", 64)}
	if ws, err := dialTerminalWebSocket(t.Context(), cfg, "", "", false); err == nil {
		ws.Close()
		t.Fatal("TLS verification disabled")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := dialTerminalWebSocket(ctx, cfg, "", "", false); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
