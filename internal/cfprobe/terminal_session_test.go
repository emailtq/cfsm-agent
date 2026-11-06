package cfprobe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type sessionTestFrame struct {
	data []byte
	op   byte
}

type sessionTestPeer struct {
	in     chan sessionTestFrame
	out    chan sessionTestFrame
	closed chan struct{}
	once   sync.Once
	block  chan struct{}
	writes atomic.Int32
}

func newSessionTestPeer() *sessionTestPeer {
	return &sessionTestPeer{in: make(chan sessionTestFrame, 64), out: make(chan sessionTestFrame, 128), closed: make(chan struct{})}
}
func (p *sessionTestPeer) ReadDataMessageLimit(limit int) ([]byte, byte, error) {
	select {
	case f := <-p.in:
		if len(f.data) > limit {
			return nil, 0, errors.New("frame limit")
		}
		return f.data, f.op, nil
	case <-p.closed:
		return nil, 0, io.EOF
	}
}
func (p *sessionTestPeer) write(b []byte, op byte, d time.Duration) error {
	if d <= 0 || d > 8*time.Second {
		return errors.New("missing write deadline")
	}
	p.writes.Add(1)
	if p.block != nil {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-p.block:
		case <-p.closed:
			return io.EOF
		case <-timer.C:
			return errors.New("write deadline")
		}
	}
	select {
	case p.out <- sessionTestFrame{append([]byte(nil), b...), op}:
		return nil
	case <-p.closed:
		return io.EOF
	}
}
func (p *sessionTestPeer) WriteText(b []byte, d time.Duration) error {
	return p.write(b, wsOpcodeText, d)
}
func (p *sessionTestPeer) WriteBinary(b []byte, d time.Duration) error {
	return p.write(b, wsOpcodeBinary, d)
}
func (p *sessionTestPeer) SetReadDeadline(time.Time) error { return nil }
func (p *sessionTestPeer) Close() error                    { p.once.Do(func() { close(p.closed) }); return nil }
func (p *sessionTestPeer) send(op byte, b []byte) {
	p.in <- sessionTestFrame{append([]byte(nil), b...), op}
}

type sessionTestProcess struct {
	reader    *io.PipeReader
	output    *io.PipeWriter
	closed    chan struct{}
	once      sync.Once
	mu        sync.Mutex
	input     bytes.Buffer
	partial   int
	inputGate chan struct{}
	reads     atomic.Int64
	waits     atomic.Int32
	sizes     [][2]uint16
}

func newSessionTestProcess() *sessionTestProcess {
	r, w := io.Pipe()
	return &sessionTestProcess{reader: r, output: w, closed: make(chan struct{})}
}

type sessionCleanupGateProcess struct {
	*sessionTestProcess
	closing, release chan struct{}
	gateOnce         sync.Once
}

func (p *sessionCleanupGateProcess) Close() error {
	p.gateOnce.Do(func() { close(p.closing) })
	<-p.release
	return p.sessionTestProcess.Close()
}

func TestTerminalSessionCloseAllJoinsRemovedCleanup(t *testing.T) {
	p := &sessionCleanupGateProcess{sessionTestProcess: newSessionTestProcess(), closing: make(chan struct{}), release: make(chan struct{})}
	m := newTerminalManager(4, func(uint16, uint16) (terminalProcess, error) { return p, nil })
	peer := newSessionTestPeer()
	sessionOpen(t, m, "owned", peer)
	m.mu.Lock()
	owned := m.sessions["owned"]
	m.mu.Unlock()
	defer func() { close(p.release); <-owned.done }()
	_ = peer.Close()
	select {
	case <-p.closing:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not start")
	}
	if m.Count() != 0 {
		t.Fatal("fixture did not remove live session")
	}
	done := make(chan struct{})
	go func() { m.CloseAll("shutdown"); close(done) }()
	select {
	case <-done:
		t.Fatal("CloseAll returned before owned cleanup completed")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestTerminalSessionCancelledFactoryOwnershipBounded(t *testing.T) {
	gate := make(chan struct{})
	var entered atomic.Int32
	m := newTerminalManager(1, func(uint16, uint16) (terminalProcess, error) {
		entered.Add(1)
		<-gate
		return newSessionTestProcess(), nil
	})
	defer func() {
		close(gate)
		sessionEventually(t, func() bool { m.mu.Lock(); defer m.mu.Unlock(); return len(m.owned) == 0 })
	}()
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- m.Open(ctx, "same", newSessionTestPeer(), 80, 24) }()
		sessionEventually(t, func() bool { return entered.Load() == int32(i+1) })
		cancel()
		if err := <-result; err == nil {
			t.Fatal("cancelled factory accepted")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err := m.Open(ctx, "third", newSessionTestPeer(), 80, 24); err == nil {
		t.Fatal("unbounded late factories admitted")
	}
	if entered.Load() != 2 {
		t.Fatal("ownership bound applied after spawn")
	}
	m.CloseAll("shutdown")
}
func (p *sessionTestProcess) Read(b []byte) (int, error) {
	n, err := p.reader.Read(b)
	p.reads.Add(int64(n))
	return n, err
}
func (p *sessionTestProcess) Write(b []byte) (int, error) {
	if p.inputGate != nil {
		select {
		case <-p.inputGate:
		case <-p.closed:
			return 0, io.EOF
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.partial > 0 && len(b) > p.partial {
		b = b[:p.partial]
	}
	return p.input.Write(b)
}
func (p *sessionTestProcess) Close() error {
	p.once.Do(func() { close(p.closed); _ = p.reader.Close(); _ = p.output.Close() })
	return nil
}
func (p *sessionTestProcess) Resize(c, r uint16) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sizes = append(p.sizes, [2]uint16{c, r})
	return nil
}
func (p *sessionTestProcess) Wait() error  { p.waits.Add(1); <-p.closed; return nil }
func (p *sessionTestProcess) text() string { p.mu.Lock(); defer p.mu.Unlock(); return p.input.String() }

func sessionEventually(t *testing.T, fn func() bool) {
	t.Helper()
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		if fn() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("session condition did not become true")
}
func sessionFrame(t *testing.T, p *sessionTestPeer) sessionTestFrame {
	t.Helper()
	select {
	case f := <-p.out:
		return f
	case <-time.After(2 * time.Second):
		t.Fatal("missing session frame")
	}
	return sessionTestFrame{}
}
func sessionReady(t *testing.T, p *sessionTestPeer) {
	t.Helper()
	f := sessionFrame(t, p)
	if string(f.data) != `{"type":"ready"}` || f.op != wsOpcodeText {
		t.Fatalf("first frame = %s", f.data)
	}
}
func sessionOpen(t *testing.T, m *terminalManager, id string, p *sessionTestPeer) {
	t.Helper()
	if err := m.Open(context.Background(), id, p, 80, 24); err != nil {
		t.Fatal(err)
	}
	sessionReady(t, p)
}

// These tests catch shared process/writer ownership, late-start slot leaks and double Wait.
func TestTerminalSessionIndependentReservationsAndClose(t *testing.T) {
	var mu sync.Mutex
	var processes []*sessionTestProcess
	m := newTerminalManager(4, func(c, r uint16) (terminalProcess, error) {
		p := newSessionTestProcess()
		mu.Lock()
		processes = append(processes, p)
		mu.Unlock()
		return p, nil
	})
	t.Cleanup(func() { m.CloseAll("test_end") })
	a, b := newSessionTestPeer(), newSessionTestPeer()
	sessionOpen(t, m, "a", a)
	sessionOpen(t, m, "b", b)
	if err := m.Open(context.Background(), "a", newSessionTestPeer(), 80, 24); err == nil {
		t.Fatal("duplicate accepted")
	}
	if len(processes) != 2 {
		t.Fatal("duplicate spawned an orphan")
	}
	a.send(wsOpcodeBinary, []byte("one"))
	b.send(wsOpcodeBinary, []byte("two"))
	sessionEventually(t, func() bool { return processes[0].text() == "one" && processes[1].text() == "two" })
	if err := m.Close("a"); err != nil {
		t.Fatal(err)
	}
	_ = m.Close("a")
	b.send(wsOpcodeBinary, []byte("still"))
	sessionEventually(t, func() bool { return processes[1].text() == "twostill" })
	sessionEventually(t, func() bool { return m.Count() == 1 && processes[0].waits.Load() == 1 })
	select {
	case <-b.closed:
		t.Fatal("other peer closed")
	default:
	}
	for _, id := range []string{"c", "d", "e"} {
		sessionOpen(t, m, id, newSessionTestPeer())
	}
	if err := m.Open(context.Background(), "f", newSessionTestPeer(), 80, 24); err == nil || len(processes) != 5 {
		t.Fatal("fifth open spawned")
	}
	m.CloseAll("control_loss")
	sessionEventually(t, func() bool { return m.Count() == 0 })
	for _, p := range processes {
		sessionEventually(t, func() bool { return p.waits.Load() == 1 })
	}
}

func TestTerminalSessionCancelledStartupCannotCloseReplacement(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{})
	var calls atomic.Int32
	old := newSessionTestProcess()
	replacement := newSessionTestProcess()
	m := newTerminalManager(4, func(c, r uint16) (terminalProcess, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-gate
			return old, nil
		}
		return replacement, nil
	})
	t.Cleanup(func() { m.CloseAll("test_end") })
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	peer := newSessionTestPeer()
	go func() { result <- m.Open(ctx, "same", peer, 80, 24) }()
	<-entered
	duplicate := make(chan error, 1)
	go func() { duplicate <- m.Open(context.Background(), "same", newSessionTestPeer(), 80, 24) }()
	select {
	case err := <-duplicate:
		if err == nil || calls.Load() != 1 {
			t.Fatal("duplicate startup spawned")
		}
	case <-time.After(time.Second):
		t.Fatal("factory held manager lock")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled open succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("factory held cancellation")
	}
	sessionEventually(t, func() bool { return m.Count() == 0 })
	next := newSessionTestPeer()
	sessionOpen(t, m, "same", next)
	close(gate)
	sessionEventually(t, func() bool { return old.waits.Load() == 1 })
	next.send(wsOpcodeBinary, []byte("alive"))
	sessionEventually(t, func() bool { return replacement.text() == "alive" })
	if m.Count() != 1 {
		t.Fatal("late cleanup removed replacement")
	}
}

func TestTerminalSessionFactoryErrorAndValidationReleaseSlot(t *testing.T) {
	var calls atomic.Int32
	m := newTerminalManager(1, func(c, r uint16) (terminalProcess, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("fake secret must not be sent")
		}
		return newSessionTestProcess(), nil
	})
	t.Cleanup(func() { m.CloseAll("test_end") })
	for _, tt := range []struct {
		id   string
		c, r uint16
	}{{"", 80, 24}, {"../id", 80, 24}, {"ok", 0, 24}, {"ok", 501, 24}} {
		if err := m.Open(context.Background(), tt.id, newSessionTestPeer(), tt.c, tt.r); err == nil {
			t.Fatal("invalid admission")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("validation after spawn")
	}
	p := newSessionTestPeer()
	if err := m.Open(context.Background(), "first", p, 80, 24); err == nil {
		t.Fatal("factory error swallowed")
	}
	sessionEventually(t, func() bool { return m.Count() == 0 })
	sessionOpen(t, m, "next", newSessionTestPeer())
}

func TestTerminalSessionPartialInputTypedJSONAndBatchedACK(t *testing.T) {
	p := newSessionTestProcess()
	p.partial = 3
	peer := newSessionTestPeer()
	m := newTerminalManager(4, func(c, r uint16) (terminalProcess, error) { return p, nil })
	t.Cleanup(func() { m.CloseAll("test_end") })
	sessionOpen(t, m, "s", peer)
	text := `{"type":"resize","cols":1,"rows":1}`
	start := time.Now()
	peer.send(wsOpcodeBinary, []byte(text))
	sessionEventually(t, func() bool { return p.text() == text })
	inputLatency := time.Since(start)
	if inputLatency > 100*time.Millisecond {
		t.Fatal("low traffic input was delayed")
	}
	f := sessionFrame(t, peer)
	if string(f.data) != fmt.Sprintf(`{"type":"ack","bytes":%d}`, len(text)) {
		t.Fatalf("ACK=%s", f.data)
	}
	for i := 0; i < 100; i++ {
		peer.send(wsOpcodeBinary, []byte("x"))
	}
	sessionEventually(t, func() bool { return len(p.text()) == len(text)+100 })
	acks := 0
	last := int64(len(text))
	end := time.After(time.Second)
	for last < int64(len(text)+100) {
		select {
		case f := <-peer.out:
			c, err := parseTerminalControl(f.data, "agent")
			if err != nil || c.Type != "ack" || c.Bytes < last {
				t.Fatalf("bad ACK %s", f.data)
			}
			last = c.Bytes
			acks++
		case <-end:
			t.Fatal("ACK never flushed")
		}
	}
	if acks >= 20 {
		t.Fatalf("ACK events not batched: %d", acks)
	}
	t.Logf("input latency=%s, 100 one-byte input frames => %d cumulative ACK events", inputLatency, acks)
}

func TestTerminalSessionOutputWindowProducerPauseAndBatch(t *testing.T) {
	p := newSessionTestProcess()
	peer := newSessionTestPeer()
	m := newTerminalManager(4, func(c, r uint16) (terminalProcess, error) { return p, nil })
	t.Cleanup(func() { m.CloseAll("test_end") })
	sessionOpen(t, m, "s", peer)
	finished := make(chan struct{})
	go func() { defer close(finished); _, _ = p.output.Write(bytes.Repeat([]byte("a"), 262145)) }()
	total := 0
	frames := 0
	for total < 262144 {
		f := sessionFrame(t, peer)
		if f.op != wsOpcodeBinary || len(f.data) > 16384 {
			t.Fatal("invalid output frame")
		}
		total += len(f.data)
		frames++
	}
	time.Sleep(20 * time.Millisecond)
	if total != 262144 || p.reads.Load() != 262144 {
		t.Fatalf("credit exceeded: sent=%d read=%d", total, p.reads.Load())
	}
	select {
	case <-finished:
		t.Fatal("producer read past credit")
	default:
	}
	peer.send(wsOpcodeText, []byte(`{"type":"ack","bytes":262144}`))
	f := sessionFrame(t, peer)
	if f.op != wsOpcodeBinary || string(f.data) != "a" {
		t.Fatal("credit did not resume producer")
	}
	if frames != 16 {
		t.Fatalf("full window used %d frames instead of 16", frames)
	}
	peer.send(wsOpcodeText, []byte(`{"type":"ack","bytes":262145}`))
	go func() {
		for i := 0; i < 100; i++ {
			_, _ = p.output.Write([]byte("b"))
		}
	}()
	total = 0
	frames = 0
	for total < 100 {
		f = sessionFrame(t, peer)
		total += len(f.data)
		frames++
	}
	if frames >= 20 {
		t.Fatalf("output events not batched: %d", frames)
	}
	t.Logf("262144 output bytes => 16 frames; 100 one-byte producer reads => %d frames", frames)
}

func TestTerminalSessionRejectsControlsAndOversizedInputLocally(t *testing.T) {
	for _, text := range []string{`{"type":"start","cols":80,"rows":24}`, `{"type":"ready"}`, `{"type":"hello","protocol":1,"platform":"linux","capabilities":["terminal.pty.v1"]}`, `{"type":"ack","bytes":1}`, `{"type":"resize","cols":501,"rows":24}`, `{"type":"resize","cols":80,"rows":24,"x":1}`} {
		t.Run(text, func(t *testing.T) {
			p := newSessionTestProcess()
			peer := newSessionTestPeer()
			m := newTerminalManager(4, func(c, r uint16) (terminalProcess, error) { return p, nil })
			t.Cleanup(func() { m.CloseAll("test_end") })
			sessionOpen(t, m, "s", peer)
			peer.send(wsOpcodeText, []byte(text))
			sessionEventually(t, func() bool { return m.Count() == 0 })
			if p.text() != "" {
				t.Fatal("control reached PTY")
			}
		})
	}
	p := newSessionTestProcess()
	peer := newSessionTestPeer()
	m := newTerminalManager(4, func(c, r uint16) (terminalProcess, error) { return p, nil })
	t.Cleanup(func() { m.CloseAll("test_end") })
	sessionOpen(t, m, "s", peer)
	peer.send(wsOpcodeBinary, bytes.Repeat([]byte("x"), 16385))
	sessionEventually(t, func() bool { return m.Count() == 0 })
	if p.text() != "" {
		t.Fatal("oversized input written")
	}
}

func TestTerminalSessionInputWindowAndSlowPeerIsolation(t *testing.T) {
	var n int
	a, b := newSessionTestProcess(), newSessionTestProcess()
	a.inputGate = make(chan struct{})
	m := newTerminalManager(4, func(c, r uint16) (terminalProcess, error) {
		n++
		if n == 1 {
			return a, nil
		}
		return b, nil
	})
	t.Cleanup(func() { m.CloseAll("test_end") })
	pa, pb := newSessionTestPeer(), newSessionTestPeer()
	sessionOpen(t, m, "a", pa)
	sessionOpen(t, m, "b", pb)
	for i := 0; i < 16; i++ {
		pa.send(wsOpcodeBinary, bytes.Repeat([]byte("x"), 16384))
	}
	pb.send(wsOpcodeBinary, []byte("responsive"))
	sessionEventually(t, func() bool { return b.text() == "responsive" })
	select {
	case f := <-pa.out:
		t.Fatalf("ACK before successful PTY write: %s", f.data)
	default:
	}
	pa.send(wsOpcodeBinary, []byte("overflow"))
	sessionEventually(t, func() bool { return m.Count() == 1 })
	if a.text() != "" {
		t.Fatal("blocked input wrote")
	}
	pb.send(wsOpcodeBinary, []byte("again"))
	sessionEventually(t, func() bool { return b.text() == "responsiveagain" })
}

func TestTerminalSessionResizeDuplicateACKAndRegressingACK(t *testing.T) {
	p := newSessionTestProcess()
	peer := newSessionTestPeer()
	m := newTerminalManager(4, func(c, r uint16) (terminalProcess, error) { return p, nil })
	t.Cleanup(func() { m.CloseAll("test_end") })
	sessionOpen(t, m, "s", peer)
	peer.send(wsOpcodeText, []byte(`{"type":"resize","cols":120,"rows":40}`))
	sessionEventually(t, func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return len(p.sizes) == 1 && p.sizes[0] == [2]uint16{120, 40}
	})
	go func() { _, _ = p.output.Write([]byte("abc")) }()
	_ = sessionFrame(t, peer)
	peer.send(wsOpcodeText, []byte(`{"type":"ack","bytes":3}`))
	peer.send(wsOpcodeText, []byte(`{"type":"ack","bytes":3}`))
	peer.send(wsOpcodeText, []byte(`{"type":"ack","bytes":2}`))
	sessionEventually(t, func() bool { return m.Count() == 0 })
}

func TestTerminalSessionCloseAllJoinsPumpsAndTimers(t *testing.T) {
	before := runtime.NumGoroutine()
	var processes []*sessionTestProcess
	m := newTerminalManager(4, func(c, r uint16) (terminalProcess, error) {
		p := newSessionTestProcess()
		processes = append(processes, p)
		return p, nil
	})
	for i := 0; i < 4; i++ {
		sessionOpen(t, m, fmt.Sprint(i), newSessionTestPeer())
	}
	m.CloseAll("control_loss")
	m.CloseAll("shutdown")
	sessionEventually(t, func() bool {
		for _, p := range processes {
			if p.waits.Load() != 1 {
				return false
			}
		}
		return m.Count() == 0 && runtime.NumGoroutine() <= before+2
	})
}

func TestTerminalSessionStallDeadlinesAndWriterIsolation(t *testing.T) {
	var calls int
	a, b := newSessionTestProcess(), newSessionTestProcess()
	slow := newSessionTestProcess()
	slow.inputGate = make(chan struct{})
	m := newTerminalManager(4, func(c, r uint16) (terminalProcess, error) {
		calls++
		if calls == 1 {
			return a, nil
		}
		if calls == 2 {
			return b, nil
		}
		return slow, nil
	})
	t.Cleanup(func() { m.CloseAll("test_end") })
	pa, pb := newSessionTestPeer(), newSessionTestPeer()
	sessionOpen(t, m, "a", pa)
	sessionOpen(t, m, "b", pb)
	slowPeer := newSessionTestPeer()
	sessionOpen(t, m, "slow", slowPeer)
	start := time.Now()
	go func() { _, _ = a.output.Write([]byte("unacked")) }()
	_ = sessionFrame(t, pa)
	pa.send(wsOpcodeText, []byte(`{"type":"ack","bytes":0}`))
	slowPeer.send(wsOpcodeBinary, []byte("blocked"))
	duplicate := time.AfterFunc(15*time.Second, func() {
		pa.send(wsOpcodeText, []byte(`{"type":"ack","bytes":0}`))
		pa.send(wsOpcodeText, []byte(`{"type":"ping"}`))
	})
	defer duplicate.Stop()
	pb.send(wsOpcodeBinary, []byte("fast"))
	sessionEventually(t, func() bool { return b.text() == "fast" })
	select {
	case <-pa.closed:
		if time.Since(start) < 29*time.Second {
			t.Fatal("stall closed early")
		}
	case <-time.After(32 * time.Second):
		t.Fatal("output stall never closed")
	}
	select {
	case <-slowPeer.closed:
		if time.Since(start) < 29*time.Second {
			t.Fatal("input stall closed early")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked input never stalled")
	}
	if m.Count() != 1 {
		t.Fatal("stall closed healthy session")
	}
	pc := newSessionTestPeer()
	c := newSessionTestProcess()
	m2 := newTerminalManager(1, func(c1, r uint16) (terminalProcess, error) { return c, nil })
	t.Cleanup(func() { m2.CloseAll("test_end") })
	sessionOpen(t, m2, "c", pc)
	pc.block = make(chan struct{})
	start = time.Now()
	go func() { _, _ = c.output.Write([]byte("blocked")) }()
	select {
	case <-pc.closed:
		if time.Since(start) < 7*time.Second || time.Since(start) > 10*time.Second {
			t.Fatal("wrong socket write deadline")
		}
	case <-time.After(11 * time.Second):
		t.Fatal("write deadline never closed")
	}
}

func TestTerminalSessionUnsupportedPlatformNeverSpawns(t *testing.T) {
	if runtime.GOOS == "linux" {
		return
	}
	for i := 0; i < 2; i++ {
		p, err := newTerminalProcess(80, 24)
		if p != nil || !errors.Is(err, errTerminalUnsupported) {
			t.Fatal("unsupported platform created a process or unstable error")
		}
	}
}

func TestTerminalSessionFactoryPartialFailureOwnsCleanup(t *testing.T) {
	p := newSessionTestProcess()
	defer p.Close()
	m := newTerminalManager(4, func(c, r uint16) (terminalProcess, error) { return p, errors.New("partial start failed") })
	if err := m.Open(context.Background(), "s", newSessionTestPeer(), 80, 24); err == nil {
		t.Fatal("partial failure admitted")
	}
	sessionEventually(t, func() bool { return m.Count() == 0 && p.waits.Load() == 1 })
	select {
	case <-p.closed:
	default:
		t.Fatal("partial factory process leaked")
	}
}

func TestTerminalSessionFourBidirectionalWindowsAreBounded(t *testing.T) {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var processes []*sessionTestProcess
	m := newTerminalManager(4, func(c, r uint16) (terminalProcess, error) {
		p := newSessionTestProcess()
		p.inputGate = make(chan struct{})
		processes = append(processes, p)
		return p, nil
	})
	t.Cleanup(func() { m.CloseAll("test_end") })
	peers := make([]*sessionTestPeer, 4)
	for i := range peers {
		peers[i] = newSessionTestPeer()
		sessionOpen(t, m, fmt.Sprint(i), peers[i])
	}
	sentInput, sentOutput := 0, 0
	for i, peer := range peers {
		for n := 0; n < 16; n++ {
			peer.send(wsOpcodeBinary, bytes.Repeat([]byte("i"), 16384))
			sentInput += 16384
		}
		p := processes[i]
		go func() { _, _ = p.output.Write(bytes.Repeat([]byte("o"), 262145)) }()
		for n := 0; n < 16; n++ {
			f := sessionFrame(t, peer)
			if f.op != wsOpcodeBinary || len(f.data) != 16384 {
				t.Fatal("unexpected output boundary")
			}
			sentOutput += len(f.data)
		}
	}
	if sentInput+sentOutput != 2097152 {
		t.Fatal("aggregate outstanding boundary mismatch")
	}
	time.Sleep(10 * time.Millisecond)
	for i, p := range processes {
		if p.reads.Load() != 262144 || p.text() != "" {
			t.Fatal("producer over-read or blocked input consumed")
		}
		select {
		case f := <-peers[i].out:
			t.Fatalf("extra data/ACK beyond windows: %s", f.data)
		default:
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	growth := int64(after.Alloc) - int64(before.Alloc)
	if growth > 8*1024*1024 {
		t.Fatalf("bounded four-session heap grew %d bytes", growth)
	}
	t.Logf("4 bidirectional windows: actual received/forwarded=%d bytes; live heap delta including test/transport=%d bytes", sentInput+sentOutput, growth)
}

type sessionTestExitError int

func (e sessionTestExitError) Error() string { return "test exit" }
func (e sessionTestExitError) ExitCode() int { return int(e) }

type sessionTestExitingProcess struct {
	*sessionTestProcess
	exit chan struct{}
}

func (p *sessionTestExitingProcess) Wait() error {
	p.waits.Add(1)
	select {
	case <-p.exit:
		return sessionTestExitError(7)
	case <-p.closed:
		return nil
	}
}

func TestTerminalSessionNormalExitFlushesLastOutputAndCode(t *testing.T) {
	p := &sessionTestExitingProcess{newSessionTestProcess(), make(chan struct{})}
	peer := newSessionTestPeer()
	m := newTerminalManager(4, func(c, r uint16) (terminalProcess, error) { return p, nil })
	t.Cleanup(func() { m.CloseAll("test_end") })
	sessionOpen(t, m, "s", peer)
	go func() { _, _ = p.output.Write([]byte("final")); _ = p.output.Close(); close(p.exit) }()
	f := sessionFrame(t, peer)
	if f.op != wsOpcodeBinary || string(f.data) != "final" {
		t.Fatalf("trailing output lost: %s", f.data)
	}
	f = sessionFrame(t, peer)
	if string(f.data) != `{"type":"exit","code":7}` {
		t.Fatalf("exit code/order lost: %s", f.data)
	}
	sessionEventually(t, func() bool { return m.Count() == 0 && p.waits.Load() == 1 })
}

type sessionTestImmediateACKPeer struct {
	*sessionTestPeer
	process   *sessionTestProcess
	triggered atomic.Bool
}

func (p *sessionTestImmediateACKPeer) WriteText(b []byte, d time.Duration) error {
	if err := p.sessionTestPeer.WriteText(b, d); err != nil {
		return err
	}
	c, err := parseTerminalControl(b, "agent")
	if err == nil && c.Type == "ack" && c.Bytes == 262144 && p.triggered.CompareAndSwap(false, true) {
		p.send(wsOpcodeBinary, []byte("z"))
		end := time.NewTimer(time.Second)
		defer end.Stop()
		for func() bool { p.process.mu.Lock(); defer p.process.mu.Unlock(); return p.process.input.Len() == 262144 }() {
			select {
			case <-p.closed:
				return io.EOF
			case <-end.C:
				return errors.New("immediate ACK reply stalled")
			default:
				time.Sleep(time.Millisecond)
			}
		}
	}
	return nil
}

func TestTerminalSessionImmediateInputAfterObservedACKIsNotRejected(t *testing.T) {
	p := newSessionTestProcess()
	base := newSessionTestPeer()
	peer := &sessionTestImmediateACKPeer{sessionTestPeer: base, process: p}
	m := newTerminalManager(1, func(c, r uint16) (terminalProcess, error) { return p, nil })
	t.Cleanup(func() { m.CloseAll("test_end") })
	if err := m.Open(context.Background(), "s", peer, 80, 24); err != nil {
		t.Fatal(err)
	}
	sessionReady(t, base)
	for i := 0; i < 16; i++ {
		base.send(wsOpcodeBinary, bytes.Repeat([]byte("x"), 16384))
	}
	want := string(bytes.Repeat([]byte("x"), 262144)) + "z"
	sessionEventually(t, func() bool { return p.text() == want })
	if m.Count() != 1 {
		t.Fatal("valid post-ACK input closed session")
	}
}

func TestTerminalSessionContextCancellationAfterOpenCleansResources(t *testing.T) {
	p := newSessionTestProcess()
	peer := newSessionTestPeer()
	m := newTerminalManager(4, func(c, r uint16) (terminalProcess, error) { return p, nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer m.CloseAll("test_end")
	if err := m.Open(ctx, "s", peer, 80, 24); err != nil {
		t.Fatal(err)
	}
	sessionReady(t, peer)
	cancel()
	sessionEventually(t, func() bool { return m.Count() == 0 && p.waits.Load() == 1 })
	select {
	case <-peer.closed:
	default:
		t.Fatal("cancelled peer remains open")
	}
}

func TestTerminalSessionLowTrafficEchoLatency(t *testing.T) {
	p := newSessionTestProcess()
	peer := newSessionTestPeer()
	m := newTerminalManager(1, func(c, r uint16) (terminalProcess, error) { return p, nil })
	t.Cleanup(func() { m.CloseAll("test_end") })
	sessionOpen(t, m, "s", peer)
	start := time.Now()
	peer.send(wsOpcodeBinary, []byte("k"))
	sessionEventually(t, func() bool { return p.text() == "k" })
	go func() { _, _ = p.output.Write([]byte("k")) }()
	for {
		f := sessionFrame(t, peer)
		if f.op == wsOpcodeBinary {
			if string(f.data) != "k" {
				t.Fatal("echo corrupted")
			}
			break
		}
	}
	latency := time.Since(start)
	if latency > 100*time.Millisecond {
		t.Fatalf("low traffic echo delayed %s", latency)
	}
	t.Logf("fake PTY keyboard-to-output latency=%s (includes test polling)", latency)
}

func TestTerminalSessionAdmissionFailureClosesOnlyIncomingPeer(t *testing.T) {
	p := newSessionTestProcess()
	m := newTerminalManager(1, func(c, r uint16) (terminalProcess, error) { return p, nil })
	t.Cleanup(func() { m.CloseAll("test_end") })
	active := newSessionTestPeer()
	sessionOpen(t, m, "active", active)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tt := range []struct {
		ctx context.Context
		id  string
		c   uint16
	}{{context.Background(), "active", 80}, {context.Background(), "full", 80}, {context.Background(), "bad", 0}, {cancelled, "cancelled", 80}} {
		incoming := newSessionTestPeer()
		if err := m.Open(tt.ctx, tt.id, incoming, tt.c, 24); err == nil {
			t.Fatal("invalid admission accepted")
		}
		select {
		case <-incoming.closed:
		default:
			t.Fatal("rejected incoming peer leaked")
		}
	}
	active.send(wsOpcodeBinary, []byte("still active"))
	sessionEventually(t, func() bool { return p.text() == "still active" })
	if m.Count() != 1 {
		t.Fatal("rejected admission removed active session")
	}
}

func TestTerminalSessionShellExitDoesNotWaitForInheritedPTYEOF(t *testing.T) {
	p := &sessionTestExitingProcess{newSessionTestProcess(), make(chan struct{})}
	peer := newSessionTestPeer()
	m := newTerminalManager(4, func(cols, rows uint16) (terminalProcess, error) { return p, nil })
	t.Cleanup(func() { m.CloseAll("test_end") })
	sessionOpen(t, m, "shell-exit", peer)
	close(p.exit)
	select {
	case <-peer.closed:
		if m.Count() != 0 || p.waits.Load() != 1 {
			t.Fatal("exited Shell retained its slot or acquired another Wait owner")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Shell Wait completed but inherited PTY keeps session live: count=%d waits=%d", m.Count(), p.waits.Load())
	}
	f := sessionFrame(t, peer)
	if string(f.data) != `{"type":"exit","code":7}` {
		t.Fatalf("missing Shell exit notification: %s", f.data)
	}
}

func TestTerminalSessionShellExitDrainsLateOutputWithoutClosingAnotherSession(t *testing.T) {
	p := &sessionTestExitingProcess{newSessionTestProcess(), make(chan struct{})}
	other := newSessionTestProcess()
	calls := 0
	m := newTerminalManager(4, func(cols, rows uint16) (terminalProcess, error) {
		calls++
		if calls == 1 {
			return p, nil
		}
		return other, nil
	})
	t.Cleanup(func() { m.CloseAll("test_end") })
	peer, healthy := newSessionTestPeer(), newSessionTestPeer()
	sessionOpen(t, m, "exit", peer)
	sessionOpen(t, m, "healthy", healthy)
	start := time.Now()
	close(p.exit)
	producer := make(chan error, 1)
	go func() {
		time.Sleep(10 * time.Millisecond)
		_, err := p.output.Write([]byte("late final output"))
		producer <- err
	}()
	healthy.send(wsOpcodeBinary, []byte("during drain"))
	var out bytes.Buffer
	for {
		f := sessionFrame(t, peer)
		if f.op == wsOpcodeBinary {
			out.Write(f.data)
			continue
		}
		if string(f.data) != `{"type":"exit","code":7}` {
			t.Fatalf("unexpected exit control: %s", f.data)
		}
		break
	}
	if out.String() != "late final output" || time.Since(start) > 2*time.Second {
		t.Fatalf("tail lost or drain unbounded: %q elapsed=%s", out.String(), time.Since(start))
	}
	if err := <-producer; err != nil {
		t.Fatal(err)
	}
	sessionEventually(t, func() bool { return m.Count() == 1 && other.text() == "during drain" })
	healthy.send(wsOpcodeBinary, []byte(" and after exit"))
	sessionEventually(t, func() bool { return other.text() == "during drain and after exit" })
	t.Logf("retained open PTY: exit/drain=%s, trailing bytes=%d, Wait owners=%d", time.Since(start), out.Len(), p.waits.Load())
}

func TestTerminalSessionShellExitAtFullOutputWindowRemainsBounded(t *testing.T) {
	p := &sessionTestExitingProcess{newSessionTestProcess(), make(chan struct{})}
	peer := newSessionTestPeer()
	m := newTerminalManager(1, func(cols, rows uint16) (terminalProcess, error) { return p, nil })
	t.Cleanup(func() { m.CloseAll("test_end") })
	sessionOpen(t, m, "saturated-exit", peer)
	producer := make(chan error, 1)
	go func() { _, err := p.output.Write(bytes.Repeat([]byte("x"), 262145)); producer <- err }()
	close(p.exit)
	total, frames := 0, 0
	for {
		f := sessionFrame(t, peer)
		if f.op == wsOpcodeBinary {
			if len(f.data) > 16384 {
				t.Fatal("exit drain exceeded frame limit")
			}
			total += len(f.data)
			frames++
			continue
		}
		if string(f.data) != `{"type":"exit","code":7}` {
			t.Fatalf("unexpected control: %s", f.data)
		}
		break
	}
	if total != 262144 || p.reads.Load() != 262144 || frames != 16 {
		t.Fatalf("exit bypassed credit or dropped admitted tail: sent=%d read=%d frames=%d", total, p.reads.Load(), frames)
	}
	sessionEventually(t, func() bool { return m.Count() == 0 && p.waits.Load() == 1 })
	select {
	case <-producer:
	case <-time.After(time.Second):
		t.Fatal("retained-slave producer leaked after exit")
	}
}

func TestTerminalSessionShellExitCannotBeExtendedByContinuingOutputAndACKs(t *testing.T) {
	p := &sessionTestExitingProcess{newSessionTestProcess(), make(chan struct{})}
	peer := newSessionTestPeer()
	m := newTerminalManager(1, func(cols, rows uint16) (terminalProcess, error) { return p, nil })
	t.Cleanup(func() { m.CloseAll("test_end") })
	sessionOpen(t, m, "streaming-exit", peer)
	m.mu.Lock()
	session := m.sessions["streaming-exit"]
	m.mu.Unlock()
	producer := make(chan struct{})
	go func() {
		defer close(producer)
		chunk := bytes.Repeat([]byte("x"), 16384)
		for {
			if _, err := p.output.Write(chunk); err != nil {
				return
			}
		}
	}()
	start := time.Now()
	close(p.exit)
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	var total int64
	var maxOutstanding int64
	frames := 0
	exited := false
	for !exited {
		select {
		case f := <-peer.out:
			if f.op == wsOpcodeBinary {
				if len(f.data) > 16384 {
					t.Fatal("streaming exit exceeded frame bound")
				}
				total += int64(len(f.data))
				frames++
				session.mu.Lock()
				outstanding := session.produced - session.outputACK
				session.mu.Unlock()
				if outstanding < 0 || outstanding > 262144 {
					t.Fatalf("streaming exit exceeded credit: %d", outstanding)
				}
				maxOutstanding = max(maxOutstanding, outstanding)
				ack := sessionTestFrame{[]byte(fmt.Sprintf(`{"type":"ack","bytes":%d}`, total)), wsOpcodeText}
				select {
				case peer.in <- ack:
				case <-peer.closed:
				}
				continue
			}
			if string(f.data) != `{"type":"exit","code":7}` {
				t.Fatalf("streaming exit lost code: %s", f.data)
			}
			exited = true
		case <-deadline.C:
			t.Fatal("continuing output/ACKs extended Shell exit indefinitely")
		}
	}
	session.mu.Lock()
	forwarded, produced := session.forwarded, session.produced
	session.mu.Unlock()
	if total == 0 || forwarded != total || forwarded > produced {
		t.Fatalf("exit accounting diverged: wire=%d forwarded=%d produced=%d", total, forwarded, produced)
	}
	sessionEventually(t, func() bool { return m.Count() == 0 && p.waits.Load() == 1 })
	select {
	case <-producer:
	case <-time.After(time.Second):
		t.Fatal("continuous producer leaked")
	}
	t.Logf("continuous output/ACK exit=%s, forwarded bytes=%d frames=%d peak outstanding=%d", time.Since(start), total, frames, maxOutstanding)
}
