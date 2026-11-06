package cfprobe

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

const (
	terminalWriteTimeout     = 8 * time.Second
	terminalStallTimeout     = 30 * time.Second
	terminalBatchDelay       = 2 * time.Millisecond
	terminalExitDrainTimeout = 500 * time.Millisecond
)

var errTerminalUnsupported = errors.New("terminal PTY is unsupported on this platform")

type terminalProcess interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	Resize(cols, rows uint16) error
	Wait() error
}

type terminalPeer interface {
	ReadDataMessageLimit(int) ([]byte, byte, error)
	WriteText([]byte, time.Duration) error
	WriteBinary([]byte, time.Duration) error
	SetReadDeadline(time.Time) error
	Close() error
}

type terminalFactory func(cols, rows uint16) (terminalProcess, error)

type terminalManager struct {
	mu       sync.Mutex
	limit    int
	factory  terminalFactory
	sessions map[string]*terminalSession
}

func newTerminalManager(limit int, factory terminalFactory) *terminalManager {
	if limit < 1 || limit > terminalMaxSessions {
		limit = terminalMaxSessions
	}
	return &terminalManager{limit: limit, factory: factory, sessions: make(map[string]*terminalSession)}
}

// Open takes ownership of a fresh, unshared peer, including rejected admissions.
func (m *terminalManager) Open(ctx context.Context, id string, peer terminalPeer, cols, rows uint16) error {
	if ctx == nil || peer == nil || m.factory == nil || !terminalIDRE.MatchString(id) || !validateTerminalSize(int(cols), int(rows)) {
		if peer != nil {
			_ = peer.Close()
		}
		return errors.New("invalid terminal session")
	}
	if err := ctx.Err(); err != nil {
		_ = peer.Close()
		return err
	}
	m.mu.Lock()
	if m.sessions[id] != nil || len(m.sessions) >= m.limit {
		m.mu.Unlock()
		_ = peer.Close()
		return errors.New("terminal session unavailable")
	}
	sctx, cancel := context.WithCancel(ctx)
	s := &terminalSession{manager: m, id: id, peer: peer, ctx: sctx, cancel: cancel, done: make(chan struct{}), started: make(chan struct{}), input: make(chan []byte, 16), output: make(chan terminalOutput, 16), ackWake: make(chan struct{}, 1), creditWake: make(chan struct{}, 1), stallWake: make(chan struct{}, 1), controls: make(chan []byte, 1)}
	m.sessions[id] = s
	m.mu.Unlock()
	result := make(chan error, 1)
	go s.run(cols, rows, result)
	select {
	case err := <-result:
		return err
	case <-sctx.Done():
		s.stop()
		return sctx.Err()
	}
}

func (m *terminalManager) Count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.sessions) }

func (m *terminalManager) Close(id string) error {
	m.mu.Lock()
	s := m.sessions[id]
	m.mu.Unlock()
	if s != nil {
		s.stop()
		s.joinStarted()
	}
	return nil
}

func (m *terminalManager) CloseAll(reason string) {
	m.mu.Lock()
	sessions := make([]*terminalSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()
	for _, s := range sessions {
		s.stop()
	}
	for _, s := range sessions {
		s.joinStarted()
	}
}

type terminalOutput struct {
	data []byte
	err  error
}

type terminalSession struct {
	manager                        *terminalManager
	id                             string
	peer                           terminalPeer
	ctx                            context.Context
	cancel                         context.CancelFunc
	stopOnce                       sync.Once
	done, started                  chan struct{}
	input                          chan []byte
	output                         chan terminalOutput
	controls                       chan []byte
	ackWake, creditWake, stallWake chan struct{}
	mu                             sync.Mutex
	received, consumed, inputACK   int64
	produced, forwarded, outputACK int64
	inputProgress, outputProgress  time.Time
}

func terminalWake(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (s *terminalSession) stop() {
	s.stopOnce.Do(func() {
		s.cancel()
		s.manager.mu.Lock()
		if s.manager.sessions[s.id] == s {
			delete(s.manager.sessions, s.id)
		}
		s.manager.mu.Unlock()
		_ = s.peer.Close()
	})
}

func (s *terminalSession) joinStarted() {
	// A cancelled, still-running factory owns its eventual cleanup, not a replacement's slot.
	select {
	case <-s.started:
		<-s.done
	default:
	}
}

func (s *terminalSession) run(cols, rows uint16, result chan<- error) {
	defer close(s.done)
	p, err := s.manager.factory(cols, rows)
	close(s.started)
	if p == nil {
		s.stop()
		result <- errors.New("terminal process start failed")
		return
	}
	wait := make(chan error, 1)
	go func() { wait <- p.Wait() }()
	var pumps sync.WaitGroup
	defer func() { s.stop(); _ = p.Close(); pumps.Wait(); <-wait }()
	if err != nil {
		s.stop()
		result <- errors.New("terminal process start failed")
		return
	}
	if s.ctx.Err() != nil {
		result <- s.ctx.Err()
		return
	}
	if err = s.peer.WriteText([]byte(`{"type":"ready"}`), terminalWriteTimeout); err != nil {
		result <- errors.New("terminal peer write failed")
		return
	}
	start := func(fn func() error) {
		pumps.Add(1)
		go func() {
			defer pumps.Done()
			if fn() != nil {
				s.stop()
			}
		}()
	}
	start(func() error { return s.readPeer(p) })
	start(func() error { return s.writeInput(p) })
	start(func() error { return s.readOutput(p) })
	start(func() error { return s.writePeer(wait) })
	start(s.watchStall)
	result <- nil
	<-s.ctx.Done()
}

func (s *terminalSession) readPeer(p terminalProcess) error {
	for {
		data, op, err := s.peer.ReadDataMessageLimit(terminalMaxDataFrameBytes)
		if err != nil {
			return err
		}
		if op == wsOpcodeBinary {
			if len(data) == 0 {
				continue
			}
			s.mu.Lock()
			if len(data) > terminalMaxDataFrameBytes || s.received > terminalMaxSafeInteger-int64(len(data)) || s.received-s.inputACK+int64(len(data)) > terminalCreditBytes {
				s.mu.Unlock()
				return errors.New("terminal input credit exceeded")
			}
			if s.received == s.consumed {
				s.inputProgress = time.Now()
			}
			s.received += int64(len(data))
			s.mu.Unlock()
			terminalWake(s.stallWake)
			select {
			case s.input <- data:
			case <-s.ctx.Done():
				return s.ctx.Err()
			}
			continue
		}
		if op != wsOpcodeText {
			return errors.New("invalid terminal data opcode")
		}
		c, err := parseTerminalControl(data, "broker")
		if err != nil {
			return err
		}
		switch c.Type {
		case "ack":
			s.mu.Lock()
			if c.Bytes < s.outputACK || c.Bytes > s.forwarded {
				s.mu.Unlock()
				return errors.New("invalid terminal output ACK")
			}
			if c.Bytes > s.outputACK {
				s.outputACK = c.Bytes
				s.outputProgress = time.Now()
			}
			s.mu.Unlock()
			terminalWake(s.creditWake)
			terminalWake(s.stallWake)
		case "resize":
			if err := p.Resize(uint16(c.Cols), uint16(c.Rows)); err != nil {
				return err
			}
		case "ping":
			select {
			case s.controls <- []byte(`{"type":"pong"}`):
			case <-s.ctx.Done():
				return s.ctx.Err()
			}
		case "pong":
		case "exit", "error":
			return io.EOF
		default:
			return errors.New("terminal control out of order")
		}
	}
}

func (s *terminalSession) writeInput(p terminalProcess) error {
	for {
		select {
		case data := <-s.input:
			for len(data) > 0 {
				n, err := p.Write(data)
				if n < 0 || n > len(data) {
					return io.ErrShortWrite
				}
				if n > 0 {
					data = data[n:]
					s.mu.Lock()
					s.consumed += int64(n)
					s.inputProgress = time.Now()
					s.mu.Unlock()
					terminalWake(s.ackWake)
					terminalWake(s.stallWake)
				}
				if err != nil {
					return err
				}
				if n == 0 {
					return io.ErrNoProgress
				}
			}
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
	}
}

func (s *terminalSession) readOutput(p terminalProcess) error {
	for {
		s.mu.Lock()
		budget := terminalCreditBytes - (s.produced - s.outputACK)
		s.mu.Unlock()
		if budget == 0 {
			select {
			case <-s.creditWake:
				continue
			case <-s.ctx.Done():
				return s.ctx.Err()
			}
		}
		data := make([]byte, min(int64(terminalMaxDataFrameBytes), budget))
		n, err := p.Read(data)
		if n < 0 || n > len(data) {
			return errors.New("invalid PTY read")
		}
		if n > 0 {
			s.mu.Lock()
			if s.produced > terminalMaxSafeInteger-int64(n) {
				s.mu.Unlock()
				return errors.New("terminal counter exhausted")
			}
			if s.produced == s.outputACK {
				s.outputProgress = time.Now()
			}
			s.produced += int64(n)
			s.mu.Unlock()
			terminalWake(s.stallWake)
			select {
			case s.output <- terminalOutput{data: data[:n]}:
			case <-s.ctx.Done():
				return s.ctx.Err()
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return err
			}
			select {
			case s.output <- terminalOutput{err: io.EOF}:
			case <-s.ctx.Done():
				return s.ctx.Err()
			}
			return nil
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
}

func (s *terminalSession) writePeer(wait chan error) error {
	timer := time.NewTimer(terminalBatchDelay)
	defer timer.Stop()
	if !timer.Stop() {
		<-timer.C
	}
	var tick <-chan time.Time
	var exitTimer *time.Timer
	defer func() {
		if exitTimer != nil {
			exitTimer.Stop()
		}
	}()
	var exitTick <-chan time.Time
	var waitResult <-chan error = wait
	var exitErr error
	var drainDeadline, writeDeadline time.Time
	outputEOF := false
	drainExpired := errors.New("terminal exit drain expired")
	buffer := make([]byte, 0, terminalMaxDataFrameBytes)
	var pending []byte
	send := func(data []byte, binary bool, ack int64) error {
		timeout := terminalWriteTimeout
		if !writeDeadline.IsZero() {
			timeout = min(timeout, time.Until(writeDeadline))
			if timeout <= 0 {
				return drainExpired
			}
		}
		// Account after the deadline check but before a peer can observe the write.
		if binary {
			s.mu.Lock()
			s.forwarded += int64(len(data))
			s.mu.Unlock()
			return s.peer.WriteBinary(data, timeout)
		}
		if ack >= 0 {
			s.mu.Lock()
			s.inputACK = ack
			s.mu.Unlock()
		}
		return s.peer.WriteText(data, timeout)
	}
	schedule := func() {
		if tick == nil {
			timer.Reset(terminalBatchDelay)
			tick = timer.C
		}
	}
	flush := func() error {
		if len(buffer) > 0 {
			if err := send(buffer, true, -1); err != nil {
				return err
			}
			buffer = buffer[:0]
		}
		s.mu.Lock()
		ack := s.consumed
		last := s.inputACK
		s.mu.Unlock()
		if ack > last {
			data, _ := json.Marshal(struct {
				Type  string `json:"type"`
				Bytes int64  `json:"bytes"`
			}{"ack", ack})
			if err := send(data, false, ack); err != nil {
				return err
			}
		}
		return nil
	}
	appendOutput := func(data []byte) error {
		for len(data) > 0 {
			n := min(terminalMaxDataFrameBytes-len(buffer), len(data))
			buffer = append(buffer, data[:n]...)
			data = data[n:]
			if len(buffer) == terminalMaxDataFrameBytes {
				if err := flush(); err != nil {
					pending = data
					return err
				}
			}
		}
		return nil
	}
	finish := func() error {
		// Drain only the bounded queue snapshot; a retained slave cannot extend exit forever.
		writeDeadline = time.Now().Add(terminalExitDrainTimeout)
		queued := len(s.output)
		if err := appendOutput(pending); err != nil {
			return err
		}
		pending = nil
		for i := 0; i < queued; i++ {
			out := <-s.output
			if err := appendOutput(out.data); err != nil {
				return err
			}
		}
		if err := flush(); err != nil {
			return err
		}
		code := 0
		var exit interface{ ExitCode() int }
		if errors.As(exitErr, &exit) {
			code = exit.ExitCode()
		} else if exitErr != nil {
			code = -1
		}
		if code < 0 || code > 255 {
			code = -1
		}
		data, _ := json.Marshal(struct {
			Type string `json:"type"`
			Code int    `json:"code"`
		}{"exit", code})
		if err := send(data, false, -1); err != nil {
			return err
		}
		return io.EOF
	}
	for {
		if !drainDeadline.IsZero() && !time.Now().Before(drainDeadline) {
			return finish()
		}
		var err error
		select {
		case exitErr = <-waitResult:
			// The lifecycle owner still joins this one Wait; EOF is a separate event.
			wait <- exitErr
			waitResult = nil
			if outputEOF {
				return finish()
			}
			drainDeadline = time.Now().Add(terminalExitDrainTimeout)
			writeDeadline = drainDeadline
			exitTimer = time.NewTimer(terminalExitDrainTimeout)
			exitTick = exitTimer.C
		case out := <-s.output:
			if out.err != nil {
				outputEOF = true
				if waitResult == nil {
					return finish()
				}
				err = flush()
			} else {
				err = appendOutput(out.data)
				schedule()
			}
		case <-s.ackWake:
			schedule()
		case data := <-s.controls:
			err = send(data, false, -1)
		case <-tick:
			tick = nil
			err = flush()
		case <-exitTick:
			return finish()
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
		if err == drainExpired {
			return finish()
		}
		if err != nil {
			return err
		}
	}
}

func (s *terminalSession) watchStall() error {
	timer := time.NewTimer(terminalStallTimeout)
	defer timer.Stop()
	for {
		s.mu.Lock()
		var next time.Time
		if s.received > s.consumed {
			next = s.inputProgress.Add(terminalStallTimeout)
		}
		if s.produced > s.outputACK {
			out := s.outputProgress.Add(terminalStallTimeout)
			if next.IsZero() || out.Before(next) {
				next = out
			}
		}
		s.mu.Unlock()
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		var tick <-chan time.Time
		if !next.IsZero() {
			delay := time.Until(next)
			if delay <= 0 {
				return errors.New("terminal credit stalled")
			}
			timer.Reset(delay)
			tick = timer.C
		}
		select {
		case <-s.stallWake:
		case <-tick:
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
	}
}
