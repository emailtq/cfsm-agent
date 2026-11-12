package cfprobe

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

var errTerminalUnavailable = errors.New("terminal capability unavailable")

type terminalControlOptions struct {
	preflight                                                                func(context.Context) error
	dial                                                                     func(context.Context, Config, string, string, bool) (terminalPeer, error)
	factory                                                                  terminalFactory
	heartbeat, readTimeout, startTimeout, retryMin, retryMax, configInterval time.Duration
}

func defaultTerminalControlOptions() terminalControlOptions {
	return terminalControlOptions{
		preflight: terminalCapability,
		dial: func(ctx context.Context, cfg Config, id, ticket string, dns bool) (terminalPeer, error) {
			return dialTerminalWebSocket(ctx, cfg, id, ticket, dns)
		},
		factory:   newTerminalProcess,
		heartbeat: 30 * time.Second, readTimeout: 75 * time.Second, startTimeout: 30 * time.Second,
		retryMin: time.Second, retryMax: 30 * time.Second, configInterval: 100 * time.Millisecond,
	}
}

func terminalLocallyEnabled(cfg Config) bool {
	_, err := terminalWebSocketURL(cfg.WorkerURL, "")
	return cfg.TerminalEnabled && validNodeToken(cfg.NodeToken) && err == nil
}

func terminalIdentityEqual(a, b Config) bool {
	return a.TerminalEnabled == b.TerminalEnabled && a.NodeToken == b.NodeToken && a.ServerID == b.ServerID && a.WorkerURL == b.WorkerURL && usePublicDNSResolver(a) == usePublicDNSResolver(b)
}

func (a *Agent) startTerminal(ctx context.Context) {
	a.terminalMu.Lock()
	defer a.terminalMu.Unlock()
	if a.terminalStopped || a.terminalDone != nil || !terminalLocallyEnabled(a.configSnapshot()) {
		return
	}
	child, cancel := context.WithCancel(ctx)
	a.terminalCancel = cancel
	a.terminalDone = make(chan struct{})
	go func() { defer close(a.terminalDone); a.terminalWorker(child) }()
}

func (a *Agent) stopTerminal() {
	a.terminalMu.Lock()
	a.terminalStopped = true
	if a.terminalCancel != nil {
		a.terminalCancel()
	}
	done := a.terminalDone
	a.terminalMu.Unlock()
	if done != nil {
		<-done
	}
}

func (a *Agent) terminalWorker(ctx context.Context) {
	a.runTerminalWorker(ctx, defaultTerminalControlOptions())
}

func (a *Agent) runTerminalWorker(ctx context.Context, opts terminalControlOptions) {
	retry := opts.retryMin
	var generation uint64
	for ctx.Err() == nil {
		cfg := a.configSnapshot()
		if !terminalLocallyEnabled(cfg) || !terminalIDRE.MatchString(cfg.ServerID) {
			if !a.waitTerminal(ctx, opts.configInterval) {
				return
			}
			continue
		}
		if opts.preflight(ctx) != nil {
			if !a.waitTerminal(ctx, opts.retryMax) {
				return
			}
			continue
		}
		generation++
		manager := newTerminalManager(terminalMaxSessions, opts.factory)
		connected := a.terminalGeneration(ctx, cfg, generation, manager, opts)
		if connected {
			retry = opts.retryMin
		}
		if !a.waitTerminal(ctx, retry) {
			return
		}
		retry = min(retry*2, opts.retryMax)
	}
}

func (a *Agent) waitTerminal(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-a.terminalChanged:
		return true
	case <-timer.C:
		return true
	}
}

type terminalAdmission struct {
	cancel     context.CancelFunc
	generation uint64
}

type terminalControlGeneration struct {
	mu         sync.Mutex
	ctx        context.Context
	cfg        Config
	number     uint64
	admissions map[string]*terminalAdmission
	wg         sync.WaitGroup
	disabled   bool
}

func (a *Agent) terminalGeneration(root context.Context, cfg Config, number uint64, manager *terminalManager, opts terminalControlOptions) bool {
	ctx, cancel := context.WithCancel(root)
	a.cfgMu.Lock()
	if !terminalIdentityEqual(cfg, a.cfg) {
		a.cfgMu.Unlock()
		cancel()
		return false
	}
	a.terminalControlCancel = cancel
	a.cfgMu.Unlock()
	g := &terminalControlGeneration{ctx: ctx, cfg: cfg, number: number, admissions: make(map[string]*terminalAdmission)}
	defer func() {
		cancel()
		g.wg.Wait()
		manager.CloseAll("control_lost")
		a.cfgMu.Lock()
		a.terminalControlCancel = nil
		a.cfgMu.Unlock()
	}()
	peer, err := opts.dial(ctx, cfg, "", "", usePublicDNSResolver(cfg))
	if err != nil || peer == nil {
		return false
	}
	stop := context.AfterFunc(ctx, func() { _ = peer.Close() })
	defer stop()
	defer peer.Close()
	if peer.WriteText([]byte(`{"type":"hello","protocol":1,"platform":"linux","capabilities":["terminal.pty.v1","terminal.disable.v1"]}`), terminalWriteTimeout) != nil {
		return false
	}
	writerDone := make(chan struct{})
	pongs := make(chan struct{}, 1)
	go func() {
		defer close(writerDone)
		ticker := time.NewTicker(opts.heartbeat)
		defer ticker.Stop()
		for {
			var text []byte
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				text = []byte(`{"type":"ping"}`)
			case <-pongs:
				text = []byte(`{"type":"pong"}`)
			}
			if peer.WriteText(text, terminalWriteTimeout) != nil {
				cancel()
				return
			}
		}
	}()
	defer func() { cancel(); <-writerDone }()
	var binding *terminalControl
	for ctx.Err() == nil {
		if peer.SetReadDeadline(time.Now().Add(opts.readTimeout)) != nil {
			break
		}
		data, op, err := peer.ReadDataMessageLimit(terminalMaxControlFrameBytes)
		if err != nil || op != wsOpcodeText {
			break
		}
		frame, err := parseTerminalControl(data, "broker-control")
		if err != nil {
			break
		}
		switch frame.Type {
		case "bound":
			if binding != nil || frame.ServerID != cfg.ServerID {
				return true
			}
			binding = &frame
		case "disable":
			if binding == nil || frame.ServerID != binding.ServerID || frame.ConnectionID != binding.ConnectionID || frame.Generation != binding.Generation || frame.CredentialVersion != binding.CredentialVersion {
				return true
			}
			if !g.disable(a, manager) {
				return true
			}
			ack, _ := json.Marshal(struct {
				Type              string `json:"type"`
				OperationID       string `json:"operationId"`
				ServerID          string `json:"serverId"`
				ConnectionID      string `json:"connectionId"`
				Generation        int64  `json:"generation"`
				CredentialVersion int64  `json:"credentialVersion"`
			}{"disabled", frame.OperationID, frame.ServerID, frame.ConnectionID, frame.Generation, frame.CredentialVersion})
			_ = peer.WriteText(ack, terminalWriteTimeout)
			return true
		case "open":
			g.admit(frame, manager, opts, a)
		case "close":
			g.mu.Lock()
			admission := g.admissions[frame.SessionID]
			if admission != nil {
				admission.cancel()
			}
			g.mu.Unlock()
		case "ping":
			select {
			case pongs <- struct{}{}:
			default:
				cancel()
				return true
			}
		case "pong":
		}
	}
	return true
}

func (g *terminalControlGeneration) disable(a *Agent, manager *terminalManager) bool {
	a.configWriteMu.Lock()
	defer a.configWriteMu.Unlock()
	a.cfgMu.Lock()
	// The cancellation check also rejects an A-B-A reinstall on this old control.
	if g.ctx.Err() != nil || !terminalIdentityEqual(g.cfg, a.cfg) || !a.cfg.TerminalEnabled {
		a.cfgMu.Unlock()
		return false
	}
	// A local reinstall can replace disk configuration before an old process observes it.
	persisted, err := readConfig(a.paths.ConfigFile)
	if err != nil || !terminalIdentityEqual(g.cfg, persisted) {
		a.cfgMu.Unlock()
		return false
	}
	next := a.cfg
	next.TerminalEnabled = false
	if writeConfig(a.paths.ConfigFile, next) != nil {
		a.cfgMu.Unlock()
		return false
	}
	a.cfg = next
	a.cfgMu.Unlock()
	g.mu.Lock()
	g.disabled = true
	for _, admission := range g.admissions {
		admission.cancel()
	}
	g.mu.Unlock()
	// No ACK until even cancelled factories and removed-session cleanup have joined.
	deadline := time.Now().Add(4 * time.Second)
	if !manager.disable(time.Until(deadline)) {
		return false
	}
	joined := make(chan struct{})
	go func() { g.wg.Wait(); close(joined) }()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-joined:
		return true
	case <-timer.C:
		return false
	}
}

func (g *terminalControlGeneration) admit(frame terminalControl, manager *terminalManager, opts terminalControlOptions, a *Agent) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.disabled || g.ctx.Err() != nil || g.admissions[frame.SessionID] != nil || len(g.admissions) >= terminalMaxSessions {
		return false
	}
	ctx, cancel := context.WithCancel(g.ctx)
	admission := &terminalAdmission{cancel: cancel, generation: g.number}
	g.admissions[frame.SessionID] = admission
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		defer func() {
			cancel()
			g.mu.Lock()
			if g.admissions[frame.SessionID] == admission {
				delete(g.admissions, frame.SessionID)
			}
			g.mu.Unlock()
		}()
		startCtx, startCancel := context.WithTimeout(ctx, opts.startTimeout)
		defer startCancel()
		peer, err := opts.dial(startCtx, g.cfg, frame.SessionID, frame.Ticket, usePublicDNSResolver(g.cfg))
		if err != nil || peer == nil {
			return
		}
		defer peer.Close()
		stop := context.AfterFunc(startCtx, func() { _ = peer.Close() })
		if peer.SetReadDeadline(time.Now().Add(opts.startTimeout)) != nil {
			stop()
			return
		}
		data, op, err := peer.ReadDataMessageLimit(terminalMaxControlFrameBytes)
		start, parseErr := parseTerminalControl(data, "broker")
		if err != nil || op != wsOpcodeText || parseErr != nil || start.Type != "start" || startCtx.Err() != nil || !terminalIdentityEqual(g.cfg, a.configSnapshot()) || opts.preflight(ctx) != nil {
			stop()
			return
		}
		// End the admission deadline before transferring the socket to its session owner.
		if !stop() {
			return
		}
		startCancel()
		if ctx.Err() != nil {
			return
		}
		if peer.SetReadDeadline(time.Time{}) != nil {
			return
		}
		owned, _ := manager.open(ctx, frame.SessionID, peer, uint16(start.Cols), uint16(start.Rows))
		if owned != nil {
			select {
			case <-ctx.Done():
				owned.stop()
				owned.joinStarted()
			case <-owned.done:
			}
		}
	}()
	return true
}
