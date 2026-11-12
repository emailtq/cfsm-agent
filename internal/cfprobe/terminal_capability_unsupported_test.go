//go:build !linux

package cfprobe

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTerminalCapabilityUnsupportedNeverDials(t *testing.T) {
	if err := terminalCapability(t.Context()); !errors.Is(err, errTerminalUnsupported) {
		t.Fatalf("unsupported capability=%v", err)
	}
	var calls atomic.Int32
	opts := defaultTerminalControlOptions()
	opts.dial = func(context.Context, Config, string, string, bool) (terminalPeer, error) {
		calls.Add(1)
		return nil, errors.New("unexpected")
	}
	a := &Agent{cfg: Config{TerminalEnabled: true, NodeToken: strings.Repeat("a", 64), ServerID: "node", WorkerURL: "https://example.invalid"}, log: newLogger(false)}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	a.runTerminalWorker(ctx, opts)
	if calls.Load() != 0 {
		t.Fatal("unsupported platform advertised/connected terminal")
	}
}
