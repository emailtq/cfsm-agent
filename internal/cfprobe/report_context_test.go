package cfprobe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStoppedAgentDoesNotSendPOSTRequests(t *testing.T) {
	requests := make(chan struct{}, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- struct{}{}
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := &Agent{ctx: ctx, log: newLogger(false)}
	cfg := Config{WorkerURL: server.URL}
	if _, err := a.postReportBody(cfg, []byte(`{}`), 0, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("report error=%v, want canceled", err)
	}
	if err := a.sendCorrectionConfirm(cfg, "0", "0"); !errors.Is(err, context.Canceled) {
		t.Fatalf("correction error=%v, want canceled", err)
	}
	if len(requests) != 0 {
		t.Fatal("stopped agent still sent a POST request")
	}
}

func TestReportContextTerminalStopJoinsOwnedWorker(t *testing.T) {
	for _, reason := range []string{"normal_stop", "discovery_failure", "update"} {
		t.Run(reason, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			a := &Agent{terminalCancel: cancel, terminalDone: make(chan struct{})}
			cleaning, release := make(chan struct{}), make(chan struct{})
			go func() { <-ctx.Done(); close(cleaning); <-release; close(a.terminalDone) }()
			stopped := make(chan struct{})
			go func() { a.stopTerminal(); close(stopped) }()
			<-cleaning
			select {
			case <-stopped:
				t.Fatal("stop returned before owned worker cleanup")
			case <-time.After(10 * time.Millisecond):
			}
			close(release)
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("stop failed to join")
			}
			a.stopTerminal()
		})
	}
}
