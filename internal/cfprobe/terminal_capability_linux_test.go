//go:build linux

package cfprobe

import (
	"context"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTerminalCapabilityLinuxUnavailableAndResources(t *testing.T) {
	before, _ := os.ReadDir("/proc/self/fd")
	for _, failure := range []error{unix.ENOSYS, unix.EPERM} {
		for _, operation := range []string{"open", "signal", "poll", "dup"} {
			opts := defaultTerminalCapabilityOps()
			switch operation {
			case "open":
				opts.openPID = func(int, int) (int, error) { return -1, failure }
			case "signal":
				opts.signal = func(int, unix.Signal, *unix.Siginfo, int) error { return failure }
			case "poll":
				opts.poll = func([]unix.PollFd, int) (int, error) { return 0, failure }
			case "dup":
				opts.dup = func(uintptr, int, int) (int, error) { return -1, failure }
			}
			if err := checkTerminalCapability(context.Background(), opts); !errors.Is(err, errTerminalUnavailable) {
				t.Fatalf("capability accepted unavailable %s: %v", operation, err)
			}
		}
	}
	if err := terminalCapability(t.Context()); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadDir("/proc/self/fd")
	if len(after) > len(before)+1 {
		t.Fatalf("preflight leaked descriptors: %d -> %d", len(before), len(after))
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := terminalCapability(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled preflight: %v", err)
	}
}

func TestTerminalCapabilityLinuxInvalidHome(t *testing.T) {
	t.Setenv("HOME", "/nonexistent/cfsm-terminal-fixture")
	if err := terminalCapability(t.Context()); !errors.Is(err, errTerminalUnavailable) {
		t.Fatalf("invalid HOME accepted: %v", err)
	}
}

func TestTerminalCapabilityLinuxDoesNotRequireStop(t *testing.T) {
	opts := defaultTerminalCapabilityOps()
	opts.signal = func(fd int, sig unix.Signal, info *unix.Siginfo, flags int) error {
		if sig == unix.SIGSTOP {
			return unix.EPERM
		}
		return unix.PidfdSendSignal(fd, sig, info, flags)
	}
	if err := checkTerminalCapability(t.Context(), opts); err != nil {
		t.Fatalf("optional STOP permission must not strand/disable the bounded probe: %v", err)
	}
}
