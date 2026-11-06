//go:build linux

package cfprobe

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

type terminalCapabilityOps struct {
	openPID func(int, int) (int, error)
	signal  func(int, unix.Signal, *unix.Siginfo, int) error
	poll    func([]unix.PollFd, int) (int, error)
	dup     func(uintptr, int, int) (int, error)
}

func defaultTerminalCapabilityOps() terminalCapabilityOps {
	return terminalCapabilityOps{openPID: unix.PidfdOpen, signal: unix.PidfdSendSignal, poll: unix.Poll, dup: unix.FcntlInt}
}

func terminalCapability(ctx context.Context) error {
	return checkTerminalCapability(ctx, defaultTerminalCapabilityOps())
}

func checkTerminalCapability(ctx context.Context, ops terminalCapabilityOps) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	home := os.Getenv("HOME")
	current, err := user.Current()
	if err != nil {
		return errTerminalUnavailable
	}
	if home == "" {
		home = current.HomeDir
	}
	if !filepath.IsAbs(home) {
		return errTerminalUnavailable
	}
	homeFD, err := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return errTerminalUnavailable
	}
	defer unix.Close(homeFD)
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		return errTerminalUnavailable
	}
	proc, err := os.Open("/proc")
	if err != nil {
		return errTerminalUnavailable
	}
	_, err = proc.ReadDir(1)
	_ = proc.Close()
	if err != nil {
		return errTerminalUnavailable
	}
	// A bounded non-interactive child is the only target of destructive signal probes.
	child := exec.Command("/bin/sleep", "2")
	child.Env = []string{"PATH=/usr/bin:/bin"}
	if err := child.Start(); err != nil {
		return errTerminalUnavailable
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	fd, err := ops.openPID(child.Process.Pid, 0)
	if err != nil {
		return errTerminalUnavailable
	}
	defer unix.Close(fd)
	before, err := readTerminalProcStat(child.Process.Pid)
	if err != nil {
		return errTerminalUnavailable
	}
	after, err := readTerminalProcStat(child.Process.Pid)
	if err != nil || before != after {
		return errTerminalUnavailable
	}
	dup, err := ops.dup(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return errTerminalUnavailable
	}
	defer unix.Close(dup)
	if _, err := ops.poll([]unix.PollFd{{Fd: int32(dup), Events: unix.POLLIN}}, 0); err != nil {
		return errTerminalUnavailable
	}
	// Never stop the probe: it must expire naturally even when terminating signals are denied.
	for _, sig := range []unix.Signal{0, unix.SIGHUP, unix.SIGTERM, unix.SIGKILL} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := ops.signal(fd, sig, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			return errTerminalUnavailable
		}
	}
	master, slave, err := pty.Open()
	if err != nil {
		return errTerminalUnavailable
	}
	defer master.Close()
	defer slave.Close()
	raw, err := master.SyscallConn()
	if err != nil {
		return errTerminalUnavailable
	}
	var setupErr error
	err = raw.Control(func(fd uintptr) { setupErr = unix.SetNonblock(int(fd), true) })
	if err != nil || setupErr != nil {
		return errTerminalUnavailable
	}
	// Rewrap a duplicate after O_NONBLOCK so Go's poller owns cancellable I/O.
	var masterFD int
	err = raw.Control(func(fd uintptr) { masterFD, setupErr = ops.dup(fd, unix.F_DUPFD_CLOEXEC, 0) })
	if err != nil || setupErr != nil {
		return errTerminalUnavailable
	}
	probe := os.NewFile(uintptr(masterFD), "terminal-capability-pty")
	if probe == nil {
		_ = unix.Close(masterFD)
		return errTerminalUnavailable
	}
	defer probe.Close()
	if err := probe.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
		return errTerminalUnavailable
	}
	_, err = probe.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		return errTerminalUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}
