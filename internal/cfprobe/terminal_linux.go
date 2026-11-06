//go:build linux

package cfprobe

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

type linuxTerminalProcess struct {
	pty                 *os.File
	cmd                 *exec.Cmd
	shellFD             int
	shellStart          string
	closeOnce, waitOnce sync.Once
	waitDone            chan struct{}
	waitErr, closeErr   error
	cleanupMu           sync.Mutex
	closing, reaped     bool
	exitFDs             []int
}

func newTerminalProcess(cols, rows uint16) (terminalProcess, error) {
	if !validateTerminalSize(int(cols), int(rows)) {
		return nil, errors.New("invalid terminal dimensions")
	}
	home := os.Getenv("HOME")
	current, err := user.Current()
	if err != nil {
		return nil, errors.New("cannot resolve terminal user")
	}
	if home == "" {
		home = current.HomeDir
	}
	info, err := os.Stat(home)
	if err != nil || !filepath.IsAbs(home) || !info.IsDir() {
		return nil, errors.New("terminal home directory is unavailable")
	}
	shell := "/bin/sh"
	args := []string{"-i"}
	for _, path := range []string{"/bin/bash", "/usr/bin/bash"} {
		if resolved, err := exec.LookPath(path); err == nil {
			shell = resolved
			args = []string{"--noprofile", "--norc", "-i"}
			break
		}
	}
	cmd := exec.Command(shell, args...)
	cmd.Dir = home
	// Do not copy service/reporting credentials, PATH hooks or shell startup variables.
	cmd.Env = []string{"HOME=" + home, "USER=" + current.Username, "LOGNAME=" + current.Username, "TERM=xterm-256color", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/local/bin:/usr/bin:/bin"}
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		return nil, errors.New("cannot start terminal PTY")
	}
	fail := func() { _ = f.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() }
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		fail()
		return nil, errors.New("terminal requires Linux pidfd support for safe process cleanup")
	}
	stat, err := readTerminalProcStat(cmd.Process.Pid)
	if err != nil {
		_ = unix.Close(fd)
		fail()
		return nil, errors.New("cannot establish terminal process identity")
	}
	raw, err := f.SyscallConn()
	var nonblockErr error
	if err == nil {
		err = raw.Control(func(fd uintptr) { nonblockErr = unix.SetNonblock(int(fd), true) })
	}
	if err != nil || nonblockErr != nil {
		_ = unix.Close(fd)
		fail()
		return nil, errors.New("cannot configure terminal PTY")
	}
	return &linuxTerminalProcess{pty: f, cmd: cmd, shellFD: fd, shellStart: stat.start, waitDone: make(chan struct{})}, nil
}

func (p *linuxTerminalProcess) Read(b []byte) (int, error) {
	n, err := p.pty.Read(b)
	if errors.Is(err, unix.EIO) {
		err = io.EOF
	}
	return n, err
}
func (p *linuxTerminalProcess) Write(b []byte) (int, error) { return p.pty.Write(b) }

func (p *linuxTerminalProcess) Resize(cols, rows uint16) error {
	if !validateTerminalSize(int(cols), int(rows)) {
		return errors.New("invalid terminal dimensions")
	}
	raw, err := p.pty.SyscallConn()
	if err != nil {
		return err
	}
	var ioctlErr error
	err = raw.Control(func(fd uintptr) {
		ioctlErr = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Col: cols, Row: rows})
	})
	if err != nil {
		return err
	}
	return ioctlErr
}

func (p *linuxTerminalProcess) Wait() error {
	p.waitOnce.Do(func() {
		p.cleanupMu.Lock()
		pollFD := -1
		var observeErr error
		if !p.closing {
			pollFD, observeErr = unix.FcntlInt(uintptr(p.shellFD), unix.F_DUPFD_CLOEXEC, 0)
		}
		p.cleanupMu.Unlock()
		if pollFD >= 0 {
			defer unix.Close(pollFD)
			poll := []unix.PollFd{{Fd: int32(pollFD), Events: unix.POLLIN}}
			for {
				_, observeErr = unix.Poll(poll, -1)
				if !errors.Is(observeErr, unix.EINTR) {
					break
				}
			}
		}
		if observeErr != nil {
			_ = p.Close()
		}
		p.cleanupMu.Lock()
		if !p.closing {
			// Pin ordinary holders while the exited Shell is still unreaped and cannot be reused.
			fds := p.knownProcessFDs(time.Now().Add(5 * time.Second))
			p.exitFDs = fds[1:]
		}
		p.waitErr = p.cmd.Wait()
		p.reaped = true
		p.cleanupMu.Unlock()
		close(p.waitDone)
	})
	return p.waitErr
}

type terminalProcStat struct {
	group, session int
	start          string
}

func readTerminalProcStat(pid int) (terminalProcStat, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return terminalProcStat{}, err
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return terminalProcStat{}, errors.New("invalid process identity")
	}
	fields := strings.Fields(string(b[i+1:]))
	if len(fields) < 20 {
		return terminalProcStat{}, errors.New("invalid process identity")
	}
	group, err := strconv.Atoi(fields[2])
	if err != nil {
		return terminalProcStat{}, err
	}
	session, err := strconv.Atoi(fields[3])
	if err != nil {
		return terminalProcStat{}, err
	}
	return terminalProcStat{group: group, session: session, start: fields[19]}, nil
}

func (p *linuxTerminalProcess) shellIdentityMatches() bool {
	stat, err := readTerminalProcStat(p.cmd.Process.Pid)
	return err == nil && stat.start == p.shellStart && stat.session == p.cmd.Process.Pid
}

// cleanupMu excludes the sole reap operation while validating even an exited Shell's identity.
func (p *linuxTerminalProcess) knownProcessFDs(deadline time.Time) []int {
	fds := []int{p.shellFD}
	if !p.shellIdentityMatches() {
		return fds
	}
	dir, err := os.Open("/proc")
	if err != nil {
		return fds
	}
	defer dir.Close()
	for {
		if time.Now().After(deadline) {
			break
		}
		entries, err := dir.ReadDir(64)
		for _, entry := range entries {
			pid, err := strconv.Atoi(entry.Name())
			if err != nil || pid == p.cmd.Process.Pid {
				continue
			}
			before, err := readTerminalProcStat(pid)
			// The tty can lose its foreground group when the leader exits; the unreaped SID cannot be reused.
			if err != nil || before.session != p.cmd.Process.Pid {
				continue
			}
			fd, err := unix.PidfdOpen(pid, 0)
			if err != nil {
				continue
			}
			after, err := readTerminalProcStat(pid)
			if err != nil || after != before || !p.shellIdentityMatches() {
				_ = unix.Close(fd)
				continue
			}
			fds = append(fds, fd)
		}
		if err != nil {
			break
		}
	}
	return fds
}

func (p *linuxTerminalProcess) Close() error {
	p.closeOnce.Do(func() {
		// Pin verified group members before closing the PTY; never signal a numeric stale PID.
		deadline := time.Now().Add(5 * time.Second)
		p.cleanupMu.Lock()
		p.closing = true
		fds := append([]int{p.shellFD}, p.exitFDs...)
		p.exitFDs = nil
		if !p.reaped {
			fds = p.knownProcessFDs(deadline)
		}
		p.cleanupMu.Unlock()
		defer func() {
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
		}()
		for _, sig := range []unix.Signal{unix.SIGHUP, unix.SIGTERM} {
			for _, fd := range fds {
				if err := unix.PidfdSendSignal(fd, sig, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
					p.closeErr = errors.New("terminal process cleanup failed")
				}
			}
		}
		_ = p.pty.Close()
		pending := make([]unix.PollFd, len(fds))
		for i, fd := range fds {
			pending[i] = unix.PollFd{Fd: int32(fd), Events: unix.POLLIN}
		}
		for len(pending) > 0 {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			_, err := unix.Poll(pending, int((remaining+time.Millisecond-1)/time.Millisecond))
			if err != nil && !errors.Is(err, unix.EINTR) {
				break
			}
			live := pending[:0]
			for _, fd := range pending {
				if fd.Revents == 0 {
					live = append(live, fd)
				}
			}
			pending = live
		}
		for _, fd := range pending {
			if err := unix.PidfdSendSignal(int(fd.Fd), unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
				p.closeErr = errors.New("terminal process cleanup failed")
			}
		}
		// shortcut: deliberately detached setsid jobs need stronger OS containment, outside V1.
	})
	return p.closeErr
}
