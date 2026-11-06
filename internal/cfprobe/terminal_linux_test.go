//go:build linux

package cfprobe

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func linuxSessionRead(t *testing.T, p *linuxTerminalProcess, marker string) string {
	t.Helper()
	if err := p.pty.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	b := make([]byte, 4096)
	for out.Len() < 65536 {
		n, err := p.Read(b)
		out.Write(b[:n])
		if strings.Contains(out.String(), marker) {
			return out.String()
		}
		if err != nil {
			t.Fatalf("PTY missing %q: %q (%v)", marker, out.String(), err)
		}
	}
	t.Fatal("PTY response exceeded test limit")
	return ""
}

func linuxSessionCommand(t *testing.T, p *linuxTerminalProcess, command, marker string) string {
	t.Helper()
	if _, err := p.Write([]byte(command + "\n")); err != nil {
		t.Fatal(err)
	}
	return linuxSessionRead(t, p, marker)
}

func linuxSessionStart(t *testing.T, c, r uint16) *linuxTerminalProcess {
	t.Helper()
	p, err := newTerminalProcess(c, r)
	if err != nil {
		t.Fatal(err)
	}
	lp := p.(*linuxTerminalProcess)
	go func() { _ = lp.Wait() }()
	t.Cleanup(func() {
		if err := lp.Close(); err != nil {
			t.Error(err)
		}
		select {
		case <-lp.waitDone:
		case <-time.After(6 * time.Second):
			t.Error("shell Wait leaked")
		}
	})
	linuxSessionCommand(t, lp, "stty -echo; printf '\\n%s\\n' READY_"+"MARK", "\r\nREADY_MARK\r\n")
	return lp
}

func TestTerminalLinuxTwoPTYDirectoryResizeInterruptAndCleanup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("TERMINAL_TOKEN", "must-not-inherit")
	t.Setenv("API_SECRET", "must-not-inherit")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "must-not-inherit")
	t.Setenv("NODE_OPTIONS", "must-not-inherit")
	fdsBefore, _ := os.ReadDir("/proc/self/fd")
	a, b := linuxSessionStart(t, 80, 24), linuxSessionStart(t, 100, 30)
	linuxSessionCommand(t, a, "cd /tmp; printf '\\nA_PWD=%s\\n' \"$PWD\"", "\r\nA_PWD=/tmp\r\n")
	linuxSessionCommand(t, b, "printf '\\nB_PWD=%s\\n' \"$PWD\"", "\r\nB_PWD="+home+"\r\n")
	env := linuxSessionCommand(t, b, "env; printf '\\n%s\\n' ENV_DONE", "\r\nENV_DONE\r\n")
	if strings.Contains(env, "must-not-inherit") || strings.Contains(env, "TERMINAL_TOKEN=") || !strings.Contains(env, "TERM=xterm-256color") {
		t.Fatalf("unsafe shell environment: %s", env)
	}
	if err := a.Resize(120, 40); err != nil {
		t.Fatal(err)
	}
	linuxSessionCommand(t, a, "stty size; printf '\\n%s\\n' SIZE_DONE", "\r\nSIZE_DONE\r\n")
	out := linuxSessionCommand(t, a, "stty size; printf '\\n%s\\n' SIZE_DONE2", "\r\nSIZE_DONE2\r\n")
	if !strings.Contains(out, "40 120") {
		t.Fatalf("resize ineffective: %q", out)
	}
	if _, err := a.Write([]byte("sleep 30\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := a.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	linuxSessionCommand(t, a, "printf '\\n%s\\n' INTERRUPTED", "\r\nINTERRUPTED\r\n")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	linuxSessionCommand(t, b, "printf '\\n%s\\n' STILL_ALIVE", "\r\nSTILL_ALIVE\r\n")
	if _, err := a.pty.Stat(); err == nil {
		t.Fatal("closed PTY descriptor remains open")
	}
	_ = b.Close()
	<-a.waitDone
	<-b.waitDone
	fdsAfter, _ := os.ReadDir("/proc/self/fd")
	if len(fdsAfter) > len(fdsBefore)+2 {
		t.Fatalf("PTY/pidfd leak: before=%d after=%d", len(fdsBefore), len(fdsAfter))
	}
}

func TestTerminalLinuxForegroundChildForcedDeadline(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	p := linuxSessionStart(t, 80, 24)
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	// Ignore graceful signals in an ordinary foreground group, not a detached setsid job.
	if _, err := p.Write([]byte(fmt.Sprintf("sh -c 'trap \"\" HUP TERM; echo $$ > %s; exec sleep 30'\n", pidFile))); err != nil {
		t.Fatal(err)
	}
	var pid int
	sessionEventually(t, func() bool {
		b, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		_, err = fmt.Sscan(string(b), &pid)
		return err == nil
	})
	childFD, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(childFD)
	start := time.Now()
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 6*time.Second {
		t.Fatal("force deadline exceeded")
	}
	var poll = [1]unix.PollFd{{Fd: int32(childFD), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll[:], 1000); err != nil || n != 1 {
		t.Fatalf("ordinary foreground child survived: %v", err)
	}
	select {
	case <-p.waitDone:
	case <-time.After(time.Second):
		t.Fatal("shell Wait remains blocked")
	}
}

func TestTerminalLinuxCloseInterruptsBlockedReadAndExitStatus(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	p := linuxSessionStart(t, 80, 24)
	_ = p.pty.SetReadDeadline(time.Time{})
	result := make(chan error, 1)
	go func() {
		b := make([]byte, 1024)
		for {
			_, err := p.Read(b)
			if err != nil {
				result <- err
				return
			}
		}
	}()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("closed PTY did not interrupt Read")
	}
	q, err := newTerminalProcess(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if _, err = q.Write([]byte("exit 7\n")); err != nil {
		t.Fatal(err)
	}
	err = q.Wait()
	var exit interface{ ExitCode() int }
	if !errors.As(err, &exit) || exit.ExitCode() != 7 {
		t.Fatalf("exit status lost: %v", err)
	}
}

func TestTerminalLinuxValidatesHomeAndResizeBeforeSpawn(t *testing.T) {
	for _, size := range [][2]uint16{{0, 24}, {80, 0}, {501, 24}, {80, 501}, {65535, 24}} {
		if p, err := newTerminalProcess(size[0], size[1]); err == nil {
			p.Close()
			p.Wait()
			t.Fatal("invalid initial dimensions accepted")
		}
	}
	t.Setenv("HOME", filepath.Join(t.TempDir(), "missing"))
	if p, err := newTerminalProcess(80, 24); err == nil {
		p.Close()
		p.Wait()
		t.Fatal("missing HOME accepted")
	}
	t.Setenv("HOME", t.TempDir())
	p := linuxSessionStart(t, 80, 24)
	if p.Resize(65535, 24) == nil {
		t.Fatal("unsafe resize accepted")
	}
	if _, err := p.Read(nil); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestTerminalLinuxTokenFIFOIsRejectedAndOpenerDoesNotBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTerminalTokenFile(path); err == nil {
		t.Fatal("real FIFO accepted as token file")
	}
	result := make(chan error, 1)
	go func() {
		file, err := openTerminalTokenFile(path)
		if err == nil {
			info, statErr := file.Stat()
			_ = file.Close()
			if statErr != nil {
				err = statErr
			} else if info.Mode()&os.ModeNamedPipe == 0 {
				err = errors.New("FIFO opener metadata mismatch")
			}
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		// Release a regressed blocking open without leaving a blocked test goroutine.
		fd, _ := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		select {
		case <-result:
		case <-time.After(time.Second):
		}
		t.Fatal("token opener blocked on real FIFO without a writer")
	}
}

func TestTerminalLinuxShellExitWithOrdinaryChildRetainingSlave(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var process *linuxTerminalProcess
	m := newTerminalManager(1, func(cols, rows uint16) (terminalProcess, error) {
		p, err := newTerminalProcess(cols, rows)
		if err == nil {
			process = p.(*linuxTerminalProcess)
		}
		return p, err
	})
	t.Cleanup(func() {
		m.CloseAll("test_end")
		if process != nil {
			_ = process.Close()
		}
	})
	peer := newSessionTestPeer()
	sessionOpen(t, m, "retained-slave", peer)
	pidFile := filepath.Join(t.TempDir(), "holder.pid")
	// An ordinary job may have a different group, but retains the Shell's session and slave.
	peer.send(wsOpcodeBinary, []byte(fmt.Sprintf("stty -echo; sh -c 'trap \"\" HUP TERM; echo $$ > %s; exec sleep 30' &\n", pidFile)))
	var pid int
	sessionEventually(t, func() bool {
		b, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		_, err = fmt.Sscan(string(b), &pid)
		return err == nil
	})
	stat, err := readTerminalProcStat(pid)
	if err != nil || stat.session != process.cmd.Process.Pid || stat.group < 1 {
		t.Fatalf("fixture escaped ordinary Shell session: %+v err=%v", stat, err)
	}
	childFD, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.PidfdSendSignal(childFD, unix.SIGKILL, nil, 0); _ = unix.Close(childFD) }()
	slave, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/1", pid))
	if err != nil || !strings.HasPrefix(slave, "/dev/pts/") {
		t.Fatalf("child did not retain PTY slave: %q err=%v", slave, err)
	}
	peer.send(wsOpcodeBinary, []byte("printf '\\n%s\\n' EXIT_TAIL; exit 7\n"))
	select {
	case <-process.waitDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Shell Wait remained live")
	}
	poll := []unix.PollFd{{Fd: int32(childFD), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 0); err != nil || n != 0 {
		t.Fatalf("retained-slave fixture exited with Shell: n=%d err=%v", n, err)
	}
	var output bytes.Buffer
	for {
		frame := sessionFrame(t, peer)
		if frame.op == wsOpcodeBinary {
			output.Write(frame.data)
			continue
		}
		control, err := parseTerminalControl(frame.data, "agent")
		if err != nil {
			t.Fatal(err)
		}
		if control.Type == "ack" {
			continue
		}
		if control.Type != "exit" || control.ExitCode != 7 {
			t.Fatalf("wrong Shell exit control: %s", frame.data)
		}
		break
	}
	if !strings.Contains(output.String(), "\r\nEXIT_TAIL\r\n") {
		t.Fatalf("Shell tail dropped: %q", output.String())
	}
	select {
	case <-peer.closed:
	case <-time.After(time.Second):
		t.Fatal("session peer stayed live after Shell exit")
	}
	if m.Count() != 0 {
		t.Fatal("exited Shell retained its slot")
	}
	if n, err := unix.Poll(poll, 6500); err != nil || n != 1 {
		t.Fatalf("ordinary retained-slave child survived cleanup: n=%d err=%v", n, err)
	}
	if err := process.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := process.pty.Stat(); err == nil {
		t.Fatal("retained master descriptor leaked")
	}
	_ = unix.Close(childFD)
	childFD = -1
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) > len(before)+2 {
		t.Fatalf("retained-slave descriptor leak: before=%d after=%d err=%v", len(before), len(after), err)
	}
}
