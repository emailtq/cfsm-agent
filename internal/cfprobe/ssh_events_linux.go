//go:build linux

package cfprobe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func sshFileID(f *os.File, info os.FileInfo) string {
	stat := info.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
}
func verifySSHLogOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
		return errors.New("untrusted SSH log owner")
	}
	return nil
}

type boundedJournalOutput struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func (b *boundedJournalOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		b.truncated = true
		return 0, errors.New("journal batch limit")
	}
	return b.Buffer.Write(p)
}

func (c *sshEventCollector) collectJournal(cfg Config, now time.Time) {
	c.mu.Lock()
	next, err := c.prepare(cfg)
	c.mu.Unlock()
	if err != nil {
		return
	}
	baseline := !next.Enabled || next.Source != "journal"
	args := []string{"--no-pager", "--output=json", "--all", "--identifier=sshd", "--identifier=sshd-session", "--identifier=sshd-auth"}
	if baseline {
		args = append(args, "--lines=1")
	} else if next.JournalCursor != "" {
		args = append(args, "--no-tail", "--after-cursor="+next.JournalCursor)
	} else {
		args = append(args, "--no-tail", fmt.Sprintf("--since=@%d.%06d", next.JournalSince/1000000, next.JournalSince%1000000))
	}
	parent := c.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	cmd.WaitDelay = time.Second
	out := &boundedJournalOutput{limit: 128 * 1024}
	stderr := &boundedJournalOutput{limit: 8192}
	cmd.Stdout = out
	cmd.Stderr = stderr
	err = cmd.Run()
	if err != nil && !out.truncated || strings.Contains(stderr.String(), "not seeing messages") || strings.Contains(stderr.String(), "Permission denied") || strings.Contains(stderr.String(), "No journal files") {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.code = "unavailable"
		if errors.Is(err, os.ErrPermission) || strings.Contains(stderr.String(), "not seeing messages") || strings.Contains(stderr.String(), "Permission denied") {
			c.code = "permission_denied"
		}
		if strings.Contains(stderr.String(), "seek to cursor") || strings.Contains(stderr.String(), "cursor is invalid") {
			next.Gap = true
			next.JournalCursor = ""
			next.Enabled = false
			c.code = "rotation_gap"
			if c.save(next) != nil {
				c.code = "state_error"
			}
		}
		return
	}
	records := out.Bytes()
	if n := bytes.LastIndexByte(records, '\n'); n >= 0 {
		records = records[:n+1]
	} else {
		records = nil
	}
	if err = c.collectJournalRecords(cfg, records, baseline, now); err != nil {
		c.mu.Lock()
		c.code = "state_error"
		c.mu.Unlock()
	}
}
