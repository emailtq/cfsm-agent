//go:build !linux && !windows

package cfprobe

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

func sshFileID(f *os.File, info os.FileInfo) string {
	s := info.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d", s.Dev, s.Ino)
}
func verifySSHLogOwner(info os.FileInfo) error                        { return nil }
func (c *sshEventCollector) collectJournal(cfg Config, now time.Time) {}
