//go:build windows

package cfprobe

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"time"
)

// Used by isolated file fixtures only; Windows SSH collection reports unsupported.
func sshFileID(f *os.File, info os.FileInfo) string {
	var s windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &s) != nil {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d", s.VolumeSerialNumber, s.FileIndexHigh, s.FileIndexLow)
}
func verifySSHLogOwner(info os.FileInfo) error                        { return nil }
func (c *sshEventCollector) collectJournal(cfg Config, now time.Time) {}
