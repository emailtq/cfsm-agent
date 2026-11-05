//go:build linux

package cfprobe

import (
	"os"
	"syscall"
)

func openTerminalTokenFile(path string) (*os.File, error) {
	// No symlink following or blocking if a regular file is swapped for a FIFO.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
