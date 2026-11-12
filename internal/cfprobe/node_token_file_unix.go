//go:build !windows

package cfprobe

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func openNodeTokenFile(path string) (*os.File, error) {
	// No symlink following or blocking if a regular file is swapped for a FIFO.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func validatePrivateFileInfo(info os.FileInfo) error { return validateNodeTokenInfo(info) }

func verifyPrivateFile(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if err := validateNodeTokenInfo(info); err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot verify credential owner")
	}
	return validateUnixPrivatePermissions(info.Mode(), stat.Uid, uint32(os.Geteuid()), false)
}

func verifyPrivateParent(path string) error {
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return err
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return err
	}
	for {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() {
			return errors.New("cannot verify private credential parent")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("cannot verify parent owner")
		}
		if err := validateUnixPrivatePermissions(info.Mode(), stat.Uid, uint32(os.Geteuid()), true); err != nil {
			return err
		}
		next := filepath.Dir(parent)
		if next == parent {
			return nil
		}
		parent = next
	}
}

func protectPrivateFile(f *os.File) error {
	if err := f.Chmod(0600); err != nil {
		return err
	}
	return verifyPrivateFile(f)
}

func createPrivateTemp(dir, prefix string) (*os.File, error) {
	return os.CreateTemp(dir, prefix+"*")
}

func ensurePrivateConfigDirectory(dir string) error { return os.MkdirAll(dir, 0755) }
