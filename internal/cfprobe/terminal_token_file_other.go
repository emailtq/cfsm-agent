//go:build !linux

package cfprobe

import (
	"errors"
	"os"
)

func openTerminalTokenFile(path string) (*os.File, error) {
	return nil, errors.New("terminal token installation is supported only on Linux")
}
