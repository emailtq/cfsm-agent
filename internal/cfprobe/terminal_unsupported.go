//go:build !linux

package cfprobe

func newTerminalProcess(cols, rows uint16) (terminalProcess, error) {
	return nil, errTerminalUnsupported
}
