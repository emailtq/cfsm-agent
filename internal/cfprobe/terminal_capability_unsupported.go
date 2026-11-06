//go:build !linux

package cfprobe

import "context"

func terminalCapability(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errTerminalUnsupported
}
