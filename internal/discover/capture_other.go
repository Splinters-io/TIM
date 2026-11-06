//go:build !linux

package discover

import (
	"context"
	"errors"
)

// Capture is only supported on Linux.
func Capture(ctx context.Context, iface string, fn func([]byte)) error {
	return errors.New("packet capture is only supported on Linux")
}
