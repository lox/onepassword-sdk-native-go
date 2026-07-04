//go:build !windows && (!cgo || (!darwin && !linux))

package internal

import (
	"fmt"
	"runtime"
)

func GetSharedLibCore(accountName string) (*CoreWrapper, error) {
	switch runtime.GOOS {
	case "darwin", "linux":
		return nil, fmt.Errorf("You've probably hit this during cross-compilation: The desktop app integration feature requires CGO (CGO_ENABLED=1 and a working C toolchain - see README.md for how to build this)")
	default:
		return nil, fmt.Errorf("the desktop app integration feature is not supported on %s", runtime.GOOS)
	}
}
