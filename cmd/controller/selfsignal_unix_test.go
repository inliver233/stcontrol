//go:build !windows

package main

import (
	"os"
	"syscall"
)

const canTerminateSelf = true

func terminateSelf() error {
	return syscall.Kill(os.Getpid(), syscall.SIGTERM)
}
