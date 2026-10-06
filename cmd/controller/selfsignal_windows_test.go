//go:build windows

package main

import "errors"

const canTerminateSelf = false

func terminateSelf() error {
	return errors.New("a process cannot send itself SIGTERM on Windows")
}
