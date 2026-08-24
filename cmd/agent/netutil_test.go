package main

import (
	"net"
	"testing"
)

func TestLocalIPv4ReturnsAValidIPv4Address(t *testing.T) {
	t.Parallel()
	value := localIPv4()
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		t.Fatalf("localIPv4()=%q is not IPv4", value)
	}
}
