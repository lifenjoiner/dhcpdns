//go:build !windows
// +build !windows

// Copyright 2023-now by lifenjoiner. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

package dhcpdns

import (
	"context"
	"errors"
	"net"
	"syscall"
)

func ReuseListenPacket(network, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
		},
	}
	return lc.ListenPacket(context.Background(), network, address)
}

func BindToDevice(pc net.PacketConn, device string) error {
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		return errors.New("not UDPConn")
	}

	rc, err := uc.SyscallConn()
	if err != nil {
		return err
	}

	return rc.Control(func(fd uintptr) {
		_ = syscall.BindToDevice(int(fd), device)
	})
}
