// Copyright 2023-now by lifenjoiner. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

package dhcpdns

import (
	"net"
)

// `SO_REUSEADDR` doesn't really work for this, if `DHCP Client` service occupies the port!
// https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
// On Windows, the 1st bind receives the reply data.
func ReuseListenPacket(network, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

func BindToDevice(pc net.PacketConn, device string) error {
	return nil
}
