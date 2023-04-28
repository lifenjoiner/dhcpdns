// Copyright 2023-now by lifenjoiner. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

// The package gets the DHCP/DHCPv6 DNS.
package dhcpdns

import (
	"crypto/rand"
	"errors"
	//"log"
	"net"
	"runtime"
	"time"
)

const (
	MaxDhcpv4MessageSize  = 576
	CommDhcpv6MessageSize = 1024
)

// Sample messages, https://wiki.wireshark.org/SampleCaptures.md

// Minimal DISCOVER message
// https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
// https://datatracker.ietf.org/doc/html/rfc2132#section-9
// A client can receive DHCP offers from multiple servers, but it will accept only one DHCP offer.
var discoverMsg = []byte{
	0x01,                   // message type
	0x01,                   // hardware type: Ethernet
	0x06,                   // hardware address length: Ethernet
	0x00,                   // hops
	0x18, 0x22, 0xae, 0x2d, // transaction id
	0x00, 0x00, // seconds elasped
	0x80, 0x00, // flags: BROADCAST. Unicast may not be received.
	0x00, 0x00, 0x00, 0x00, // client ip
	0x00, 0x00, 0x00, 0x00, // your ip
	0x00, 0x00, 0x00, 0x00, // server ip
	0x00, 0x00, 0x00, 0x00, // relay ip
	// client MAC: https://gitlab.com/wireshark/wireshark/-/raw/master/manuf
	0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // client hardware address padding
	// ServerHostName
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// BootFileName
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// magic cookie: DHCP
	0x63, 0x82, 0x53, 0x63,
	// Options
	0x35, 0x01, 0x01, // Discover
	0x37, 0x01, 0x06, // Parameter Request List: DNS
	0xff, // END: 247B
	// padding: min length of 300 bytes per RFC951
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
}

// Get DNS from a DHCP OFFER message.
// Doesn't verify transaction ID, just plain broadcasts.
func GetDNSFromOffer(msg []byte) (ip []net.IP, err error) {
	if msg[0] != 0x02 {
		err = errors.New("not DHCPv4 Offer")
		return
	}

	m := 240
	n := len(msg)
	for m < n {
		opt := msg[m]
		if opt == 255 {
			// END
			break
		}
		m++

		if m < n {
			i := m + 1
			m += 1 + int(msg[m])
			if m <= n {
				if opt == 6 {
					// DHCP DNS
					for i+4 <= m {
						ip = append(ip, msg[i:i+4])
						i += 4
					}
					break
				}
				continue
			}
		}

		err = errors.New("invalid Offer")
		break
	}

	if len(ip) == 0 {
		err = errors.New("no DNS found")
	}
	return
}

// Send DHCP DISCOVER message and return the DNS.
func Discover(ip string) (dns []net.IP, err error) {
	ipAddr, ifi, err := getOutboundParams(ip)
	if err != nil {
		return nil, err
	}
	//log.Printf("Receiving addr Zone: %v", ipAddr.Zone)

	// Windows (WSL2) can't choose the right IP.
	pc, err := reuseListenPacket("udp4", ip+":68")
	if err != nil {
		return nil, err
	}

	// new transaction id
	_, _ = rand.Read(discoverMsg[4:8])
	// known client ip
	copy(discoverMsg[12:12+4], ipAddr.IP.To4())
	// Ubuntu requires MAC
	copy(discoverMsg[28:28+16], ifi.HardwareAddr)

	rAddr := &net.UDPAddr{IP: net.IPv4bcast, Port: 67}
	_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = pc.WriteTo(discoverMsg, rAddr)
	if err != nil {
		// defer doesn't work on reassignment
		pc.Close()
		return nil, err
	}

	// (*nix) may have a deamon binding the local IPPort and the gateway IPPort.
	// If so and the server replies with a broadcast to the local IPPort, rather than IPv4bcast,
	// it may not be received on some OS.
	// Android needs it.
	if ipAddr.Zone != "" {
		pc.Close()
		pc, err = reuseListenPacket("udp4", ":68")
		if err != nil {
			return nil, err
		}
	}

	//log.Printf("Receiving addr: %v", pc.LocalAddr())

	buf := make([]byte, MaxDhcpv4MessageSize)
	_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf[:])
	pc.Close()
	if err != nil {
		return nil, err
	}
	//log.Printf("Received from: %v", rAddr2)

	dns, err = GetDNSFromOffer(buf[:n])

	return
}

// Required.
func getOutboundParams(ip string) (*net.IPAddr, *net.Interface, error) {
	ipAddr, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		return nil, nil, err
	}

	is6 := ipAddr.IP.To4() == nil

	ift, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, ifi := range ift {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}

		var ipUnicast net.IP
		var got bool
		for _, addr := range addrs {
			ipi := addr.(*net.IPNet).IP
			if ipi.Equal(ipAddr.IP) {
				got = true
			}
			if is6 && ipi.To4() == nil && ipi.IsLinkLocalUnicast() {
				ipUnicast = ipi
			}
			//log.Printf("%v: %v", ifi.Name, ipi)
		}

		if got {
			// https://www.kernel.org/doc/html/latest/networking/operstates.html
			if ifi.Flags&net.FlagRunning == net.FlagRunning {
				if ipUnicast != nil {
					ipAddr.IP = ipUnicast
				}
				// Bind fe80::/10 and ListenUDP on *nix needs Zone.
				if ipAddr.Zone == "" && runtime.GOOS != "windows" {
					ipAddr.Zone = ifi.Name
				}
				return ipAddr, &ifi, nil
			}
			return nil, nil, errors.New("[" + ifi.Name + "] is not running")
		}
	}

	return nil, nil, errors.New("no link-local unicast address found")
}

// Minimal INFORMATION-REQUEST message
// https://en.wikipedia.org/wiki/DHCPv6
// INFORMATION-REQUEST (11):
// https://datatracker.ietf.org/doc/html/rfc8415#section-5.1
// https://datatracker.ietf.org/doc/html/rfc8415#section-18.2.6
// https://datatracker.ietf.org/doc/html/rfc8415#section-8
var informationRequestMsg = []byte{
	0x0b,             // message type
	0x10, 0x08, 0x74, // transaction id
	// Options
	// Elapsed Time Option: https://datatracker.ietf.org/doc/html/rfc8415#section-21.9
	0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
	// Client Identifier Option: https://datatracker.ietf.org/doc/html/rfc8415#section-16.2
	0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	// option reques: DNS
	0x00, 0x06, 0x00, 0x02, 0x00, 0x17,
}

func readBigEndianUint16(b []byte) uint16 {
	return uint16(b[0])<<8&0xff00 | uint16(b[1])
}

// Get DNS from a DHCPv6 REPLY message.
// Doesn't verify transaction ID, just plain broadcasts.
// https://datatracker.ietf.org/doc/html/rfc3646
func GetDNSFromReply(msg []byte) (ip []net.IP, err error) {
	if msg[0] != 0x07 {
		err = errors.New("not DHCPv6 Reply")
		return
	}

	m := 4
	n := len(msg)
	for m+2 <= n {
		opt := readBigEndianUint16(msg[m : m+2])
		m += 2
		if m+2 < n {
			i := m + 2
			m += 2 + int(readBigEndianUint16(msg[m:m+2]))
			if m <= n {
				if opt == 23 {
					// DHCPv6 DNS
					for i+16 <= m {
						ip = append(ip, msg[i:i+16])
						i += 16
					}
					break
				}
				continue
			}
		}
		err = errors.New("invalid REPLY")
		break
	}
	if len(ip) == 0 {
		err = errors.New("no DNS found")
	}
	return
}

// Send DHCPv6 INFORMATION-REQUEST message and return the DNS.
func InformationRequest(ip string) (dns []net.IP, err error) {
	ipAddr, _, err := getOutboundParams(ip)
	if err != nil {
		return nil, err
	}

	pc, err := reuseListenPacket("udp6", "["+ipAddr.String()+"]:546")
	if err != nil {
		return nil, err
	}

	//log.Printf("Receiving addr: %v", pc.LocalAddr())

	// new transaction id
	_, _ = rand.Read(informationRequestMsg[1:4])

	rAddr := &net.UDPAddr{IP: net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02}, Port: 547}
	_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = pc.WriteTo(informationRequestMsg, rAddr)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, CommDhcpv6MessageSize)
	_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf[:])
	pc.Close()
	if err != nil {
		return nil, err
	}

	dns, err = GetDNSFromReply(buf[:n])

	return
}

func detect(raddr string, fn func(string) ([]net.IP, error)) ([]net.IP, error) {
	c, err := net.Dial("udp", raddr)
	if err != nil {
		return nil, err
	}
	_ = c.Close()

	ip, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return nil, err
	}

	//log.Printf("Active local IP: %v", ip)

	return fn(ip)
}

// Detect the IPv4 DNS from the active interface which is adopted
// to connect to the provided IpPort address.
func Detect4(raddr string) ([]net.IP, error) {
	return detect(raddr, Discover)
}

// Detect the IPv6 DNS from the active interface which is adopted
// to connect to the provided IpPort address.
func Detect6(raddr string) ([]net.IP, error) {
	return detect(raddr, InformationRequest)
}
