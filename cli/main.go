// Copyright 2023-now by lifenjoiner. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

// The CLI.
package main

import (
	"log"
	"net"
	"os"
	"time"

	"github.com/lifenjoiner/dhcpdns"
)

func showResult(dns []net.IP, err error) {
	if err != nil {
		log.Printf("error: %v", err)
		return
	}

	for _, dnsi := range dns {
		log.Printf("DHCP DNS: %v", dnsi.String())
	}
}

func main() {
	var addr string

	for {
		addr = "[2001:4860:4860::8888]:80"
		log.Printf("Targeting: %v", addr)
		showResult(dhcpdns.Detect6(addr))

		addr = "8.8.8.8:80"
		log.Printf("Targeting: %v", addr)
		showResult(dhcpdns.Detect4(addr))

		if len(os.Args) > 1 {
			break
		}

		time.Sleep(30 * time.Second)
	}
}
