// Copyright 2023-now by lifenjoiner. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

// The CLI.
package main

import (
	"flag"
	"log"
	"time"

	"github.com/lifenjoiner/dhcpdns"
)

func showResult(d *dhcpdns.Detector, err error) {
	if err != nil {
		log.Printf("error: %v", err)
		return
	}

	log.Printf("Active local IP: %v", d.LastActiveIP)

	for _, dnsi := range d.DNS() {
		log.Printf("DHCP DNS: %v", dnsi.String())
	}
}

func main() {
	var (
		n   int
		err error
	)

	flag.IntVar(&n, "n", -1, "Detecting rounds")
	flag.Parse()

	d4 := &dhcpdns.Detector{RemoteIPPort: "8.8.8.8:80"}
	d6 := &dhcpdns.Detector{RemoteIPPort: "[2001:4860:4860::8888]:80"}

	for ; n != 0; n-- {
		if n%9 == 0 {
			d4.LastActiveIP = ""
			d6.LastActiveIP = ""
		}

		log.Printf("Targeting: %v", d4.RemoteIPPort)
		err = d4.Detect()
		showResult(d4, err)

		log.Printf("Targeting: %v", d6.RemoteIPPort)
		err = d6.Detect()
		showResult(d6, err)

		if n == 1 {
			break
		}

		time.Sleep(10 * time.Second)
	}
}
