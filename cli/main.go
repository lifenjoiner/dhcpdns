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

func detect(d *dhcpdns.Detector) {
	log.Printf("Targeting: %v", d.RemoteIPPort)
	_ = d.Detect()

	n, ip, DNS, err := d.Status()

	log.Printf("Constancy: %v", n)
	if err != nil {
		log.Printf("Error: %v", err)
		if ip != "" {
			if n > 9 {
				log.Print("Seems can't get DHCP DNS")
				return
			} else {
				log.Print("Maybe DHCP temporarily failed, keep the last results")
			}
		}
	}
	log.Printf("Active local IP: %v", ip)

	for _, dnsi := range DNS {
		log.Printf("DHCP DNS: %v", dnsi.String())
	}
}

// `Serve` acts like a daemon.

func main() {
	var n, k int

	flag.IntVar(&n, "n", -1, "Detecting rounds")
	flag.IntVar(&k, "k", 9, "Keep rounds for the same active IP")
	flag.Parse()

	d4 := &dhcpdns.Detector{RemoteIPPort: "8.8.8.8:80"}
	d6 := &dhcpdns.Detector{RemoteIPPort: "[2001:4860:4860::8888]:80"}

	for ; n != 0; n-- {
		if n%k == 0 {
			d4.SetNewRound()
			d6.SetNewRound()
		}

		detect(d4)
		detect(d6)

		if n == 1 {
			break
		}

		time.Sleep(10 * time.Second)
	}
}
