// Copyright 2023-now by lifenjoiner. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

// The CLI.
package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/lifenjoiner/dhcpdns"
)

func detect(d *dhcpdns.Detector) int {
	log.Printf("Targeting: %v", d.RemoteIPPort)
	_ = d.Detect()

	n, ip, DNS, err := d.Status()

	log.Printf("Constancy: %v", n)
	if err != nil {
		log.Printf("Error: %v", err)
		if ip != "" {
			if n > 9 {
				log.Print("Seems can't get DHCP DNS")
				return 0
			} else {
				log.Print("Maybe DHCP temporarily failed, keep the last results")
			}
		}
	}
	log.Printf("Active local IP: %v", ip)

	for _, dnsi := range DNS {
		log.Printf("DHCP DNS: %v", dnsi.String())
	}
	return len(DNS)
}

// `Serve` acts like a daemon.

func main() {
	var n, k int

	flag.IntVar(&n, "n", -1, "Detecting rounds")
	flag.IntVar(&k, "k", 9, "Keep rounds for the same active IP")
	flag.Parse()

	d4 := &dhcpdns.Detector{RemoteIPPort: "8.8.8.8:80"}
	d6 := &dhcpdns.Detector{RemoteIPPort: "[2001:4860:4860::8888]:80"}

	got4 := 0
	got6 := 0
	for ; n != 0; n-- {
		if n%k == 0 {
			d4.SetNewRound()
			d6.SetNewRound()
		}

		if detect(d4) > 0 {
			got4++
		}
		if detect(d6) > 0 {
			got6++
		}

		if n == 1 {
			break
		}

		time.Sleep(10 * time.Second)
	}
	log.Printf("v4 got: %d", got4)
	log.Printf("v6 got: %d", got6)
	if got4+got6 == 0 {
		os.Exit(1)
	}
}
