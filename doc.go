/*
Package conntrack provides an API to interact with the conntrack subsystem of the netfilter family from the linux kernel.

Example:

	package main
	import (
		"fmt"
		"net"
		ct "github.com/florianl/go-conntrack"
	)
	func main() {
		// Opens the socket for the communication with the subsystem
		nfct, err := ct.Open()
		if err != nil {
			fmt.Println("Could not open socket:", err)
			return
		}
		defer nfct.Close()

		// Get all IPv4 sessions
		s, _ := nfct.Dump(ct.Ct, ct.CtIPv4)
		for _, x := range a {
			srcIP := net.IP(x[ct.AttrOrigIPv4Src])
			dstIP := net.IP(x[ct.AttrOrigIPv4Dst])
			// Print source and destination for each IPv4 session
			fmt.Println("src:", srcIP, "\tdst:",dstIP)
		}
	}

*/
package conntrack
