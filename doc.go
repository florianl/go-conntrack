/*
Package conntrack provides an API to interact with the conntrack subsystem of the netfilter family from the linux kernel.

Example:

	package main
	import (
		"fmt"

		ct "github.com/florianl/go-conntrack"
	)

	func main() {
		// Opens the socket for the communication with the subsystem
		nfct, err := ct.Open(&Config{})
		if err != nil {
			fmt.Println("Could not open socket:", err)
			return
		}
		defer nfct.Close()

		// Get all IPv4 sessions
		sessions, err := nfct.Dump(ct.Ct, ct.CtIPv4)
		if err != nil {
			fmt.Println("Could not dump sessions:", err)
			return
		}

		for _, x := range sessions {
			oSrcIP, _ := x.OrigSrcIP()
			oDstIP, _ := x.OrigDstIP()
			// Print source and destination for each IPv4 session
			fmt.Printf("src: %s\tdst: %s \n", oSrcIP, oDstIP)
		}
	}

*/
package conntrack
