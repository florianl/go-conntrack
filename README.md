go-conntrack [![Build Status](https://travis-ci.org/florianl/go-conntrack.svg?branch=master)](https://travis-ci.org/florianl/go-conntrack) [![GoDoc](https://godoc.org/github.com/florianl/go-conntrack?status.svg)](https://godoc.org/github.com/florianl/go-conntrack)
============

This is `go-conntrack` and it is written in [golang](https://golang.org/). It provides a [C](https://en.wikipedia.org/wiki/C_(programming_language))-binding free API to the conntrack subsystem of the [Linux kernel](https://www.kernel.org).

Example
-------

```golang
package main
import (
    "fmt"

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
```

For documentation and more examples please take a look at [![GoDoc](https://godoc.org/github.com/florianl/go-conntrack?status.svg)](https://godoc.org/github.com/florianl/go-conntrack)