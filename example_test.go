package conntrack_test

import (
	"fmt"
	"net"

	ct "github.com/florianl/go-conntrack"
)

func ExampleNfct_Dump() {
	nfct, err := ct.Open()
	if err != nil {
		fmt.Println("Could not create nfct:", err)
		return
	}
	defer nfct.Close()
	sessions, err := nfct.Dump(ct.Ct, ct.CtIPv4)
	if err != nil {
		fmt.Println("Could not dump sessions:", err)
		return
	}

	for _, x := range sessions {
		osrcIP := net.IP(x[ct.AttrOrigIPv4Src])
		odstIP := net.IP(x[ct.AttrOrigIPv4Dst])
		fmt.Printf("src: %s\tdst: %s \n", osrcIP, odstIP)
	}
}

func ExampleNfct_Flush() {
	nfct, err := ct.Open()
	if err != nil {
		fmt.Println("Could not create nfct:", err)
		return
	}
	defer nfct.Close()
	err = nfct.Flush(ct.Ct, ct.CtIPv4)
	if err != nil {
		fmt.Println("Could not flush conntrack subsystem:", err)
		return
	}
}

func ExampleNfct_Create() {
	nfct, err := ct.Open()
	if err != nil {
		fmt.Println("Could not create nfct:", err)
		return
	}
	defer nfct.Close()
	ipA := net.ParseIP("1.1.1.1")
	ipB := net.ParseIP("8.8.8.8")
	err = nfct.Create(ct.Ct, ct.CtIPv4, []ct.ConnAttr{
		{Type: ct.AttrOrigIPv4Src, Data: []byte{ipA[12], ipA[13], ipA[14], ipA[15]}},
		{Type: ct.AttrOrigIPv4Dst, Data: []byte{ipB[12], ipB[13], ipB[14], ipB[15]}},
		{Type: ct.AttrReplIPv4Src, Data: []byte{ipB[12], ipB[13], ipB[14], ipB[15]}},
		{Type: ct.AttrReplIPv4Dst, Data: []byte{ipA[12], ipA[13], ipA[14], ipA[15]}},
		{Type: ct.AttrOrigL4Proto, Data: []byte{0x02}},
		{Type: ct.AttrReplL4Proto, Data: []byte{0x02}},
		{Type: ct.AttrStatus, Data: []byte{0x0, 0x0, 0x0, 0x08}},
		{Type: ct.AttrTimeout, Data: []byte{0x0, 0x0, 0x0, 0x42}}})
	if err != nil {
		fmt.Println("Could not create new session:", err)
		return
	}
}
