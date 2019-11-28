package conntrack_test

import (
	"fmt"

	ct "github.com/florianl/go-conntrack"
)

func ExampleNfct_Dump() {
	nfct, err := ct.Open(&ct.Config{})
	if err != nil {
		fmt.Println("could not create nfct:", err)
		return
	}
	defer nfct.Close()
	sessions, err := nfct.Dump(ct.Expected, ct.IPv4)
	if err != nil {
		fmt.Println("could not dump sessions:", err)
		return
	}

	for _, session := range sessions {
		fmt.Printf("%#v\n", session)
	}
}
