package conntrack_test

import (
	"fmt"

	ct "github.com/florianl/go-conntrack"
)

func ExampleNfct_DumpCPUStats() {
	nfct, err := ct.Open(&ct.Config{})
	if err != nil {
		fmt.Println("could not create nfct:", err)
		return
	}
	defer nfct.Close()
	stats, err := nfct.DumpCPUStats(ct.Conntrack)
	if err != nil {
		fmt.Println("could not dump CPU stats:", err)
		return
	}

	fmt.Printf("ID\tIgnore\tInvalid\tError\n")
	for _, stat := range stats {
		fmt.Printf("%2d\t%4d\t%4d\t%4d\n", stat.ID, *stat.Ignore, *stat.Invalid, *stat.Error)
	}
}
