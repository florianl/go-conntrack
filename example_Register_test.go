package conntrack_test

import (
	"context"
	"fmt"
	"time"

	ct "github.com/florianl/go-conntrack"
)

func ExampleNfct_Register() {
	nfct, err := ct.Open(&ct.Config{})
	if err != nil {
		fmt.Println("could not create nfct:", err)
		return
	}
	defer nfct.Close()

	monitor := func(c ct.Con) int {
		fmt.Printf("%#v\n", c)
		return 0
	}

	if err := nfct.Register(context.Background(), ct.Expected, ct.NetlinkCtExpectedNew|ct.NetlinkCtExpectedUpdate|ct.NetlinkCtExpectedDestroy, monitor); err != nil {
		fmt.Println("could not register callback:", err)
		return
	}

	time.Sleep(10 * time.Second)

}
