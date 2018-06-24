package conntrack

import (
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Nfct represents a conntrack handler
type Nfct struct {
	con *netlink.Conn
}

// CtType specifies the subsystem of conntrack
type CtType byte

// Supported conntrack subsystems
const (
	Ct         CtType = unix.NFNL_SUBSYS_CTNETLINK
	CtExpected CtType = unix.NFNL_SUBSYS_CTNETLINK_EXP
	CtTimeout  CtType = unix.NFNL_SUBSYS_CTNETLINK_TIMEOUT
)

// Open a connection to the given conntrack subsystem
func Open(ctType CtType) (*Nfct, error) {
	var nfct Nfct

	con, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{Groups: uint32(ctType)})
	if err != nil {
		return nil, err
	}
	nfct.con = con

	return &nfct, nil
}

// Close the connection to the conntrack subsystem
func (nfct *Nfct) Close() error {
	return nfct.con.Close()
}
