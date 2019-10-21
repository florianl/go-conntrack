//+build go1.12

package conntrack

import (
	"log"
	"time"

	"github.com/florianl/go-conntrack/internal/unix"

	"github.com/mdlayher/netlink"
)

// Open a connection to the conntrack subsystem
func Open(config *Config) (*Nfct, error) {
	var nfct Nfct

	con, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: config.NetNS})
	if err != nil {
		return nil, err
	}
	nfct.Con = con

	if config.Logger == nil {
		nfct.logger = log.New(new(devNull), "", 0)
	} else {
		nfct.logger = config.Logger
	}
	if config.ReadTimeout > 0 {
		nfct.setReadTimeout = func() error {
			deadline := time.Now().Add(config.ReadTimeout)
			return nfct.Con.SetReadDeadline(deadline)
		}
	} else {
		nfct.setReadTimeout = func() error { return nil }
	}

	if config.WriteTimeout > 0 {
		nfct.setWriteTimeout = func() error {
			deadline := time.Now().Add(config.WriteTimeout)
			return nfct.Con.SetWriteDeadline(deadline)
		}
	} else {
		nfct.setWriteTimeout = func() error { return nil }
	}

	return &nfct, nil
}
