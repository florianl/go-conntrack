//+build !linux

package conntrack

import "errors"

// Open returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func Open() (*Nfct, error) {
	return nil, errors.New("conntrack requires the netfilter subsystem of the linux kernel")
}
