//+build !linux

package conntrack

import "errors"

// ErrNotLinux is returned when using this package on a non linux OS
var ErrNotLinux = errors.New("package requires the netfilter subsystem of the linux kernel")

// Nfct represents a conntrack handler
type Nfct struct {
}

// ConnAttrType specifies the attribute of a connection
type ConnAttrType uint16

// Conn contains all the information of a connection
type Conn map[ConnAttrType][]byte

// CtFamily specifies the network family
type CtFamily uint8

// Open returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func Open() (*Nfct, error) {
	return nil, ErrNotLinux
}

// Close returns an error, as this package highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) Close() error {
	return ErrNotLinux
}

// Dump returns an error, as this package highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) Dump(f CtFamily) ([]Conn, error) {
	return nil, ErrNotLinux
}

// Flush returns an error, as this package highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) Flush(f CtFamily) error {
	return ErrNotLinux
}
