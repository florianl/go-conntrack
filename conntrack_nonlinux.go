//+build !linux

package conntrack

import (
	"context"
	"errors"
)

// Supported conntrack subsystems for Linux systems
const (
	// Conntrack table
	Ct CtTable = 0
	// Conntrack expect table
	CtExpected CtTable = 0
)

// ErrNotLinux is returned when using this package on a non linux OS
var ErrNotLinux = errors.New("package requires the netfilter subsystem of the linux kernel")

// Open returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func Open() (*Nfct, error) { return nil, ErrNotLinux }

// Close returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) Close() error { return ErrNotLinux }

// Dump returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) Dump(_ CtTable, _ CtFamily) ([]Conn, error) { return nil, ErrNotLinux }

// Flush returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) Flush(_ CtTable, _ CtFamily) error { return ErrNotLinux }

// Create returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) Create(_ CtTable, _ CtFamily, _ []ConnAttr) error { return ErrNotLinux }

// Query returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) Query(_ CtTable, _ CtFamily, _ FilterAttr) ([]Conn, error) { return nil, ErrNotLinux }

// Register returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) Register(_ context.Context, _ CtTable, _ NetlinkGroup, _ func(c Conn) int) (<-chan error, error) {
	return nil, ErrNotLinux
}

// RegisterFiltered returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) RegisterFiltered(_ context.Context, _ CtTable, _ NetlinkGroup, _ []ConnAttr, _ func(c Conn) int) (<-chan error, error) {
	return nil, ErrNotLinux
}

// ParseAttributes extracts all the attributes from the given data
func ParseAttributes(data []byte) (Conn, error) {
	// At least 2 bytes are needed for the header check
	if len(data) < 2 {
		return nil, ErrDataLength
	}
	return extractAttributes(data)
}
