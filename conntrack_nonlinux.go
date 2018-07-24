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
func Open() (*Nfct, error)                                                   { return nil, ErrNotLinux }
func (nfct *Nfct) Close() error                                              { return ErrNotLinux }
func (nfct *Nfct) Dump(_ CtTable, _ CtFamily) ([]Conn, error)                { return nil, ErrNotLinux }
func (nfct *Nfct) Flush(_ CtTable, _ CtFamily) error                         { return ErrNotLinux }
func (nfct *Nfct) Create(_ CtTable, _ CtFamily, _ []ConnAttr) error          { return ErrNotLinux }
func (nfct *Nfct) Query(_ CtTable, _ CtFamily, _ FilterAttr) ([]Conn, error) { return nil, ErrNotLinux }
func (nfct *Nfct) Register(_ context.Context, _ CtTable, _ NetlinkGroup, _ func(c Conn) int) (<-chan error, error) {
	return nil, ErrNotLinux
}
func (nfct *Nfct) RegisterFiltered(_ context.Context, _ CtTable, _ NetlinkGroup, _ []ConnAttr, _ func(c Conn) int) (<-chan error, error) {
	return nil, ErrNotLinux
}
