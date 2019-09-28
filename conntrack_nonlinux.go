//+build !linux

package conntrack

import (
	"context"
	"errors"
)

// Supported conntrack subsystems for Linux systems
const (
	// Conntrack table
	Ct Table = 0
	// Conntrack expect table
	CtExpected Table = 1
)

// ErrNotLinux is returned when using this package on a non linux OS
var ErrNotLinux = errors.New("package requires the netfilter subsystem of the linux kernel")

// Open returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func Open(_ *Config) (*Nfct, error) { return nil, ErrNotLinux }

// Close returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) Close() error { return ErrNotLinux }

// Dump returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) Dump(_ Table, _ Family) ([]Con, error) { return nil, ErrNotLinux }

// Flush returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) Flush(_ Table, _ Family) error { return ErrNotLinux }

// Create returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) Create(_ Table, _ Family, _ []ConnAttr) error { return ErrNotLinux }

// Query returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) Query(_ Table, _ Family, _ FilterAttr) ([]Con, error) { return nil, ErrNotLinux }

// Register returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) Register(_ context.Context, _ Table, _ NetlinkGroup, _ func(c Con) int) error {
	return ErrNotLinux
}

// RegisterFiltered returns an error, as this packages highly depends on the netfilter subsystem of the linux kernel
func (nfct *Nfct) RegisterFiltered(_ context.Context, _ Table, _ NetlinkGroup, _ []ConnAttr, _ func(c Con) int) error {
	return ErrNotLinux
}

// ParseAttributes extracts all the attributes from the given data
func ParseAttributes(_ []byte) (Con, error) { return Con{}, ErrNotLinux }

// Update an existing conntrack entry
func (nfct *Nfct) Update(t Table, f Family, attributes []ConnAttr) error { return ErrNotLinux }

// Delete elements from the conntrack subsystem with certain attributes
func (nfct *Nfct) Delete(t Table, f Family, filters []ConnAttr) error { return ErrNotLinux }

// Get returns matching conntrack entries with certain attributes
func (nfct *Nfct) Get(_ Table, _ Family, _ []ConnAttr) ([]Con, error) {
	return nil, ErrNotLinux
}
