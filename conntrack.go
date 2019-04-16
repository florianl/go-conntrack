//+build linux

package conntrack

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// Supported conntrack subsystems
const (
	// Conntrack table
	Ct CtTable = unix.NFNL_SUBSYS_CTNETLINK

	// Conntrack expect table
	CtExpected CtTable = unix.NFNL_SUBSYS_CTNETLINK_EXP
)

const (
	ipctnlMsgCtNew            = iota
	ipctnlMsgCtGet            = iota
	ipctnlMsgCtDelete         = iota
	ipctnlMsgCtGetCtrZero     = iota
	ipctnlMsgCtGetStatsCPU    = iota
	ipctnlMsgCtGetStats       = iota
	ipctnlMsgCtGetDying       = iota
	ipctnlMsgCtGetUnconfirmed = iota
)

const (
	ipctnlMsgExpNew         = iota
	ipctnlMsgExpGet         = iota
	ipctnlMsgExpDelete      = iota
	ipctnlMsgExpGetStatsCPU = iota
)

// Open a connection to the conntrack subsystem
func Open() (*Nfct, error) {
	var nfct Nfct

	con, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	nfct.Con = con

	return &nfct, nil
}

// Close the connection to the conntrack subsystem
func (nfct *Nfct) Close() error {
	return nfct.Con.Close()
}

// Flush a conntrack subsystem
func (nfct *Nfct) Flush(t CtTable, f CtFamily) error {
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, 0)
	req := netlink.Message{
		Header: netlink.Header{
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	}

	if t == Ct {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgCtDelete)
	} else if t == CtExpected {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgExpDelete)
	} else {
		return ErrUnknownCtTable
	}

	return nfct.execute(req)
}

// DumpDying returns connections marked as dying
func (nfct *Nfct) DumpDying(f CtFamily) ([]Conn, error) {
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, 0)
	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((Ct << 8) | ipctnlMsgCtGetDying),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: data,
	}
	return nfct.query(req)
}

// DumpUnconfirmed returns connections marked as unconfirmed
func (nfct *Nfct) DumpUnconfirmed(f CtFamily) ([]Conn, error) {
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, 0)
	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((Ct << 8) | ipctnlMsgCtGetUnconfirmed),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: data,
	}
	return nfct.query(req)
}

// Dump a conntrack subsystem
func (nfct *Nfct) Dump(t CtTable, f CtFamily) ([]Conn, error) {
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, 0)
	req := netlink.Message{
		Header: netlink.Header{
			Flags: netlink.Request | netlink.Dump,
		},
		Data: data,
	}

	if t == Ct {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgCtGet)
	} else if t == CtExpected {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgExpGet)
	} else {
		return nil, ErrUnknownCtTable
	}

	return nfct.query(req)
}

// DumpCPUStats gets statistics about the conntrack subsystem
func (nfct *Nfct) DumpCPUStats(t CtTable) ([]Conn, error) {
	data := putExtraHeader(unix.AF_UNSPEC, unix.NFNETLINK_V0, 0)
	req := netlink.Message{
		Header: netlink.Header{
			Flags: netlink.Request | netlink.Dump,
		},
		Data: data,
	}
	if t == Ct {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgCtGetStatsCPU)
	} else if t == CtExpected {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgExpGetStatsCPU)
	} else {
		return nil, ErrUnknownCtTable
	}
	return nfct.query(req)
}

// Counters returns the global counters of the subsystem
func (nfct *Nfct) Counters(t CtTable) ([]Conn, error) {
	data := putExtraHeader(unix.AF_UNSPEC, unix.NFNETLINK_V0, 0)
	req := netlink.Message{
		Header: netlink.Header{
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	}
	if t == Ct {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgCtGetStats)
	} else {
		return nil, ErrUnknownCtTable
	}
	return nfct.query(req)
}

// Create a new entry in the conntrack subsystem with certain attributes
func (nfct *Nfct) Create(t CtTable, f CtFamily, attributes []ConnAttr) error {
	if t != Ct {
		return ErrUnknownCtTable
	}

	query, err := nestAttributes(attributes)
	if err != nil {
		return err
	}
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, unix.NFNL_SUBSYS_CTNETLINK)
	data = append(data, query...)

	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((t << 8) | ipctnlMsgCtNew),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Excl,
		},
		Data: data,
	}
	return nfct.execute(req)
}

// Update an existing conntrack entry
func (nfct *Nfct) Update(t CtTable, f CtFamily, attributes []ConnAttr) error {
	if t != Ct {
		return ErrUnknownCtTable
	}

	query, err := nestAttributes(attributes)
	if err != nil {
		return err
	}
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, unix.NFNL_SUBSYS_CTNETLINK)
	data = append(data, query...)

	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((t << 8) | ipctnlMsgCtNew),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	}
	return nfct.execute(req)
}

// Delete elements from the conntrack subsystem with certain attributes
func (nfct *Nfct) Delete(t CtTable, f CtFamily, filters []ConnAttr) error {
	query, err := nestAttributes(filters)
	if err != nil {
		return err
	}
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, unix.NFNL_SUBSYS_CTNETLINK)
	data = append(data, query...)

	req := netlink.Message{
		Header: netlink.Header{
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	}

	if t == Ct {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgCtDelete)
	} else if t == CtExpected {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgExpDelete)
	} else {
		return ErrUnknownCtTable
	}

	return nfct.execute(req)
}

// Query conntrack subsystem with certain attributes
func (nfct *Nfct) Query(t CtTable, f CtFamily, filter FilterAttr) ([]Conn, error) {
	query, err := nestFilter(filter)
	if err != nil {
		return nil, err
	}
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, unix.NFNL_SUBSYS_CTNETLINK)
	data = append(data, query...)

	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((t << 8) | ipctnlMsgCtGet),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: data,
	}

	if t == Ct {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgCtGet)
	} else if t == CtExpected {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgExpGet)
	} else {
		return nil, ErrUnknownCtTable
	}
	return nfct.query(req)
}

// Get returns matching conntrack entries with certain attributes
func (nfct *Nfct) Get(t CtTable, f CtFamily, attributes []ConnAttr) ([]Conn, error) {
	if t != Ct {
		return nil, ErrUnknownCtTable
	}

	query, err := nestAttributes(attributes)
	if err != nil {
		return nil, err
	}
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, unix.NFNL_SUBSYS_CTNETLINK)
	data = append(data, query...)

	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((t << 8) | ipctnlMsgCtGet),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	}
	return nfct.query(req)
}

// ParseAttributes extracts all the attributes from the given data
func ParseAttributes(data []byte) (Conn, error) {
	// At least 2 bytes are needed for the header check
	if len(data) < 2 {
		return nil, ErrDataLength
	}
	return extractAttributes(data)
}

// HookFunc is a function, that receives events from a Netlinkgroup.
// Return something different than 0, to stop receiving messages.
type HookFunc func(c Conn) int

// Register your function to receive events from a Netlinkgroup.
// If your function returns something different than 0, it will stop.
func (nfct *Nfct) Register(ctx context.Context, t CtTable, group NetlinkGroup, fn HookFunc) (<-chan error, error) {
	return nfct.register(ctx, t, group, []ConnAttr{}, fn)
}

// RegisterFiltered registers your function to receive events from a Netlinkgroup and applies a filter.
// If your function returns something different than 0, it will stop.
// ConnAttr of the same ConnAttrType will be linked by an OR operation.
// Otherwise, ConnAttr of different ConnAttrType will be connected by an AND operation for the filter.
func (nfct *Nfct) RegisterFiltered(ctx context.Context, t CtTable, group NetlinkGroup, filter []ConnAttr, fn HookFunc) (<-chan error, error) {
	return nfct.register(ctx, t, group, filter, fn)
}

func (nfct *Nfct) register(ctx context.Context, t CtTable, groups NetlinkGroup, filter []ConnAttr, fn func(c Conn) int) (<-chan error, error) {
	if err := nfct.manageGroups(t, uint32(groups), true); err != nil {
		return nil, err
	}
	if err := nfct.attachFilter(t, filter); err != nil {
		return nil, err
	}
	ctrl := make(chan error)
	go func() {
		defer func() {
			if err := nfct.removeFilter(); err != nil {
				ctrl <- err
			}
			if err := nfct.manageGroups(t, uint32(groups), false); err != nil {
				ctrl <- err
			}
			close(ctrl)

		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			reply, err := nfct.Con.Receive()
			if err != nil {
				ctrl <- err
				return
			}

			for _, msg := range reply {
				c, err := parseConnectionMsg(msg, int(msg.Header.Type)&0xF)
				if err != nil {
					ctrl <- err
				}
				if ret := fn(c); ret != 0 {
					return
				}
			}

		}
	}()
	return ctrl, nil
}

func (nfct *Nfct) manageGroups(t CtTable, groups uint32, join bool) error {
	var manage func(group uint32) error

	if join == true {
		manage = nfct.Con.JoinGroup
	} else {
		manage = nfct.Con.LeaveGroup
	}

	switch t {
	case Ct:
		for _, v := range []NetlinkGroup{NetlinkCtNew, NetlinkCtUpdate, NetlinkCtDestroy} {
			if groups&uint32(v) == uint32(v) {
				if err := manage(groups & uint32(v)); err != nil {
					return err
				}
			}
		}
	case CtExpected:
		for _, v := range []NetlinkGroup{NetlinkCtExpectedNew, NetlinkCtExpectedUpdate, NetlinkCtExpectedDestroy} {
			if groups&uint32(v) == uint32(v) {
				if err := manage(groups & uint32(v)); err != nil {
					return err
				}
			}
		}
	default:
		return ErrUnknownCtTable
	}
	return nil
}

// ErrMsg as defined in nlmsgerr
type ErrMsg struct {
	Code  int
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

func unmarschalErrMsg(b []byte) (ErrMsg, error) {
	var msg ErrMsg

	msg.Code = int(nlenc.Uint32(b[0:4]))
	msg.Len = nlenc.Uint32(b[4:8])
	msg.Type = nlenc.Uint16(b[8:10])
	msg.Flags = nlenc.Uint16(b[10:12])
	msg.Seq = nlenc.Uint32(b[12:16])
	msg.Pid = nlenc.Uint32(b[16:20])

	return msg, nil
}

func (nfct *Nfct) execute(req netlink.Message) error {
	reply, e := nfct.Con.Execute(req)
	if e != nil {
		return e
	}
	if e := netlink.Validate(req, reply); e != nil {
		return e
	}
	for _, msg := range reply {
		errMsg, err := unmarschalErrMsg(msg.Data)
		if err != nil {
			return err
		}
		if errMsg.Code != 0 {
			return fmt.Errorf("%#v", errMsg)
		}
	}
	return nil
}

func (nfct *Nfct) query(req netlink.Message) ([]Conn, error) {
	verify, err := nfct.Con.Send(req)
	if err != nil {
		return nil, err
	}

	if err := netlink.Validate(req, []netlink.Message{verify}); err != nil {
		return nil, err
	}

	reply, err := nfct.Con.Receive()
	if err != nil {
		return nil, err
	}

	var conn []Conn
	for _, msg := range reply {
		c, err := parseConnectionMsg(msg, int(req.Header.Type)&0xF)
		if err != nil {
			return nil, err
		}
		if len(c) == 0 {
			break
		}
		conn = append(conn, c)
	}
	return conn, nil
}

// /include/uapi/linux/netfilter/nfnetlink.h:struct nfgenmsg{} res_id is Big Endian
func putExtraHeader(familiy, version uint8, resid uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, resid)
	return append([]byte{familiy, version}, buf...)
}

type extractFunc func([]byte) (Conn, error)

func parseConnectionMsg(msg netlink.Message, reqType int) (Conn, error) {
	if msg.Header.Type&netlink.Error == netlink.Error {
		errMsg, err := unmarschalErrMsg(msg.Data)
		if err != nil {
			return nil, err
		}
		if errMsg.Code == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("%#v", errMsg)
	}

	fnMap := map[int]extractFunc{
		ipctnlMsgCtNew:         extractAttributes,
		ipctnlMsgCtGet:         extractAttributes,
		ipctnlMsgCtDelete:      extractAttributes,
		ipctnlMsgCtGetStats:    extractStats,
		ipctnlMsgCtGetStatsCPU: extractStatsCPU,
	}

	if fn, ok := fnMap[reqType]; ok {
		return fn(msg.Data)
	}

	return nil, fmt.Errorf("Unknown message type: 0x%02x", reqType)
}
