package conntrack

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"unsafe"

	"github.com/florianl/go-conntrack/internal/unix"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
)

// Supported conntrack subsystems
const (
	// Conntrack table
	Conntrack Table = unix.NFNL_SUBSYS_CTNETLINK

	// Conntrack expect table
	Expected Table = unix.NFNL_SUBSYS_CTNETLINK_EXP
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

// for detailes see https://github.com/tensorflow/tensorflow/blob/master/tensorflow/go/tensor.go#L488-L505
var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

// devNull satisfies io.Writer, in case *log.Logger is not provided
type devNull struct{}

func (devNull) Write(p []byte) (int, error) {
	return 0, nil
}

// Close the connection to the conntrack subsystem
func (nfct *Nfct) Close() error {
	return nfct.Con.Close()
}

// Flush a conntrack subsystem
func (nfct *Nfct) Flush(t Table, f Family) error {
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, 0)
	req := netlink.Message{
		Header: netlink.Header{
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	}

	if t == Conntrack {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgCtDelete)
	} else if t == Expected {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgExpDelete)
	} else {
		return ErrUnknownCtTable
	}

	return nfct.execute(req)
}

// Dump a conntrack subsystem
func (nfct *Nfct) Dump(t Table, f Family) ([]Con, error) {
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, 0)
	req := netlink.Message{
		Header: netlink.Header{
			Flags: netlink.Request | netlink.Dump,
		},
		Data: data,
	}

	if t == Conntrack {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgCtGet)
	} else if t == Expected {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgExpGet)
	} else {
		return nil, ErrUnknownCtTable
	}

	return nfct.query(req)
}

// Create a new entry in the conntrack subsystem with certain attributes
func (nfct *Nfct) Create(t Table, f Family, attributes Con) error {
	if t != Conntrack {
		return ErrUnknownCtTable
	}

	query, err := nestAttributes(nfct.logger, &attributes)
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

// Query conntrack subsystem with certain attributes
func (nfct *Nfct) Query(t Table, f Family, filter FilterAttr) ([]Con, error) {
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

	if t == Conntrack {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgCtGet)
	} else if t == Expected {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgExpGet)
	} else {
		return nil, ErrUnknownCtTable
	}
	return nfct.query(req)
}

// Get returns matching conntrack entries with certain attributes
func (nfct *Nfct) Get(t Table, f Family, match Con) ([]Con, error) {
	if t != Conntrack {
		return nil, ErrUnknownCtTable
	}
	query, err := nestAttributes(nfct.logger, &match)
	if err != nil {
		return []Con{}, err
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

// Update an existing conntrack entry
func (nfct *Nfct) Update(t Table, f Family, attributes Con) error {
	if t != Conntrack {
		return ErrUnknownCtTable
	}

	query, err := nestAttributes(nfct.logger, &attributes)
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
func (nfct *Nfct) Delete(t Table, f Family, filters Con) error {
	query, err := nestAttributes(nfct.logger, &filters)
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

	if t == Conntrack {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgCtDelete)
	} else if t == Expected {
		req.Header.Type = netlink.HeaderType((t << 8) | ipctnlMsgExpDelete)
	} else {
		return ErrUnknownCtTable
	}

	return nfct.execute(req)
}

// ParseAttributes extracts all the attributes from the given data
func ParseAttributes(logger *log.Logger, data []byte) (Con, error) {
	// At least 2 bytes are needed for the header check
	if len(data) < 2 {
		return Con{}, ErrDataLength
	}
	return extractAttributes(logger, data)
}

// HookFunc is a function, that receives events from a Netlinkgroup.
// Return something different than 0, to stop receiving messages.
type HookFunc func(c Con) int

// Register your function to receive events from a Netlinkgroup.
// If your function returns something different than 0, it will stop.
func (nfct *Nfct) Register(ctx context.Context, t Table, group NetlinkGroup, fn HookFunc) error {
	return nfct.register(ctx, t, group, []ConnAttr{}, fn)
}

// RegisterFiltered registers your function to receive events from a Netlinkgroup and applies a filter.
// If your function returns something different than 0, it will stop.
// ConnAttr of the same ConnAttrType will be linked by an OR operation.
// Otherwise, ConnAttr of different ConnAttrType will be connected by an AND operation for the filter.
func (nfct *Nfct) RegisterFiltered(ctx context.Context, t Table, group NetlinkGroup, filter []ConnAttr, fn HookFunc) error {
	return nfct.register(ctx, t, group, filter, fn)
}

func (nfct *Nfct) register(ctx context.Context, t Table, groups NetlinkGroup, filter []ConnAttr, fn func(c Con) int) error {
	if err := nfct.manageGroups(t, uint32(groups), true); err != nil {
		return err
	}
	if err := nfct.attachFilter(t, filter); err != nil {
		return err
	}
	go func() {
		defer func() {
			if err := nfct.removeFilter(); err != nil {
				nfct.logger.Printf("could not remove filter: %v", err)
			}
			if err := nfct.manageGroups(t, uint32(groups), false); err != nil {
				nfct.logger.Printf("could not unsubscribe grom group: %v", err)
			}

		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if err := nfct.setReadTimeout(); err != nil {
				nfct.logger.Printf("could not set read timeout: %v", err)
			}
			reply, err := nfct.Con.Receive()
			if err != nil {
				nfct.logger.Printf("receiving error: %v", err)
				return
			}

			for _, msg := range reply {
				c, err := parseConnectionMsg(nfct.logger, msg, int(msg.Header.Type)&0xF)
				if err != nil {
					nfct.logger.Printf("could not parse received message: %v", err)
				}
				if ret := fn(c); ret != 0 {
					return
				}
			}

		}
	}()
	return nil
}

func (nfct *Nfct) manageGroups(t Table, groups uint32, join bool) error {
	var manage func(group uint32) error

	if groups == 0 {
		nfct.logger.Println("will not join group 0")
		return nil
	}

	manage = nfct.Con.LeaveGroup
	if join {
		manage = nfct.Con.JoinGroup
	}

	switch t {
	case Conntrack:
		mapping := map[uint32]uint32{
			uint32(NetlinkCtNew):     1, // NFNLGRP_CONNTRACK_NEW
			uint32(NetlinkCtUpdate):  2, // NFNLGRP_CONNTRACK_UPDATE
			uint32(NetlinkCtDestroy): 3, // NFNLGRP_CONNTRACK_DESTROY
		}
		for _, v := range []NetlinkGroup{NetlinkCtNew, NetlinkCtUpdate, NetlinkCtDestroy} {
			if groups&uint32(v) == uint32(v) {
				if err := manage(mapping[groups&uint32(v)]); err != nil {
					return err
				}
			}
		}
	case Expected:
		mapping := map[uint32]uint32{
			uint32(NetlinkCtExpectedNew):     4, // NFNLGRP_CONNTRACK_EXP_NEW
			uint32(NetlinkCtExpectedUpdate):  5, // NFNLGRP_CONNTRACK_EXP_UPDATE
			uint32(NetlinkCtExpectedDestroy): 6, // NFNLGRP_CONNTRACK_EXP_DESTROY
		}
		for _, v := range []NetlinkGroup{NetlinkCtExpectedNew, NetlinkCtExpectedUpdate, NetlinkCtExpectedDestroy} {
			if groups&uint32(v) == uint32(v) {
				if err := manage(mapping[groups&uint32(v)]); err != nil {
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
	if err := nfct.setWriteTimeout(); err != nil {
		nfct.logger.Printf("could not set write timeout: %v", err)
	}
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

func (nfct *Nfct) query(req netlink.Message) ([]Con, error) {
	if err := nfct.setWriteTimeout(); err != nil {
		nfct.logger.Printf("could not set write timeout: %v", err)
	}
	verify, err := nfct.Con.Send(req)
	if err != nil {
		return nil, err
	}

	if err := netlink.Validate(req, []netlink.Message{verify}); err != nil {
		return nil, err
	}

	if err := nfct.setReadTimeout(); err != nil {
		nfct.logger.Printf("could not set read timeout: %v", err)
	}
	reply, err := nfct.Con.Receive()
	if err != nil {
		return nil, err
	}

	var conn []Con
	for _, msg := range reply {
		c, err := parseConnectionMsg(nfct.logger, msg, int(req.Header.Type)&0xF)
		if err != nil {
			return nil, err
		}
		// check if c is an empty struct
		if (Con{}) == c {
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

type extractFunc func(*log.Logger, []byte) (Con, error)

func parseConnectionMsg(logger *log.Logger, msg netlink.Message, reqType int) (Con, error) {

	if msg.Header.Type == netlink.Error {
		errMsg, err := unmarschalErrMsg(msg.Data)
		if err != nil {
			return Con{}, err
		}
		if errMsg.Code == 0 {
			return Con{}, nil
		}
		return Con{}, fmt.Errorf("%#v", errMsg)
	}

	fnMap := map[int]extractFunc{
		ipctnlMsgCtNew:    extractAttributes,
		ipctnlMsgCtGet:    extractAttributes,
		ipctnlMsgCtDelete: extractAttributes,
	}

	if fn, ok := fnMap[reqType]; ok {
		return fn(logger, msg.Data)
	}

	return Con{}, fmt.Errorf("unknown message type: 0x%02x", reqType)
}
