package conntrack

import (
	"errors"
	"net"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// Nfct represents a conntrack handler
type Nfct struct {
	// Con is the pure representation of a netlink socket
	Con *netlink.Conn
}

// Conn contains all the information of a connection
type Conn map[ConnAttrType][]byte

// CtTable specifies the subsystem of conntrack
type CtTable int

// NetlinkGroup represents a Netlink multicast group
type NetlinkGroup uint32

// Supported Netlink groups
const (
	NetlinkCtNew             NetlinkGroup = 1 << iota
	NetlinkCtUpdate          NetlinkGroup = 1 << iota
	NetlinkCtDestroy         NetlinkGroup = 1 << iota
	NetlinkCtExpectedNew     NetlinkGroup = 1 << iota
	NetlinkCtExpectedUpdate  NetlinkGroup = 1 << iota
	NetlinkCtExpectedDestroy NetlinkGroup = 1 << iota
)

// CtFamily specifies the network family
type CtFamily uint8

// Supported family types
const (
	CtIPv6 CtFamily = unix.AF_INET6
	CtIPv4 CtFamily = unix.AF_INET
)

// FilterAttr represents a very basic filter
type FilterAttr struct {
	Mark, MarkMask []byte
}

// ConnAttr represents the type and value of a attribute of a connection
type ConnAttr struct {
	Type ConnAttrType
	Data []byte
	// Mask is required for specific attributes, if you want to filter for them
	Mask []byte
	// Negates this attribute for filtering
	Negate bool
}

// ConnAttrType specifies the attribute of a connection
type ConnAttrType uint16

// Attributes of a connection
// based on libnetfilter_conntrack.h
const (
	AttrOrigIPv4Src             ConnAttrType = iota /* u32 bits, requires a mask if applied as filter */
	AttrOrigIPv4Dst             ConnAttrType = iota /* u32 bits, requires a mask if applied as filter */
	AttrReplIPv4Src             ConnAttrType = iota /* u32 bits, requires a mask if applied as filter */
	AttrReplIPv4Dst             ConnAttrType = iota /* u32 bits, requires a mask if applied as filter */
	AttrOrigIPv6Src             ConnAttrType = iota /* u128 bits */
	AttrOrigIPv6Dst             ConnAttrType = iota /* u128 bits */
	AttrReplIPv6Src             ConnAttrType = iota /* u128 bits */
	AttrReplIPv6Dst             ConnAttrType = iota /* u128 bits */
	AttrOrigPortSrc             ConnAttrType = iota /* u16 bits */
	AttrOrigPortDst             ConnAttrType = iota /* u16 bits */
	AttrReplPortSrc             ConnAttrType = iota /* u16 bits */
	AttrReplPortDst             ConnAttrType = iota /* u16 bits */
	AttrIcmpType                ConnAttrType = iota /* u8 bits */
	AttrIcmpCode                ConnAttrType = iota /* u8 bits */
	AttrIcmpID                  ConnAttrType = iota /* u16 bits */
	AttrOrigL3Proto             ConnAttrType = iota /* u8 bits */
	AttrReplL3Proto             ConnAttrType = iota /* u8 bits */
	AttrOrigL4Proto             ConnAttrType = iota /* u8 bits */
	AttrReplL4Proto             ConnAttrType = iota /* u8 bits */
	AttrTCPState                ConnAttrType = iota /* u8 bits */
	AttrSNatIPv4                ConnAttrType = iota /* u32 bits */
	AttrDNatIPv4                ConnAttrType = iota /* u32 bits */
	AttrSNatPort                ConnAttrType = iota /* u16 bits */
	AttrDNatPort                ConnAttrType = iota /* u16 bits */
	AttrTimeout                 ConnAttrType = iota /* u32 bits */
	AttrMark                    ConnAttrType = iota /* u32 bits, requires a mask if applied as filter */
	AttrOrigCounterPackets      ConnAttrType = iota /* u64 bits */
	AttrReplCounterPackets      ConnAttrType = iota /* u64 bits */
	AttrOrigCounterBytes        ConnAttrType = iota /* u64 bits */
	AttrReplCounterBytes        ConnAttrType = iota /* u64 bits */
	AttrUse                     ConnAttrType = iota /* u32 bits */
	AttrID                      ConnAttrType = iota /* u32 bits */
	AttrStatus                  ConnAttrType = iota /* u32 bits  */
	AttrTCPFlagsOrig            ConnAttrType = iota /* u8 bits */
	AttrTCPFlagsRepl            ConnAttrType = iota /* u8 bits */
	AttrTCPMaskOrig             ConnAttrType = iota /* u8 bits */
	AttrTCPMaskRepl             ConnAttrType = iota /* u8 bits */
	AttrMasterIPv4Src           ConnAttrType = iota /* u32 bits */
	AttrMasterIPv4Dst           ConnAttrType = iota /* u32 bits */
	AttrMasterIPv6Src           ConnAttrType = iota /* u128 bits */
	AttrMasterIPv6Dst           ConnAttrType = iota /* u128 bits */
	AttrMasterPortSrc           ConnAttrType = iota /* u16 bits */
	AttrMasterPortDst           ConnAttrType = iota /* u16 bits */
	AttrMasterL3Proto           ConnAttrType = iota /* u8 bits */
	AttrMasterL4Proto           ConnAttrType = iota /* u8 bits */
	AttrSecmark                 ConnAttrType = iota /* u32 bits */
	AttrOrigNatSeqCorrectionPos ConnAttrType = iota /* u32 bits */
	AttrOrigNatSeqOffsetBefore  ConnAttrType = iota /* u32 bits */
	AttrOrigNatSeqOffsetAfter   ConnAttrType = iota /* u32 bits */
	AttrReplNatSeqCorrectionPos ConnAttrType = iota /* u32 bits */
	AttrReplNatSeqOffsetBefore  ConnAttrType = iota /* u32 bits */
	AttrReplNatSeqOffsetAfter   ConnAttrType = iota /* u32 bits */
	AttrSctpState               ConnAttrType = iota /* u8 bits */
	AttrSctpVtagOrig            ConnAttrType = iota /* u32 bits */
	AttrSctpVtagRepl            ConnAttrType = iota /* u32 bits */
	AttrHelperName              ConnAttrType = iota /* string (30 bytes max) */
	AttrDccpState               ConnAttrType = iota /* u8 bits */
	AttrDccpRole                ConnAttrType = iota /* u8 bits */
	AttrDccpHandshakeSeq        ConnAttrType = iota /* u64 bits */
	AttrTCPWScaleOrig           ConnAttrType = iota /* u8 bits */
	AttrTCPWScaleRepl           ConnAttrType = iota /* u8 bits */
	AttrZone                    ConnAttrType = iota /* u16 bits */
	AttrSecCtx                  ConnAttrType = iota /* string */
	AttrTimestampStart          ConnAttrType = iota /* u64 bits linux >= 2.6.38 */
	AttrTimestampStop           ConnAttrType = iota /* u64 bits linux >= 2.6.38 */
	AttrHelperInfo              ConnAttrType = iota /* variable length */
	AttrConnlabels              ConnAttrType = iota /* variable length */
	AttrConnlabelsMask          ConnAttrType = iota /* variable length */
	AttrOrigzone                ConnAttrType = iota /* u16 bits */
	AttrReplzone                ConnAttrType = iota /* u16 bits */
	AttrSNatIPv6                ConnAttrType = iota /* u128 bits */
	AttrDNatIPv6                ConnAttrType = iota /* u128 bits */

	attrMax ConnAttrType = iota /* This is for internal use only	*/
)

// Various errors which may occur when procressing a connection
var (
	ErrConnNoSrcIP = errors.New("Conn has no source IP")
	ErrConnNoDstIP = errors.New("Conn has no destination IP")
	ErrConnNoAttr  = errors.New("Conn has not this attribute")
)

// Various errors which may occur when processing attributes
var (
	ErrAttrLength         = errors.New("Incorrect length of attribute")
	ErrAttrNotImplemented = errors.New("Attribute not implemented")
	ErrAttrNotExist       = errors.New("Type of attribute does not exist")
)

// OrigSrcIP returns the net.IP representation of the source IP
func (c Conn) OrigSrcIP() (net.IP, error) {
	if data, ok := c[AttrOrigIPv6Src]; ok {
		ip := net.IP(data)
		return ip, nil
	} else if data, ok := c[AttrOrigIPv4Src]; ok {
		ip := net.IPv4(data[0], data[1], data[2], data[3])
		return ip, nil
	}
	return nil, ErrConnNoSrcIP
}

// OrigDstIP returns the net.IP representation of the destination IP
func (c Conn) OrigDstIP() (net.IP, error) {
	if data, ok := c[AttrOrigIPv6Dst]; ok {
		ip := net.IP(data)
		return ip, nil
	} else if data, ok := c[AttrOrigIPv4Dst]; ok {
		ip := net.IPv4(data[0], data[1], data[2], data[3])
		return ip, nil
	}
	return nil, ErrConnNoSrcIP
}

// Uint8 returns the uint8 representation of the given attribute's data.
func (c Conn) Uint8(attr ConnAttrType) (uint8, error) {
	if data, ok := c[attr]; ok {
		if len(data) != 1 {
			return 0, ErrAttrLength
		}
		return nlenc.Uint8(data), nil
	}
	return 0, ErrConnNoAttr
}

// Uint16 returns the uint16 representation of the given attribute's data.
func (c Conn) Uint16(attr ConnAttrType) (uint16, error) {
	if data, ok := c[attr]; ok {
		if len(data) != 2 {
			return 0, ErrAttrLength
		}
		return nlenc.Uint16(data), nil
	}
	return 0, ErrConnNoAttr
}

// Uint32 returns the uint32 representation of the given attribute's data.
func (c Conn) Uint32(attr ConnAttrType) (uint32, error) {
	if data, ok := c[attr]; ok {
		if len(data) != 4 {
			return 0, ErrAttrLength
		}
		return nlenc.Uint32(data), nil
	}
	return 0, ErrConnNoAttr
}

// Uint64 returns the uint64 representation of the given attribute's data.
func (c Conn) Uint64(attr ConnAttrType) (uint64, error) {
	if data, ok := c[attr]; ok {
		if len(data) != 8 {
			return 0, ErrAttrLength
		}
		return nlenc.Uint64(data), nil
	}
	return 0, ErrConnNoAttr
}
