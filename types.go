package conntrack

import (
	"errors"
	"log"
	"net"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Config contains options for a Conn.
type Config struct {
	// Network namespace the Nflog needs to operate in. If set to 0 (default),
	// no network namespace will be entered.
	NetNS int

	// Time till a read action times out - only available for Go >= 1.12
	ReadTimeout time.Duration

	// Time till a write action times out - only available for Go >= 1.12
	WriteTimeout time.Duration

	// Interface to log internals.
	Logger *log.Logger
}

// Nfct represents a conntrack handler
type Nfct struct {
	// Con is the pure representation of a netlink socket
	Con *netlink.Conn

	logger *log.Logger

	setReadTimeout  func() error
	setWriteTimeout func() error
}

// adjust the ReadTimeout (mostly for testing)
func adjustReadTimeout(nfct *Nfct, fn func() error) {
	nfct.setReadTimeout = fn
}

// adjust the WriteTimeout (mostly for testing)
func adjustWriteTimeout(nfct *Nfct, fn func() error) {
	nfct.setWriteTimeout = fn
}

// ProtoTuple contains the source and destination IP
type ProtoTuple struct {
}

// IPTuple contains the source and destination IP
type IPTuple struct {
	Src   net.IP
	Dst   net.IP
	Proto ProtoTuple
}

// Conn contains all the information of a connection
type Con struct {
	Origin *IPTuple
	Reply  *IPTuple
	ID     *uint32
	Status *uint32
}

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
	AttrMarkMask                ConnAttrType = iota /* u32 bits */
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

	AttrExpID     ConnAttrType = iota /* u32 bits */
	AttrExpFlags  ConnAttrType = iota /* u32 bits */
	AttrExpClass  ConnAttrType = iota /* u32 bits */
	AttrExpNATDir ConnAttrType = iota /* u32 bits */

)

// Various CPU related statistics
// based on libnetfilter_conntrack.h
const (
	CPUID                 = ConnAttrType(0)
	CPUStatsSearched      = ConnAttrType(1)  /* u64 bits */
	CPUStatsFound         = ConnAttrType(2)  /* u64 bits */
	CPUStatsNew           = ConnAttrType(3)  /* u64 bits */
	CPUStatsInvalid       = ConnAttrType(4)  /* u64 bits */
	CPUStatsIgnore        = ConnAttrType(5)  /* u64 bits */
	CPUStatsDelete        = ConnAttrType(6)  /* u64 bits */
	CPUStatsDeleteList    = ConnAttrType(7)  /* u64 bits */
	CPUStatsInsert        = ConnAttrType(8)  /* u64 bits */
	CPUStatsInsertFailed  = ConnAttrType(9)  /* u64 bits */
	CPUStatsDrop          = ConnAttrType(10) /* u64 bits */
	CPUStatsEarlyDrop     = ConnAttrType(11) /* u64 bits */
	CPUStatsError         = ConnAttrType(12) /* u64 bits */
	CPUStatsSearchRestart = ConnAttrType(13) /* u64 bits */
)

// Various types of global statistics
const (
	StatsGlobalEntries    = 1
	StatsGlobalMaxEntries = 2
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
	ErrDataLength         = errors.New("Incorrect length of provided data")
)

// ErrUnknownCtTable will be return, if the function can not be performed on this subsystem
var ErrUnknownCtTable = errors.New("Not supported for this subsystem")
