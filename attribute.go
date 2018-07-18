//+build linux

package conntrack

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// ConnAttr represents the type and value of a attribute of a connection
type ConnAttr struct {
	Type ConnAttrType
	Data []byte
}

// ConnAttrType specifies the attribute of a connection
type ConnAttrType uint16

// Attributes of a connection
// based on libnetfilter_conntrack.h
const (
	AttrOrigIPv4Src             ConnAttrType = iota /* u32 bits */
	AttrOrigIPv4Dst             ConnAttrType = iota /* u32 bits */
	AttrReplIPv4Src             ConnAttrType = iota /* u32 bits */
	AttrReplIPv4Dst             ConnAttrType = iota /* u32 bits */
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
	AttrMark                    ConnAttrType = iota /* u32 bits */
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
)

const (
	ctaUnspec        = iota
	ctaTupleOrig     = iota
	ctaTupleReply    = iota
	ctaStatus        = iota
	ctaProtoinfo     = iota
	ctaHelp          = iota
	ctaNatSrc        = iota
	ctaTimeout       = iota
	ctaMark          = iota
	ctaCountersOrig  = iota
	ctaCountersReply = iota
	ctaUse           = iota
	ctaID            = iota
	ctaNatDst        = iota
	ctaTupleMaster   = iota
	ctaSeqAdjOrig    = iota
	ctaSeqAdjRepl    = iota
	ctaSecmark       = iota
	ctaZone          = iota
	ctaSecCtx        = iota
	ctaTimestamp     = iota
	ctaMarkMask      = iota
	ctaLables        = iota
	ctaLablesMask    = iota
)

const (
	ctaTupleIP    = 1
	ctaTupleProto = 2
	ctaTupleZone  = 3
)

const (
	ctaIPv4Src = 1
	ctaIPv4Dst = 2
	ctaIPv6Src = 3
	ctaIPv6Dst = 4
)

const (
	ctaProtoNum        = 1
	ctaProtoSrcPort    = 2
	ctaProtoDstPort    = 3
	ctaProtoIcmpID     = 4
	ctaProtoIcmpType   = 5
	ctaProtoIcmpCode   = 6
	ctaProtoIcmpv6ID   = 7
	ctaProtoIcmpv6Type = 8
	ctaProtoIcmpv6Code = 9
)

const (
	ctaProtoinfoTCP  = 1
	ctaProtoinfoDCCP = 2
	ctaProtoinfoSCTP = 3
)

const (
	ctaProtoinfoTCPState      = 1
	ctaProtoinfoTCPWScaleOrig = 2
	ctaProtoinfoTCPWScaleRepl = 3
	ctaProtoinfoTCPFlagsOrig  = 4
	ctaProtoinfoTCPFlagsRepl  = 5
)

const (
	ctaProtoinfoDCCPState        = 1
	ctaProtoinfoDCCPRole         = 2
	ctaProtoinfoDCCPHandshakeSeq = 3
)

const (
	ctaProtoInfoSCTPState        = 1
	ctaProtoInfoSCTPVTagOriginal = 2
	ctaProtoInfoSCTPVTagReply    = 3
)

const (
	ctaCounterPackets   = 1
	ctaCounterBytes     = 2
	ctaCounter32Packets = 3
	ctaCounter32Bytes   = 4
)

const (
	ctaTimestampStart = 1
	ctaTimestampStop  = 2
)

const (
	ctaHelpName = 1
	ctaHelpInfo = 2
)

const (
	ctaSeqAdjCorrPos      = 1
	ctaSeqAdjOffsetBefore = 2
	ctaSeqAdjOffsetAfter  = 3
)

const nlafNested = (1 << 15)

func checkHeader(data []byte) int {
	if (data[0] == unix.AF_INET || data[0] == unix.AF_INET6) && data[1] == unix.NFNETLINK_V0 {
		return 4
	}
	return 0
}

func extractTCPTuple(conn Conn, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	for _, attr := range attributes {
		switch attr.Type & 0XFF {
		case ctaProtoinfoTCPState:
			conn[AttrTCPState] = attr.Data
		case ctaProtoinfoTCPWScaleOrig:
			conn[AttrTCPWScaleOrig] = attr.Data
		case ctaProtoinfoTCPWScaleRepl:
			conn[AttrTCPWScaleRepl] = attr.Data
		case ctaProtoinfoTCPFlagsOrig:
			conn[AttrTCPFlagsOrig] = attr.Data
		case ctaProtoinfoTCPFlagsRepl:
			conn[AttrTCPFlagsRepl] = attr.Data
		}
	}
	return nil
}

func extractDCCPTuple(conn Conn, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	for _, attr := range attributes {
		switch attr.Type & 0XFF {
		case ctaProtoinfoDCCPState:
			conn[AttrDccpState] = attr.Data
		case ctaProtoinfoDCCPRole:
			conn[AttrDccpRole] = attr.Data
		case ctaProtoinfoDCCPHandshakeSeq:
			conn[AttrDccpHandshakeSeq] = attr.Data
		}
	}
	return nil
}

func extractSCTPTuple(conn Conn, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	for _, attr := range attributes {
		switch attr.Type & 0XFF {
		case ctaProtoInfoSCTPState:
			conn[AttrSctpState] = attr.Data
		case ctaProtoInfoSCTPVTagOriginal:
			conn[AttrSctpVtagOrig] = attr.Data
		case ctaProtoInfoSCTPVTagReply:
			conn[AttrSctpVtagRepl] = attr.Data
		}
	}
	return nil
}

func extractProtoinfo(conn Conn, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	for _, attr := range attributes {
		switch attr.Type & 0XFF {
		case ctaProtoinfoTCP:
			if err := extractTCPTuple(conn, attr.Data); err != nil {
				return err
			}
		case ctaProtoinfoDCCP:
			if err := extractDCCPTuple(conn, attr.Data); err != nil {
				return err
			}
		case ctaProtoinfoSCTP:
			if err := extractSCTPTuple(conn, attr.Data); err != nil {
				return err
			}
		}
	}
	return nil
}

func extractProtocolTuple(conn Conn, dir int, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	for _, attr := range attributes {
		switch attr.Type & 0XFF {
		case ctaProtoNum:
			if dir == -1 {
				conn[AttrOrigL4Proto] = attr.Data
			} else {
				conn[AttrReplL4Proto] = attr.Data
			}
		case ctaProtoSrcPort:
			conn[ConnAttrType(ctaProtoSrcPort+dir+8)] = attr.Data
		case ctaProtoDstPort:
			conn[ConnAttrType(ctaProtoDstPort+dir+8)] = attr.Data
		case ctaProtoIcmpID:
			conn[AttrIcmpID] = attr.Data
		case ctaProtoIcmpType:
			conn[AttrIcmpType] = attr.Data
		case ctaProtoIcmpCode:
			conn[AttrIcmpCode] = attr.Data
		case ctaProtoIcmpv6ID:
			conn[AttrIcmpID] = attr.Data
		case ctaProtoIcmpv6Type:
			conn[AttrIcmpCode] = attr.Data
		case ctaProtoIcmpv6Code:
			conn[AttrIcmpCode] = attr.Data
		}
	}
	return nil
}

func extractIPTuple(conn Conn, dir int, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	for _, attr := range attributes {
		switch attr.Type & 0XFF {
		case ctaIPv4Src:
			conn[ConnAttrType(ctaIPv4Src+dir)] = attr.Data
			if dir == -1 {
				conn[AttrOrigL3Proto] = []byte{byte(unix.AF_INET)}
			} else {
				conn[AttrReplL3Proto] = []byte{byte(unix.AF_INET)}
			}
		case ctaIPv4Dst:
			conn[ConnAttrType(ctaIPv4Dst+dir)] = attr.Data
		case ctaIPv6Src:
			if dir == -1 {
				conn[AttrOrigL3Proto] = []byte{byte(unix.AF_INET6)}
			} else {
				conn[AttrReplL3Proto] = []byte{byte(unix.AF_INET6)}
			}
			conn[ConnAttrType(ctaIPv6Src+dir+2)] = attr.Data
		case ctaIPv6Dst:
			conn[ConnAttrType(ctaIPv6Dst+dir+2)] = attr.Data
		}
	}
	return nil
}

func extractTuple(conn Conn, dir int, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	for _, attr := range attributes {
		switch attr.Type & 0XFF {
		case ctaTupleIP:
			if err := extractIPTuple(conn, dir, attr.Data); err != nil {
				return err
			}
		case ctaTupleProto:
			if err := extractProtocolTuple(conn, dir, attr.Data); err != nil {
				return err
			}
		case ctaTupleZone:
			return fmt.Errorf("ctaTupleZone not yet implemented")

		}
	}
	return nil
}

func extractCounterTuple(conn Conn, dir int, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	for _, attr := range attributes {
		switch attr.Type & 0XFF {
		case ctaCounter32Packets:
			fallthrough
		case ctaCounterPackets:
			if dir == -1 {
				conn[AttrOrigCounterPackets] = attr.Data
			} else {
				conn[AttrReplCounterPackets] = attr.Data
			}
		case ctaCounter32Bytes:
			fallthrough
		case ctaCounterBytes:
			if dir == -1 {
				conn[AttrOrigCounterBytes] = attr.Data
			} else {
				conn[AttrReplCounterBytes] = attr.Data
			}
		}
	}
	return nil
}

func extractTimestampTuple(conn Conn, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	for _, attr := range attributes {
		switch attr.Type & 0XFF {
		case ctaTimestampStart:
			conn[AttrTimestampStart] = attr.Data
		case ctaTimestampStop:
			conn[AttrTimestampStop] = attr.Data
		}
	}
	return nil
}

func extractHelpTuple(conn Conn, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	for _, attr := range attributes {
		switch attr.Type & 0XFF {
		case ctaHelpName:
			conn[AttrHelperName] = attr.Data
		case ctaHelpInfo:
			conn[AttrHelperInfo] = attr.Data
		}
	}
	return nil
}

func extractNATSeqTuple(conn Conn, dir int, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	for _, attr := range attributes {
		switch attr.Type & 0XFF {
		case ctaSeqAdjCorrPos:
			conn[ConnAttrType(int(AttrOrigNatSeqCorrectionPos)+dir)] = attr.Data
		case ctaSeqAdjOffsetBefore:
			conn[ConnAttrType(int(AttrOrigNatSeqOffsetBefore)+dir)] = attr.Data
		case ctaSeqAdjOffsetAfter:
			conn[ConnAttrType(int(AttrOrigNatSeqOffsetAfter)+dir)] = attr.Data
		}
	}
	return nil
}

func extractAttribute(conn Conn, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}

	for _, attr := range attributes {
		switch attr.Type & 0xFF {
		case ctaTupleOrig:
			if err := extractTuple(conn, -1, attr.Data); err != nil {
				return err
			}
		case ctaTupleReply:
			if err := extractTuple(conn, 1, attr.Data); err != nil {
				return err
			}
		case ctaProtoinfo:
			if err := extractProtoinfo(conn, attr.Data); err != nil {
				return err
			}
		case ctaSeqAdjOrig:
			if err := extractNATSeqTuple(conn, 0, attr.Data); err != nil {
				return err
			}
		case ctaSeqAdjRepl:
			if err := extractNATSeqTuple(conn, 3, attr.Data); err != nil {
				return err
			}
		case ctaCountersOrig:
			if err := extractCounterTuple(conn, -1, attr.Data); err != nil {
				return err
			}
		case ctaCountersReply:
			if err := extractCounterTuple(conn, 1, attr.Data); err != nil {
				return err
			}
		case ctaTimestamp:
			if err := extractTimestampTuple(conn, attr.Data); err != nil {
				return err
			}
		case ctaHelp:
			if err := extractHelpTuple(conn, attr.Data); err != nil {
				return err
			}
		case ctaTimeout:
			conn[AttrTimeout] = attr.Data
		case ctaID:
			conn[AttrID] = attr.Data
		case ctaUse:
			conn[AttrUse] = attr.Data
		case ctaStatus:
			conn[AttrStatus] = attr.Data
		case ctaMark:
			conn[AttrMark] = attr.Data
		case ctaSecCtx:
			conn[AttrSecCtx] = attr.Data
		case ctaLables:
			conn[AttrConnlabels] = attr.Data
		case ctaLablesMask:
			conn[AttrConnlabelsMask] = attr.Data
		case ctaSecmark:
			conn[AttrSecmark] = attr.Data
		case ctaZone:
			conn[AttrZone] = attr.Data
		case ctaNatDst:
			/* deprecated	*/
		case ctaNatSrc:
			/* deprecated	*/
		default:
			fmt.Println(attr.Type&0xFF, "\t", attr.Length, "\t", attr.Data)
		}
	}
	return nil
}

func extractAttributes(msg []byte) (Conn, error) {
	var conn = make(map[ConnAttrType][]byte)

	offset := checkHeader(msg[:2])
	if err := extractAttribute(conn, msg[offset:]); err != nil {
		return nil, err
	}
	return conn, nil
}
