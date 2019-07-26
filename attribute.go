//+build linux

package conntrack

import (
	"fmt"
	"log"
	"net"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
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
	ctaProtoinfoSCTPState        = 1
	ctaProtoinfoSCTPVTagOriginal = 2
	ctaProtoinfoSCTPVTagReply    = 3
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

const (
	dirOrig   = iota
	dirReply  = iota
	dirMaster = iota
)

const nlafNested = (1 << 15)

func extractIP(logger *log.Logger, data []byte) (net.IP, net.IP, error) {
	var src, dst net.IP
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return src, dst, err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaIPv4Src:
			src = net.IP(ad.Bytes())
		case ctaIPv4Dst:
			dst = net.IP(ad.Bytes())
		case ctaIPv6Src:
			src = net.IP(ad.Bytes())
		case ctaIPv6Dst:
			dst = net.IP(ad.Bytes())
		default:
			return src, dst, fmt.Errorf("extractIP(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return src, dst, nil
}

func extractIPTuple(v *IPTuple, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() + nlafNested {
		case ctaTupleIP:
			src, dst, err := extractIP(logger, ad.Bytes())
			if err != nil {
				return err
			}
			v.Src = src
			v.Dst = dst
		case ctaTupleProto:
		case ctaTupleZone:
		default:
			return fmt.Errorf("extractIPTuple(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return nil
}

func extractAttribute(c *Con, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() & 0xFF {
		case ctaTupleOrig:
			tuple := &IPTuple{}
			if err := extractIPTuple(tuple, logger, ad.Bytes()); err != nil {
				return err
			}
			c.Origin = tuple
		case ctaTupleReply:
			tuple := &IPTuple{}
			if err := extractIPTuple(tuple, logger, ad.Bytes()); err != nil {
				return err
			}
			c.Reply = tuple
		case ctaID:
			tmp := ad.Uint32()
			logger.Printf("ID: %d", tmp)
			c.ID = &tmp
		case ctaStatus:
			tmp := ad.Uint32()
			logger.Printf("Status: %d", tmp)
			c.Status = &tmp
		default:
			logger.Printf("extractAttribute() - Unknown attribute: %d %v\n", ad.Type(), ad.Bytes())
		}
	}
	return nil
}

func checkHeader(data []byte) int {
	if (data[0] == unix.AF_INET || data[0] == unix.AF_INET6) && data[1] == unix.NFNETLINK_V0 {
		return 4
	}
	return 0
}

func extractAttributes(logger *log.Logger, msg []byte) (Con, error) {
	c := Con{}

	offset := checkHeader(msg[:2])
	if err := extractAttribute(&c, logger, msg[offset:]); err != nil {
		return c, err
	}
	return c, nil
}
