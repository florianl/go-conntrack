//+build linux

package conntrack

import (
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	ctaUnspec = iota
	ctaTupleOrig
	ctaTupleReply
	ctaStatus
	ctaProtoinfo
	ctaHelp
	ctaNatSrc
	ctaTimeout
	ctaMark
	ctaCountersOrig
	ctaCountersReply
	ctaUse
	ctaID
	ctaNatDst
	ctaTupleMaster
	ctaSeqAdjOrig
	ctaSeqAdjRepl
	ctaSecmark
	ctaZone
	ctaSecCtx
	ctaTimestamp
	ctaMarkMask
	ctaLables
	ctaLablesMask
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
	ctaSecCtxName = 1
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

func extractSecCtx(v *SecCtx, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaSecCtxName:
			tmp := ad.String()
			v.Name = &tmp
		default:
			logger.Printf("extractSecCtx(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func extractTimestamp(v *Timestamp, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaTimestampStart:
			tmp := ad.Uint64()
			ts := time.Unix(0, int64(tmp))
			v.Start = &ts
		case ctaTimestampStop:
			tmp := ad.Uint64()
			ts := time.Unix(0, int64(tmp))
			v.Stop = &ts
		default:
			logger.Printf("extractTimestamp(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func extractCounter(v *Counter, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaCounterPackets:
			tmp := ad.Uint64()
			v.Packets = &tmp
		case ctaCounterBytes:
			tmp := ad.Uint64()
			v.Bytes = &tmp
		case ctaCounter32Packets:
			tmp := ad.Uint32()
			v.Packets32 = &tmp
		case ctaCounter32Bytes:
			tmp := ad.Uint32()
			v.Bytes32 = &tmp
		default:
			logger.Printf("extractCounter(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func extractDCCPInfo(v *DCCPInfo, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaProtoinfoDCCPState:
			tmp := ad.Uint8()
			v.State = &tmp
		case ctaProtoinfoDCCPRole:
			tmp := ad.Uint8()
			v.Role = &tmp
		case ctaProtoinfoDCCPHandshakeSeq:
			tmp := ad.Uint64()
			v.HandshakeSeq = &tmp
		default:
			logger.Printf("extractDCCPInfo(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func extractSCTPInfo(v *SCTPInfo, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaProtoinfoSCTPState:
			tmp := ad.Uint8()
			v.State = &tmp
		case ctaProtoinfoSCTPVTagOriginal:
			tmp := ad.Uint32()
			v.VTagOriginal = &tmp
		case ctaProtoinfoSCTPVTagReply:
			tmp := ad.Uint32()
			v.VTagReply = &tmp
		default:
			logger.Printf("extractSCTPInfo(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func extractSeqAdj(v *SeqAdj, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaSeqAdjCorrPos:
			tmp := ad.Uint32()
			v.CorrectionPos = &tmp
		case ctaSeqAdjOffsetBefore:
			tmp := ad.Uint32()
			v.OffsetBefore = &tmp
		case ctaSeqAdjOffsetAfter:
			tmp := ad.Uint32()
			v.OffsetAfter = &tmp
		default:
			logger.Printf("extractSeqAdj(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func extractTCPInfo(v *TCPInfo, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaProtoinfoTCPState:
			tmp := ad.Uint8()
			v.State = &tmp
		case ctaProtoinfoTCPWScaleOrig:
			tmp := ad.Uint8()
			v.WScaleOrig = &tmp
		case ctaProtoinfoTCPWScaleRepl:
			tmp := ad.Uint8()
			v.WScaleRepl = &tmp
		case ctaProtoinfoTCPFlagsOrig:
			tmp := ad.Bytes()
			v.FlagsOrig = &tmp
		case ctaProtoinfoTCPFlagsRepl:
			tmp := ad.Bytes()
			v.FlagsReply = &tmp
		default:
			logger.Printf("extractTCPInfo(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func marshalTCPInfo(logger *log.Logger, v *TCPInfo) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()

	if v.State != nil {
		ae.Uint8(ctaProtoinfoTCPState, *v.State)
	}
	if v.WScaleOrig != nil {
		ae.Uint8(ctaProtoinfoTCPWScaleOrig, *v.WScaleOrig)
	}
	if v.WScaleRepl != nil {
		ae.Uint8(ctaProtoinfoTCPWScaleRepl, *v.WScaleRepl)
	}
	if v.FlagsOrig != nil {
		ae.Bytes(ctaProtoinfoTCPFlagsOrig, *v.FlagsOrig)
	}
	if v.FlagsReply != nil {
		ae.Bytes(ctaProtoinfoTCPFlagsRepl, *v.FlagsReply)
	}

	return ae.Encode()
}

func extractProtoInfo(v *ProtoInfo, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaProtoinfoTCP + nlafNested:
			tcp := &TCPInfo{}
			if err := extractTCPInfo(tcp, logger, ad.Bytes()); err != nil {
				return err
			}
			v.TCP = tcp
		case ctaProtoinfoDCCP + nlafNested:
			dccp := &DCCPInfo{}
			if err := extractDCCPInfo(dccp, logger, ad.Bytes()); err != nil {
				return err
			}
			v.DCCP = dccp
		case ctaProtoinfoSCTP + nlafNested:
			sctp := &SCTPInfo{}
			if err := extractSCTPInfo(sctp, logger, ad.Bytes()); err != nil {
				return err
			}
			v.SCTP = sctp
		default:
			logger.Printf("extractProtoInfo(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func marshalProtoInfo(logger *log.Logger, v *ProtoInfo) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()

	if v.TCP != nil {
		data, err := marshalTCPInfo(logger, v.TCP)
		if err != nil {
			return []byte{}, err
		}
		ae.Bytes(ctaProtoinfoTCP|nlafNested, data)
	}

	return ae.Encode()
}

func extractHelp(v *Help, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaHelpName:
			tmp := ad.String()
			v.Name = &tmp
		default:
			logger.Printf("extractHelp(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func extractProtoTuple(logger *log.Logger, data []byte) (ProtoTuple, error) {
	var proto ProtoTuple
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return proto, err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaProtoNum:
			tmp := ad.Uint8()
			proto.Number = &tmp
		case ctaProtoSrcPort:
			tmp := ad.Uint16()
			proto.SrcPort = &tmp
		case ctaProtoDstPort:
			tmp := ad.Uint16()
			proto.DstPort = &tmp
		case ctaProtoIcmpID:
			tmp := ad.Uint16()
			proto.IcmpID = &tmp
		case ctaProtoIcmpType:
			tmp := ad.Uint8()
			proto.IcmpType = &tmp
		case ctaProtoIcmpCode:
			tmp := ad.Uint8()
			proto.IcmpCode = &tmp
		case ctaProtoIcmpv6ID:
			tmp := ad.Uint16()
			proto.Icmpv6ID = &tmp
		case ctaProtoIcmpv6Type:
			tmp := ad.Uint8()
			proto.Icmpv6Type = &tmp
		case ctaProtoIcmpv6Code:
			tmp := ad.Uint8()
			proto.Icmpv6Code = &tmp
		default:
			logger.Printf("extractProtoTuple(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return proto, ad.Err()
}

func marshalProtoTuple(logger *log.Logger, v *ProtoTuple) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()

	if v.Number != nil {
		ae.Uint8(ctaProtoNum, *v.Number)
	}
	if v.SrcPort != nil {
		ae.Uint16(ctaProtoSrcPort, *v.SrcPort)
	}
	if v.DstPort != nil {
		ae.Uint16(ctaProtoDstPort, *v.DstPort)
	}
	if v.IcmpID != nil {
		ae.Uint16(ctaProtoIcmpID, *v.IcmpID)
	}
	if v.IcmpType != nil {
		ae.Uint8(ctaProtoIcmpType, *v.IcmpType)
	}
	if v.IcmpCode != nil {
		ae.Uint8(ctaProtoIcmpCode, *v.IcmpCode)
	}
	if v.Icmpv6ID != nil {
		ae.Uint16(ctaProtoIcmpv6ID, *v.Icmpv6ID)
	}
	if v.Icmpv6Type != nil {
		ae.Uint8(ctaProtoIcmpv6Type, *v.Icmpv6Type)
	}
	if v.Icmpv6Code != nil {
		ae.Uint8(ctaProtoIcmpv6Code, *v.Icmpv6Code)
	}

	return ae.Encode()
}

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
			logger.Printf("extractIP(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return src, dst, ad.Err()
}

func marshalIP(logger *log.Logger, v *IPTuple) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()

	if v.Src != nil {
		if v.Src.To4() == nil && v.Src.To16() != nil {
			ae.Bytes(ctaIPv6Src, *v.Src)
		} else {
			tmp := *v.Src
			ae.Bytes(ctaIPv4Src, tmp[12:])
		}
	}

	if v.Dst != nil {
		if v.Dst.To4() == nil && v.Dst.To16() != nil {
			ae.Bytes(ctaIPv6Dst, *v.Dst)
		} else {
			tmp := *v.Dst
			ae.Bytes(ctaIPv4Dst, tmp[12:])
		}
	}

	return ae.Encode()
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
			v.Src = &src
			v.Dst = &dst
		case ctaTupleProto:
			proto, err := extractProtoTuple(logger, ad.Bytes())
			if err != nil {
				return err
			}
			v.Proto = &proto
		case ctaTupleZone:
			tmp := ad.Bytes()
			v.Zone = &tmp
		default:
			logger.Printf("extractIPTuple(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func marshalIPTuple(logger *log.Logger, v *IPTuple) ([]byte, error) {
	var attrs []netlink.Attribute

	if v.Src != nil || v.Dst != nil {
		data, err := marshalIP(logger, v)
		if err != nil {
			return []byte{}, err
		}
		attrs = append(attrs, netlink.Attribute{Type: ctaTupleIP | nlafNested, Data: data})
	}

	if v.Proto != nil {
		data, err := marshalProtoTuple(logger, v.Proto)
		if err != nil {
			return []byte{}, err
		}
		attrs = append(attrs, netlink.Attribute{Type: ctaTupleProto | nlafNested, Data: data})
	}

	return netlink.MarshalAttributes(attrs)
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
		case ctaProtoinfo:
			protoInfo := &ProtoInfo{}
			if err := extractProtoInfo(protoInfo, logger, ad.Bytes()); err != nil {
				return err
			}
			c.ProtoInfo = protoInfo
		case ctaHelp:
			help := &Help{}
			if err := extractHelp(help, logger, ad.Bytes()); err != nil {
				return err
			}
			c.Help = help
		case ctaID:
			tmp := ad.Uint32()
			c.ID = &tmp
		case ctaStatus:
			tmp := ad.Uint32()
			c.Status = &tmp
		case ctaUse:
			tmp := ad.Uint32()
			c.Use = &tmp
		case ctaMark:
			tmp := ad.Uint32()
			c.Mark = &tmp
		case ctaTimeout:
			tmp := ad.Uint32()
			c.Timeout = &tmp
		case ctaCountersOrig:
			orig := &Counter{}
			if err := extractCounter(orig, logger, ad.Bytes()); err != nil {
				return err
			}
			c.CounterOrigin = orig
		case ctaCountersReply:
			reply := &Counter{}
			if err := extractCounter(reply, logger, ad.Bytes()); err != nil {
				return err
			}
			c.CounterReply = reply
		case ctaSeqAdjOrig:
			orig := &SeqAdj{}
			if err := extractSeqAdj(orig, logger, ad.Bytes()); err != nil {
				return err
			}
			c.SeqAdjOrig = orig
		case ctaSeqAdjRepl:
			reply := &SeqAdj{}
			if err := extractSeqAdj(reply, logger, ad.Bytes()); err != nil {
				return err
			}
			c.SeqAdjRepl = reply
		case ctaZone:
			zone := ad.Uint16()
			c.Zone = &zone
		case ctaSecCtx:
			secCtx := &SecCtx{}
			if err := extractSecCtx(secCtx, logger, ad.Bytes()); err != nil {
				return err
			}
			c.SecCtx = secCtx
		case ctaTimestamp:
			ts := &Timestamp{}
			if err := extractTimestamp(ts, logger, ad.Bytes()); err != nil {
				return err
			}
			c.Timestamp = ts
		default:
			logger.Printf("extractAttribute() - Unknown attribute: %d %d %v\n", ad.Type()&0xFF, ad.Type(), ad.Bytes())
		}
	}
	return ad.Err()
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
