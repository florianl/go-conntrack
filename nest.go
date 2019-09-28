//+build linux

package conntrack

import (
	"encoding/binary"
	"log"

	"github.com/mdlayher/netlink"
)

func nestAttributes(logger *log.Logger, filters *Con) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()

	if filters.Origin != nil {
		data, err := marshalIPTuple(logger, filters.Origin)
		if err != nil {
			return []byte{}, err
		}
		ae.Bytes(ctaTupleOrig|nlafNested, data)
	}
	if filters.Reply != nil {
		data, err := marshalIPTuple(logger, filters.Reply)
		if err != nil {
			return []byte{}, err
		}
		ae.Bytes(ctaTupleReply|nlafNested, data)
	}

	if filters.ID != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint32(ctaID, *filters.ID)
		ae.ByteOrder = nativeEndian
	}
	if filters.Mark != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint32(ctaMark, *filters.Mark)
		ae.ByteOrder = nativeEndian
	}

	if filters.MarkMask != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint32(ctaMarkMask, *filters.MarkMask)
		ae.ByteOrder = nativeEndian
	}

	if filters.Timeout != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint32(ctaTimeout, *filters.Timeout)
		ae.ByteOrder = nativeEndian
	}
	if filters.Status != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint32(ctaStatus, *filters.Status)
		ae.ByteOrder = nativeEndian
	}
	if filters.ProtoInfo != nil {
		data, err := marshalProtoInfo(logger, filters.ProtoInfo)
		if err != nil {
			return []byte{}, err
		}
		ae.Bytes(ctaProtoinfo|nlafNested, data)
	}

	return ae.Encode()
}
