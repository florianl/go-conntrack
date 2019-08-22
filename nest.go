//+build linux

package conntrack

import (
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
		ae.Uint32(ctaID, *filters.ID)
	}
	if filters.Mark != nil {
		ae.Uint32(ctaMark, *filters.Mark)
	}

	return ae.Encode()
}
