//+build linux

package conntrack

import (
	"errors"

	"github.com/mdlayher/netlink"
)

// Various errors which may occur when processing attributes
var (
	ErrAttrLength         = errors.New("Incorrect length of attribute")
	ErrAttrNotImplemented = errors.New("Attribute not implemented")
	ErrAttrNotExist       = errors.New("Type of attribute does not exist")
)

func nestSubTuple(tupleType uint16, sub []netlink.Attribute) ([]byte, error) {
	attr, err := netlink.MarshalAttributes(sub)
	if err != nil {
		return nil, err
	}
	var tuple netlink.Attribute
	tuple.Type = tupleType | nlafNested
	tuple.Length = uint16(len(attr) + 4)
	tuple.Data = attr

	return tuple.MarshalBinary()
}

func nestTuples(attrs []ConnAttr) ([]byte, error) {
	subTuples := make(map[uint32][]netlink.Attribute)
	var nestingTuple uint32
	for _, x := range attrs {
		if nestingTuple == 0 {
			nestingTuple = filterCheck[x.Type].nest[0]
		}
		subNest := filterCheck[x.Type].nest[1]
		subTuples[subNest] = append(subTuples[subNest], netlink.Attribute{Type: uint16(filterCheck[x.Type].ct), Data: x.Data})
	}

	var tuple netlink.Attribute
	tuple.Type = uint16(nestingTuple) | nlafNested
	var data []byte
	for i, x := range subTuples {
		tmp, err := nestSubTuple(uint16(i), x)
		if err != nil {
			return nil, err
		}
		data = append(data, tmp...)
	}
	tuple.Length = uint16(len(data) + 4)
	tuple.Data = data

	return tuple.MarshalBinary()
}

func nestAttributes(filters []ConnAttr) ([]byte, error) {
	var attributes []byte
	var attrs []netlink.Attribute
	var tupleOrig, tupleRepl, tupleProto []ConnAttr

	for _, filter := range filters {
		if _, ok := filterCheck[filter.Type]; !ok {
			return nil, ErrAttrNotExist
		}
		if filterCheck[filter.Type].ct == ctaUnspec {
			return nil, ErrAttrNotImplemented
		}
		if len(filter.Data) != filterCheck[filter.Type].len {
			return nil, ErrAttrLength
		}
		if filter.Type == AttrOrigIPv4Src ||
			filter.Type == AttrOrigIPv4Dst ||
			filter.Type == AttrOrigIPv6Src ||
			filter.Type == AttrOrigIPv6Dst ||
			filter.Type == AttrOrigPortSrc ||
			filter.Type == AttrOrigPortDst ||
			filter.Type == AttrIcmpType ||
			filter.Type == AttrIcmpCode ||
			filter.Type == AttrIcmpID {
			tupleOrig = append(tupleOrig, filter)
		} else if filter.Type == AttrReplIPv4Src ||
			filter.Type == AttrReplIPv4Dst ||
			filter.Type == AttrReplIPv6Src ||
			filter.Type == AttrReplIPv6Dst ||
			filter.Type == AttrReplPortSrc ||
			filter.Type == AttrReplPortDst ||
			filter.Type == AttrIcmpType ||
			filter.Type == AttrIcmpCode ||
			filter.Type == AttrIcmpID {
			tupleRepl = append(tupleRepl, filter)
		} else if filter.Type == AttrTCPFlagsOrig ||
			filter.Type == AttrTCPFlagsRepl ||
			filter.Type == AttrTCPState ||
			filter.Type == AttrTCPWScaleOrig ||
			filter.Type == AttrTCPWScaleRepl ||
			filter.Type == AttrSctpState ||
			filter.Type == AttrSctpVtagOrig ||
			filter.Type == AttrSctpVtagRepl ||
			filter.Type == AttrDccpState ||
			filter.Type == AttrDccpRole ||
			filter.Type == AttrDccpHandshakeSeq {
			tupleProto = append(tupleProto)
		} else {
			attrs = append(attrs, netlink.Attribute{Type: uint16(filterCheck[filter.Type].ct), Data: filter.Data})
		}
	}

	if len(tupleOrig) != 0 {
		data, err := nestTuples(tupleOrig)
		if err != nil {
			return nil, err
		}
		attributes = append(attributes, data...)
	}
	if len(tupleRepl) != 0 {
		data, err := nestTuples(tupleRepl)
		if err != nil {
			return nil, err
		}
		attributes = append(attributes, data...)
	}
	if len(tupleProto) != 0 {
		data, err := nestTuples(tupleProto)
		if err != nil {
			return nil, err
		}
		attributes = append(attributes, data...)

	}

	regular, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return nil, err
	}
	attributes = append(attributes, regular...)
	return attributes, nil
}
