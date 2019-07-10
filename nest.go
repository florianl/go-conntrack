//+build linux

package conntrack

import (
	"github.com/mdlayher/netlink"
)

func nestSubTuple(tupleType uint16, sub []netlink.Attribute) ([]byte, error) {
	attr, err := netlink.MarshalAttributes(sub)
	if err != nil {
		return nil, err
	}

	return netlink.MarshalAttributes([]netlink.Attribute{{
		Type: tupleType | nlafNested,
		Data: attr,
	}})
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

	// We can not simple range over the map, because the order of selected items can vary
	for key := 0; key <= int(attrMax); key++ {
		if x, ok := subTuples[uint32(key)]; ok {
			tmp, err := nestSubTuple(uint16(key), x)
			if err != nil {
				return nil, err
			}
			data = append(data, tmp...)
		}
		tuple.Data = data
	}

	return netlink.MarshalAttributes([]netlink.Attribute{tuple})
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
		switch filter.Type {
		case AttrOrigIPv4Src, AttrOrigIPv4Dst, AttrOrigIPv6Src, AttrOrigIPv6Dst, AttrOrigL4Proto, AttrOrigPortSrc, AttrOrigPortDst, AttrIcmpType, AttrIcmpCode, AttrIcmpID:
			tupleOrig = append(tupleOrig, filter)
		case AttrReplIPv4Src, AttrReplIPv4Dst, AttrReplIPv6Src, AttrReplIPv6Dst, AttrReplL4Proto, AttrReplPortSrc, AttrReplPortDst:
			tupleRepl = append(tupleRepl, filter)
		case AttrTCPFlagsOrig, AttrTCPFlagsRepl, AttrTCPState, AttrTCPWScaleOrig, AttrTCPWScaleRepl, AttrSctpState, AttrSctpVtagOrig, AttrSctpVtagRepl, AttrDccpState, AttrDccpRole, AttrDccpHandshakeSeq:
			tupleProto = append(tupleProto, filter)
		default:
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
