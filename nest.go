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

func nestAttributes(filters Con) ([]byte, error) {
	var attrs []netlink.Attribute

	attributes, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return nil, err
	}
	return attributes, nil
}
