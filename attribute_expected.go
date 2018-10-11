package conntrack

import (
	"fmt"

	"github.com/mdlayher/netlink"
)

const (
	ctaExpUnspec   = iota
	ctaExpMaster   = iota
	ctaExpTuple    = iota
	ctaExpMask     = iota
	ctaExpTimeout  = iota
	ctaExpID       = iota
	ctaExpHelpName = iota
	ctaExpZone     = iota
	ctaExpFlags    = iota
	ctaExpClass    = iota
	ctaExpNAT      = iota
	ctaExpFN       = iota
)

const (
	ctaExpectNATUnspec = iota
	ctaExpectNATDir    = iota
	ctaExpectNATTuple  = iota
)

func extractExpectTuple(expect Conn, offset int, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	for _, attr := range attributes {
		switch attr.Type {
		case ctaTupleIP + nlafNested:
		case ctaTupleProto + nlafNested:
		case ctaTupleZone + nlafNested:
		default:
			return fmt.Errorf("Tuple %d is not yet implemented", attr.Type)
		}
	}
	return nil
}

func extractExpectAttribute(expect Conn, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	for _, attr := range attributes {
		switch attr.Type & 0xFF {
		case ctaExpMask:
			if err := extractExpectTuple(expect, 0, attr.Data); err != nil {
				return err
			}
		case ctaExpTimeout:
			expect[AttrTimeout] = attr.Data
		case ctaExpHelpName:
			expect[AttrHelperName] = attr.Data
		case ctaExpZone:
			expect[AttrZone] = attr.Data
		case ctaExpFN:
			expect[AttrHelperInfo] = attr.Data
		default:
			fmt.Println(attr.Type&0xFF, "\t", attr.Length, "\t", attr.Data)
		}
	}
	return nil
}

func extractExpectAttributes(msg []byte) (Conn, error) {
	var expect = make(map[ConnAttrType][]byte)

	if err := extractExpectAttribute(expect, msg[24:]); err != nil {
		return nil, err
	}
	return expect, nil
}
