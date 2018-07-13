package conntrack

import (
	"errors"

	"github.com/mdlayher/netlink"
)

// FilterAttr represents a very basic filter
type FilterAttr struct {
	Mark, MarkMask []byte
}

// Error which may occour when processing the filter attribute
var (
	ErrFilterAttrLength = errors.New("Incorrect length of filter attribute")
)

func nestFilter(filter FilterAttr) ([]byte, error) {
	var attrs []netlink.Attribute

	if len(filter.Mark) != 4 {
		return nil, ErrFilterAttrLength
	}
	if len(filter.MarkMask) != 4 {
		return nil, ErrFilterAttrLength
	}
	attrs = append(attrs, netlink.Attribute{Type: ctaMark, Data: filter.Mark})
	attrs = append(attrs, netlink.Attribute{Type: ctaMarkMask, Data: filter.MarkMask})
	return netlink.MarshalAttributes(attrs)
}
