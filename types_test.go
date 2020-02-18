package conntrack

import (
	"fmt"
	"testing"
)

func TestConnAttr_String(t *testing.T) {
	ca := ConnAttr{
		Type: AttrOrigIPv4Src,
		Data: []byte{0x7F, 0x00, 0x00, 0x01},
		Mask: []byte{0xFF, 0xFF, 0xFF, 0xFF},
	}
	fmt.Printf("%v\n", ca)
	// Output: Type:  0 - Data: [[127 0 0 1]] - Mask: [[255 255 255 255]] - Negate: false
}
