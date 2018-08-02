package conntrack

import (
	"reflect"
	"testing"
)

func TestNestFilter(t *testing.T) {
	tests := []struct {
		name   string
		filter FilterAttr
		data   []byte
		err    error
	}{
		{name: "empty filter", filter: FilterAttr{}, err: ErrFilterAttrLength},
		{name: "simple filter", filter: FilterAttr{Mark: []byte{0x11, 0x11, 0x11, 0x11}, MarkMask: []byte{0xFF, 0xFF, 0xFF, 0xFF}},
			data: []byte{0x8, 0x0, 0x8, 0x0, 0x11, 0x11, 0x11, 0x11, 0x8, 0x0, 0x15, 0x0, 0xff, 0xff, 0xff, 0xff}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			data, err := nestFilter(tc.filter)
			if err != tc.err {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(data, tc.data) {
				t.Fatalf("unexpected replies:\n- want: %#v\n-  got: %#v", tc.data, data)
			}

		})
	}
}
