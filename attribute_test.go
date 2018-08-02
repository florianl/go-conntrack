package conntrack

import (
	"reflect"
	"testing"
)

func TestExtractAttributes(t *testing.T) {
	tests := []struct {
		name string
		msg  []byte
		conn Conn
		err  error
	}{
		{name: "localhostV4-DNS", msg: []byte{0x02, 0x00, 0x00, 0x00, 0x34, 0x00, 0x01, 0x80, 0x14, 0x00, 0x01, 0x80, 0x08, 0x00, 0x01, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0x02, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x1c, 0x00, 0x02, 0x80, 0x05, 0x00, 0x01, 0x00, 0x11, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0xae, 0x82, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x00, 0x35, 0x00, 0x00, 0x34, 0x00, 0x02, 0x80, 0x14, 0x00, 0x01, 0x80, 0x08, 0x00, 0x01, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0x02, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x1c, 0x00, 0x02, 0x80, 0x05, 0x00, 0x01, 0x00, 0x11, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0x00, 0x35, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0xae, 0x82, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x88, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x11, 0x1c, 0x00, 0x09, 0x80, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x1c, 0x00, 0x0a, 0x80, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x14, 0x80, 0x0c, 0x00, 0x01, 0x00, 0x15, 0x47, 0x0e, 0x8c, 0x34, 0x78, 0x34, 0x4e, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x13, 0x80, 0x25, 0x00, 0x01, 0x00, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x75, 0x3a, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x72, 0x3a, 0x75, 0x6e, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x65, 0x64, 0x5f, 0x74, 0x3a, 0x73, 0x30, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0xf1, 0xba, 0x2b, 0x40, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x01},
			conn: Conn{0x3e: []uint8{0x25, 0x0, 0x1, 0x0, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x75, 0x3a, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x72, 0x3a, 0x75, 0x6e, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x65, 0x64, 0x5f, 0x74, 0x3a, 0x73, 0x30, 0x0, 0x0, 0x0, 0x0}, 0x11: []uint8{0x11}, 0x10: []uint8{0x2}, 0x12: []uint8{0x11}, 0xc: []uint8{0xae, 0x82}, 0x1a: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, 0x1f: []uint8{0xf1, 0xba, 0x2b, 0x40}, 0x1e: []uint8{0x0, 0x0, 0x0, 0x1}, 0x0: []uint8{0x7f, 0x0, 0x0, 0x1}, 0x2: []uint8{0x7f, 0x0, 0x0, 0x1}, 0x1c: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41}, 0x1d: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x3f: []uint8{0x15, 0x47, 0xe, 0x8c, 0x34, 0x78, 0x34, 0x4e}, 0xa: []uint8{0x0, 0x35}, 0x20: []uint8{0x0, 0x0, 0x1, 0x88}, 0x18: []uint8{0x0, 0x0, 0x0, 0x11}, 0x19: []uint8{0x0, 0x0, 0x0, 0x0}, 0x1b: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0xf: []uint8{0x2}, 0x1: []uint8{0x7f, 0x0, 0x0, 0x1}, 0x9: []uint8{0xae, 0x82}, 0x3: []uint8{0x7f, 0x0, 0x0, 0x1}, 0xb: []uint8{0x0, 0x35}}},
		{name: "localhostV4-TCP", msg: []byte{0x02, 0x00, 0x00, 0x00, 0x34, 0x00, 0x01, 0x80, 0x14, 0x00, 0x01, 0x80, 0x08, 0x00, 0x01, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0x02, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x1c, 0x00, 0x02, 0x80, 0x05, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0xe5, 0x22, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x20, 0xfb, 0x00, 0x00, 0x34, 0x00, 0x02, 0x80, 0x14, 0x00, 0x01, 0x80, 0x08, 0x00, 0x01, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0x02, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x1c, 0x00, 0x02, 0x80, 0x05, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0x20, 0xfb, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0xe5, 0x22, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x8e, 0x08, 0x00, 0x07, 0x00, 0x00, 0x06, 0x97, 0x58, 0x1c, 0x00, 0x09, 0x80, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x1c, 0x00, 0x0a, 0x80, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x10, 0x00, 0x14, 0x80, 0x0c, 0x00, 0x01, 0x00, 0x15, 0x47, 0x0f, 0x2f, 0x5f, 0x21, 0x21, 0xc1, 0x30, 0x00, 0x04, 0x80, 0x2c, 0x00, 0x01, 0x80, 0x05, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x06, 0x00, 0x05, 0x00, 0x23, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x13, 0x80, 0x25, 0x00, 0x01, 0x00, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x75, 0x3a, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x72, 0x3a, 0x75, 0x6e, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x65, 0x64, 0x5f, 0x74, 0x3a, 0x73, 0x30, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0xf1, 0xba, 0x39, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x01},
			conn: Conn{0xa: []uint8{0x20, 0xfb}, 0x20: []uint8{0x0, 0x0, 0x1, 0x8e}, 0x21: []uint8{0x23, 0x0}, 0xf: []uint8{0x2}, 0x10: []uint8{0x2}, 0xb: []uint8{0x20, 0xfb}, 0x3f: []uint8{0x15, 0x47, 0xf, 0x2f, 0x5f, 0x21, 0x21, 0xc1}, 0x1f: []uint8{0xf1, 0xba, 0x39, 0x0}, 0x2: []uint8{0x7f, 0x0, 0x0, 0x1}, 0x3: []uint8{0x7f, 0x0, 0x0, 0x1}, 0x3b: []uint8{0x7}, 0x3c: []uint8{0x7}, 0x1e: []uint8{0x0, 0x0, 0x0, 0x1}, 0x0: []uint8{0x7f, 0x0, 0x0, 0x1}, 0x22: []uint8{0x23, 0x0}, 0x11: []uint8{0x6}, 0x12: []uint8{0x6}, 0xc: []uint8{0xe5, 0x22}, 0x18: []uint8{0x0, 0x6, 0x97, 0x58}, 0x1: []uint8{0x7f, 0x0, 0x0, 0x1}, 0x1b: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, 0x13: []uint8{0x3}, 0x19: []uint8{0x0, 0x0, 0x0, 0x0}, 0x3e: []uint8{0x25, 0x0, 0x1, 0x0, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x75, 0x3a, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x72, 0x3a, 0x75, 0x6e, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x65, 0x64, 0x5f, 0x74, 0x3a, 0x73, 0x30, 0x0, 0x0, 0x0, 0x0}, 0x9: []uint8{0xe5, 0x22}, 0x1c: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x70}, 0x1a: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2}, 0x1d: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3c}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := extractAttributes(tc.msg)

			if err != tc.err {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(conn, tc.conn) {
				t.Fatalf("unexpected replies:\n- want: %#v\n-  got: %#v", tc.conn, conn)
			}

		})
	}
}
