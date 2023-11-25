package conntrack

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/florianl/go-conntrack/internal/unix"

	"golang.org/x/net/bpf"
)

func TestOldConstructFilter(t *testing.T) {
	tests := []struct {
		name     string
		table    Table
		filters  []ConnAttr
		rawInstr []bpf.RawInstruction
		err      error
	}{
		// Example from libnetfilter_conntrack/utils/conntrack_filter.c
		{name: "conntrack_filter.c", table: Conntrack, filters: []ConnAttr{
			{Type: AttrOrigL4Proto, Data: []byte{0x11}}, // TCP
			{Type: AttrOrigL4Proto, Data: []byte{0x06}}, // UDP
			{Type: AttrTCPState, Data: []byte{0x3}},     // TCP_CONNTRACK_ESTABLISHED
			{Type: AttrOrigIPv4Src, Data: []byte{0x7F, 0x0, 0x0, 0x1}, Mask: []byte{0xff, 0xff, 0xff, 0xff}, Negate: true}, // SrcIP != 127.0.0.1
			{Type: AttrOrigIPv6Src, Data: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, // SrcIP != ::1
				Mask: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, Negate: true},
		},
			rawInstr: []bpf.RawInstruction{
				{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: 0x0050, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: 0x0015, Jt: 0x01, Jf: 0x00, K: 0x00000001},
				{Op: 0x0006, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				{Op: 0x0000, Jt: 0x00, Jf: 0x00, K: 0x00000014},
				{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: 0x0015, Jt: 0x0d, Jf: 0x00, K: 0x00000000},
				{Op: 0x0004, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: 0x0015, Jt: 0x09, Jf: 0x00, K: 0x00000000},
				{Op: 0x0004, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: 0x0015, Jt: 0x05, Jf: 0x00, K: 0x00000000},
				{Op: 0x0007, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: 0x0040, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: 0x0054, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				{Op: 0x0015, Jt: 0x01, Jf: 0x00, K: 0x7f000001},
				{Op: 0x0005, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: 0x0006, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: 0x0000, Jt: 0x00, Jf: 0x00, K: 0x00000014},
				{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: 0x0015, Jt: 0x16, Jf: 0x00, K: 0x00000000},
				{Op: 0x0004, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: 0x0015, Jt: 0x12, Jf: 0x00, K: 0x00000000},
				{Op: 0x0004, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000003},
				{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: 0x0015, Jt: 0x0e, Jf: 0x00, K: 0x00000000},
				{Op: 0x0007, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: 0x0040, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: 0x0054, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				{Op: 0x0015, Jt: 0x00, Jf: 0x0a, K: 0x00000000},
				{Op: 0x0040, Jt: 0x00, Jf: 0x00, K: 0x00000008},
				{Op: 0x0054, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				{Op: 0x0015, Jt: 0x00, Jf: 0x07, K: 0x00000000},
				{Op: 0x0040, Jt: 0x00, Jf: 0x00, K: 0x0000000c},
				{Op: 0x0054, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				{Op: 0x0015, Jt: 0x00, Jf: 0x04, K: 0x00000000},
				{Op: 0x0040, Jt: 0x00, Jf: 0x00, K: 0x00000010},
				{Op: 0x0054, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				{Op: 0x0015, Jt: 0x01, Jf: 0x00, K: 0x00000001},
				{Op: 0x0005, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: 0x0006, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: 0x0000, Jt: 0x00, Jf: 0x00, K: 0x00000014},
				{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: 0x0015, Jt: 0x0d, Jf: 0x00, K: 0x00000000},
				{Op: 0x0004, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000002},
				{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: 0x0015, Jt: 0x09, Jf: 0x00, K: 0x00000000},
				{Op: 0x0004, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: 0x0015, Jt: 0x05, Jf: 0x00, K: 0x00000000},
				{Op: 0x0007, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: 0x0050, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: 0x0015, Jt: 0x02, Jf: 0x00, K: 0x00000011},
				{Op: 0x0015, Jt: 0x01, Jf: 0x00, K: 0x00000006},
				{Op: 0x0006, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: 0x0000, Jt: 0x00, Jf: 0x00, K: 0x00000014},
				{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: 0x0015, Jt: 0x0c, Jf: 0x00, K: 0x00000000},
				{Op: 0x0004, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: 0x0015, Jt: 0x08, Jf: 0x00, K: 0x00000000},
				{Op: 0x0004, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: 0x0015, Jt: 0x04, Jf: 0x00, K: 0x00000000},
				{Op: 0x0007, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: 0x0050, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: 0x0015, Jt: 0x01, Jf: 0x00, K: 0x00000003},
				{Op: 0x0006, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: 0x0006, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
			},
		},
		{name: "tcp and port 22", table: Conntrack, filters: []ConnAttr{
			{Type: AttrOrigL4Proto, Data: []byte{0x11}},       // TCP
			{Type: AttrOrigPortDst, Data: []byte{0x00, 0x16}}, // 22
		}, rawInstr: []bpf.RawInstruction{
			{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000004},
			{Op: 0x0050, Jt: 0x00, Jf: 0x00, K: 0x00000001},
			{Op: 0x0015, Jt: 0x01, Jf: 0x00, K: 0x00000001},
			{Op: 0x0006, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
			{Op: 0x0000, Jt: 0x00, Jf: 0x00, K: 0x00000014},
			{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000001},
			{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
			{Op: 0x0015, Jt: 0x0c, Jf: 0x00, K: 0x00000000},
			{Op: 0x0004, Jt: 0x00, Jf: 0x00, K: 0x00000004},
			{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000002},
			{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
			{Op: 0x0015, Jt: 0x08, Jf: 0x00, K: 0x00000000},
			{Op: 0x0004, Jt: 0x00, Jf: 0x00, K: 0x00000004},
			{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000003},
			{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
			{Op: 0x0015, Jt: 0x04, Jf: 0x00, K: 0x00000000},
			{Op: 0x0007, Jt: 0x00, Jf: 0x00, K: 0x00000000},
			{Op: 0x0048, Jt: 0x00, Jf: 0x00, K: 0x00000004},
			{Op: 0x0015, Jt: 0x01, Jf: 0x00, K: 0x00000016},
			{Op: 0x0006, Jt: 0x00, Jf: 0x00, K: 0x00000000},
			{Op: 0x0000, Jt: 0x00, Jf: 0x00, K: 0x00000014},
			{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000001},
			{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
			{Op: 0x0015, Jt: 0x0c, Jf: 0x00, K: 0x00000000},
			{Op: 0x0004, Jt: 0x00, Jf: 0x00, K: 0x00000004},
			{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x000000002},
			{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
			{Op: 0x0015, Jt: 0x08, Jf: 0x00, K: 0x00000000},
			{Op: 0x0004, Jt: 0x00, Jf: 0x00, K: 0x00000004},
			{Op: 0x0001, Jt: 0x00, Jf: 0x00, K: 0x00000001},
			{Op: 0x0030, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
			{Op: 0x0015, Jt: 0x04, Jf: 0x00, K: 0x00000000},
			{Op: 0x0007, Jt: 0x00, Jf: 0x00, K: 0x00000000},
			{Op: 0x0050, Jt: 0x00, Jf: 0x00, K: 0x00000004},
			{Op: 0x0015, Jt: 0x01, Jf: 0x00, K: 0x00000011},
			{Op: 0x0006, Jt: 0x00, Jf: 0x00, K: 0x00000000},
			{Op: 0x0006, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rawInstr, err := constructFilter(tc.table, tc.filters)
			if err != tc.err {
				t.Fatal(err)
			}
			if len(rawInstr) != len(tc.rawInstr) {
				t.Fatalf("different length:\n- want: %#v\n-  got: %#v", tc.rawInstr, rawInstr)
			}
			for i, v := range rawInstr {
				if v != tc.rawInstr[i] {
					t.Fatalf("unexpected reply:\n- want: %#v\n-  got: %#v", tc.rawInstr, rawInstr)
				}
			}

		})
	}
}

func TestConstructFilter(t *testing.T) {
	mark1ByteValue := make([]byte, 4)
	binary.BigEndian.PutUint32(mark1ByteValue, 1)
	mark10ByteValue := make([]byte, 4)
	binary.BigEndian.PutUint32(mark10ByteValue, 10)
	mark11ByteValue := make([]byte, 4)
	binary.BigEndian.PutUint32(mark11ByteValue, 11)
	mark50ByteValue := make([]byte, 4)
	binary.BigEndian.PutUint32(mark50ByteValue, 50)
	mark1000ByteValue := make([]byte, 4)
	binary.BigEndian.PutUint32(mark1000ByteValue, 1000)

	tests := map[string]struct {
		table    Table
		filters  []ConnAttr
		rawInstr []bpf.RawInstruction
		err      error
	}{
		"mark positive filter: [1]": {
			table: Conntrack,
			filters: []ConnAttr{
				{Type: AttrMark, Data: mark1ByteValue, Mask: []byte{255, 255, 255, 255}, Negate: false},
			},
			rawInstr: []bpf.RawInstruction{
				//--- check subsys ---
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_IND, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x01, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				//--- check mark ---
				{Op: unix.BPF_LD | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000014},
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000008},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x02, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_MISC | unix.BPF_TAX, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_LD | unix.BPF_W | unix.BPF_IND, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_MISC | unix.BPF_TAX, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x02, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_MISC | unix.BPF_TXA, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				//---- final verdict ----
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
			}},
		"mark positive filter: [10,50,1000]": {
			table: Conntrack,
			filters: []ConnAttr{
				{Type: AttrMark, Data: mark10ByteValue, Mask: []byte{255, 255, 255, 255}, Negate: false},
				{Type: AttrMark, Data: mark50ByteValue, Mask: []byte{255, 255, 255, 255}, Negate: false},
				{Type: AttrMark, Data: mark1000ByteValue, Mask: []byte{255, 255, 255, 255}, Negate: false},
			},
			rawInstr: []bpf.RawInstruction{
				//--- check subsys ---
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_IND, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x01, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				//--- check mark ---
				{Op: unix.BPF_LD | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000014},
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000008},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x02, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_MISC | unix.BPF_TAX, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_LD | unix.BPF_W | unix.BPF_IND, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_MISC | unix.BPF_TAX, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x08, Jf: 0x00, K: 0x0000000a},
				{Op: unix.BPF_MISC | unix.BPF_TXA, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x05, Jf: 0x00, K: 0x00000032},
				{Op: unix.BPF_MISC | unix.BPF_TXA, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x02, Jf: 0x00, K: 0x000003e8},
				{Op: unix.BPF_MISC | unix.BPF_TXA, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				//---- final verdict ----
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
			}},
		"mark negative filter: [10,11]": {
			table: Conntrack, filters: []ConnAttr{
				{Type: AttrMark, Data: mark10ByteValue, Mask: []byte{255, 255, 255, 255}, Negate: true},
				{Type: AttrMark, Data: mark11ByteValue, Mask: []byte{255, 255, 255, 255}, Negate: true},
			},
			rawInstr: []bpf.RawInstruction{
				//--- check subsys ---
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_IND, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x01, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				//--- check mark ---
				{Op: unix.BPF_LD | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000014},
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000008},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x02, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_MISC | unix.BPF_TAX, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_LD | unix.BPF_W | unix.BPF_IND, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_MISC | unix.BPF_TAX, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x05, Jf: 0x00, K: 0x0000000a},
				{Op: unix.BPF_MISC | unix.BPF_TXA, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x02, Jf: 0x00, K: 0x0000000b},
				{Op: unix.BPF_MISC | unix.BPF_TXA, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_JMP | unix.BPF_JA, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				//---- final verdict ----
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
			}},
		"tcp": {
			table: Conntrack,
			filters: []ConnAttr{
				{Type: AttrOrigL4Proto, Data: []byte{0x06}}, // TCP
			},
			rawInstr: []bpf.RawInstruction{
				// ---- check subsys ---
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_IND, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x01, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				// ---- check proto ----
				{Op: unix.BPF_LD | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000014},
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x0c, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_ALU | unix.BPF_ADD | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000002},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x08, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_ALU | unix.BPF_ADD | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x04, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_MISC | unix.BPF_TAX, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_IND, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x01, Jf: 0x00, K: 0x00000006},
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				// ---- final verdict ----
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
			}},
		"tcp or udp": {
			table: Conntrack,
			filters: []ConnAttr{
				{Type: AttrOrigL4Proto, Data: []byte{0x06}}, // TCP
				{Type: AttrOrigL4Proto, Data: []byte{0x11}}, // UDP
			},
			rawInstr: []bpf.RawInstruction{
				// ---- check subsys ---
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_IND, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x01, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				// ---- check proto ----
				{Op: unix.BPF_LD | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000014},
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x0d, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_ALU | unix.BPF_ADD | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000002},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x09, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_ALU | unix.BPF_ADD | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x05, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_MISC | unix.BPF_TAX, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_IND, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x02, Jf: 0x00, K: 0x00000006},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x01, Jf: 0x00, K: 0x00000011},
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				// ---- final verdict ----
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
			},
		},
		"src 127.0.0.1 or src 127.0.0.2 or src 127.0.0.3": {
			table: Conntrack,
			filters: []ConnAttr{
				{Type: AttrOrigIPv4Src, Data: []byte{0x7F, 0x0, 0x0, 0x1}, Mask: []byte{0xff, 0xff, 0xff, 0xff}},
				{Type: AttrOrigIPv4Src, Data: []byte{0x7F, 0x0, 0x0, 0x2}, Mask: []byte{0xff, 0xff, 0xff, 0xff}},
				{Type: AttrOrigIPv4Src, Data: []byte{0x7F, 0x0, 0x0, 0x3}, Mask: []byte{0xff, 0xff, 0xff, 0xff}},
			},
			rawInstr: []bpf.RawInstruction{
				// ---- check subsys ---
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_IND, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x01, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				// ---- check src IPv4 ----
				{Op: unix.BPF_LD | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000014},
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x13, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_ALU | unix.BPF_ADD | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x0f, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_ALU | unix.BPF_ADD | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_LDX | unix.BPF_IMM, Jt: 0x00, Jf: 0x00, K: 0x00000001},
				{Op: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, Jt: 0x00, Jf: 0x00, K: 0xfffff00c},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x0b, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_MISC | unix.BPF_TAX, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				{Op: unix.BPF_LD | unix.BPF_W | unix.BPF_IND, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x07, Jf: 0x00, K: 0x7f000001},
				{Op: unix.BPF_LD | unix.BPF_W | unix.BPF_IND, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x04, Jf: 0x00, K: 0x7f000002},
				{Op: unix.BPF_LD | unix.BPF_W | unix.BPF_IND, Jt: 0x00, Jf: 0x00, K: 0x00000004},
				{Op: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
				{Op: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0x01, Jf: 0x00, K: 0x7f000003},
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0x00000000},
				// ---- final verdict ----
				{Op: unix.BPF_RET | unix.BPF_K, Jt: 0x00, Jf: 0x00, K: 0xffffffff},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rawInstr, err := constructFilter(tc.table, tc.filters)
			if !errors.Is(err, tc.err) {
				t.Fatal(err)
			}
			if len(rawInstr) != len(tc.rawInstr) {
				t.Fatalf("different length:\n- want:\n%s\n-  got:\n%s",
					fmtRawInstructions(tc.rawInstr), fmtRawInstructions(rawInstr))
			}
			var isErr bool
			for i, v := range rawInstr {
				if v != tc.rawInstr[i] {
					t.Errorf("unexpected %d. instruction:\n- want:\n%s\n-  got:\n%s",
						i, fmtRawInstruction(tc.rawInstr[i]), fmtRawInstruction(rawInstr[i]))
					isErr = true
				}
			}

			if isErr {
				t.Fatalf("unexpected reply:\n- want:\n%s\n-  got:\n%s",
					fmtRawInstructions(tc.rawInstr), fmtRawInstructions(rawInstr))
			}
		})
	}
}
