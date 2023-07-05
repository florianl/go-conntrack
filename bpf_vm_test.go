package conntrack

import (
	"errors"
	"testing"

	"golang.org/x/net/bpf"
)

// Collection of reusable inputs to test bpf filters against.
var (
	// nlMsg1: UDP - src=192.168.1.105 dst=224.0.0.251
	nlMsg1 = []byte{0x34, 0x00, 0x01, 0x80, 0x14, 0x00, 0x01, 0x80, 0x08, 0x00, 0x01, 0x00, 0xc0, 0xa8, 0x01, 0x69, 0x08, 0x00, 0x02, 0x00, 0xe0, 0x00, 0x00, 0xfb, 0x1c, 0x00, 0x02, 0x80, 0x05, 0x00, 0x01, 0x00, 0x11, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0x14, 0xe9, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x14, 0xe9, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0x1a, 0xfb, 0x54, 0xa9, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x88, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x1e}
)

func TestConstructFilterVM(t *testing.T) {
	t.Skipf("ExtNetlinkAttr and ExtNetlinkAttrNested are currently not implemented in x/net/bpf")

	tests := map[string]struct {
		filters      []ConnAttr
		constructErr error
		runErr       error
		input        []byte
	}{
		"no filters": {input: nlMsg1},
		"tcp-only":   {filters: []ConnAttr{{Type: AttrOrigL4Proto, Data: []byte{0x11}}}, input: nlMsg1},
	}

	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			rawInstrs, constructErr := constructFilter(Conntrack, test.filters)
			if !errors.Is(constructErr, test.constructErr) {
				t.Fatalf("Expected '%v' but got '%v'", test.constructErr, constructErr)
			}
			instrs, _ := bpf.Disassemble(rawInstrs)
			t.Logf("%#v", instrs)
			vm, vmErr := bpf.NewVM(instrs)
			if vmErr != nil {
				t.Fatal(vmErr)
			}

			accepted, runErr := vm.Run(test.input)
			if !errors.Is(runErr, test.runErr) {
				t.Fatalf("Expected '%v' but got '%v'", test.runErr, runErr)
			}

			// TODO: validate result
			_ = accepted
		})
	}
}
