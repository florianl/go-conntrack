//+build !linux

package conntrack

import "testing"

func TestOthersUnimplemented(t *testing.T) {
	want := ErrNotLinux

	nfct := &Nfct{}

	if _, got := Open(); want != got {
		t.Fatalf("unexpected error during Open:\n- want: %v\n-  got: %v", want, got)
	}

	if _, got := nfct.Dump(0, 0); want != got {
		t.Fatalf("unexpected error during Open:\n- want: %v\n-  got: %v", want, got)
	}

	if got := nfct.Flush(0, 0); want != got {
		t.Fatalf("unexpected error during Open:\n- want: %v\n-  got: %v", want, got)
	}

	if _, got := nfct.Register(nil, 0, 0, nil); want != got {
		t.Fatalf("unexpected error during Open:\n- want: %v\n-  got: %v", want, got)
	}

	if _, got := nfct.RegisterFiltered(nil, 0, 0, nil, nil); want != got {
		t.Fatalf("unexpected error during Open:\n- want: %v\n-  got: %v", want, got)
	}

	if got := nfct.Close(); want != got {
		t.Fatalf("unexpected error during Open:\n- want: %v\n-  got: %v", want, got)
	}
}
