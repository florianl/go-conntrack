//+build !linux

package conntrack

import "testing"

func TestOthersUnimplemented(t *testing.T) {
	want := ErrNotLinux

	nfct := &Nfct{}

	if _, got := Open(); want != got {
		t.Fatalf("unexpected error during Open:\n- want: %v\n-  got: %v", want, got)
	}

	if _, got := nfct.Dump(); want != got {
		t.Fatalf("unexpected error during Open:\n- want: %v\n-  got: %v", want, got)
	}

	if _, got := nfct.Flush(); want != got {
		t.Fatalf("unexpected error during Open:\n- want: %v\n-  got: %v", want, got)
	}

	if got := nfct.Close(); want != got {
		t.Fatalf("unexpected error during Open:\n- want: %v\n-  got: %v", want, got)
	}
}
