//+build !linux

package conntrack_test

import "testing"
import ct "github.com/florianl/go-conntrack"

func TestOthersUnimplemented(t *testing.T) {
	want := ct.ErrNotLinux

	nfct := &ct.Nfct{}

	if _, got := ct.Open(); want != got {
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
