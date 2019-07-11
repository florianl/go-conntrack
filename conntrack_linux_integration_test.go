//+build integration,linux

package conntrack

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

/*
 * returns 0, if both contain the same values
 * returns -1, if size differs
 * returns >0, the position, on which the values are different
 */
func compare(a, b []byte) int {
	var diff = 1
	if len(a) != len(b) {
		return -1
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return diff
		}
		diff++
	}
	return 0
}

func TestLinuxConntrackUpdatePing(t *testing.T) {
	// ping is needed to create a session, we can work with
	_, err := exec.LookPath("ping")
	if err != nil {
		t.Fatalf("Could not find ping binary")
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Create a session
	cmd := exec.CommandContext(ctx, "ping", "127.0.0.2")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Could not start ping to 127.0.0.2: %v", err)
	}
	defer cancel()

	// Give the kernel some time, to track the session
	time.Sleep(2 * time.Second)

	nfct, err := Open(&Config{})
	if err != nil {
		t.Fatalf("Could not open socket: %v", err)
	}
	defer nfct.Close()

	conns, err := nfct.Dump(Ct, CtIPv4)
	if err != nil {
		t.Fatalf("Could not dump sessions: %v", err)
	}

	var attrs []ConnAttr
	var oldMark []byte

	for _, c := range conns {
		if compare(c[AttrOrigIPv4Dst], []byte{127, 0, 0, 2}) == 0 {
			attrs = append(attrs,
				ConnAttr{Type: AttrOrigIPv4Src, Data: c[AttrOrigIPv4Src]},
				ConnAttr{Type: AttrOrigIPv4Dst, Data: c[AttrOrigIPv4Dst]},
				ConnAttr{Type: AttrOrigL4Proto, Data: c[AttrOrigL4Proto]},
				ConnAttr{Type: AttrIcmpType, Data: []byte{8}},
				ConnAttr{Type: AttrIcmpCode, Data: []byte{0}},
				ConnAttr{Type: AttrIcmpID, Data: c[AttrIcmpID]},
			)
			oldMark = c[AttrMark]
			break
		}
	}

	if len(attrs) == 0 {
		t.Fatalf("Could not get ping session from dump")
	}

	// Set a new mark
	attrs = append(attrs, ConnAttr{Type: AttrMark, Data: []byte{0xAA, 0xFF, 0xAA, 0xFF}})

	// Update the conntrack entry
	if err := nfct.Update(Ct, CtIPv4, attrs); err != nil {
		t.Fatalf("Could not update conntrack entry: %v", err)
	}
	attrs = attrs[:len(attrs)-1]

	c, err := nfct.Get(Ct, CtIPv4, attrs)
	if err != nil {
		t.Fatalf("Could not get session: %v", err)
	}
	if len(c) != 1 {
		t.Fatalf("Could not find unique ping sessiond")
	}

	var newMark []byte
	if _, ok := c[0][AttrMark]; ok {
		newMark = c[0][AttrMark]
	}

	if compare(oldMark, newMark) == 0 {
		t.Fatalf("Mark has not been updated")
	}
}

func TestLinuxConntrackDeleteEntry(t *testing.T) {
	// ping is needed to create a session, we can work with
	_, err := exec.LookPath("ping")
	if err != nil {
		t.Fatalf("Could not find ping binary")
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Create a session
	cmd := exec.CommandContext(ctx, "ping", "-i 2", "127.0.0.4")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Could not start ping to 127.0.0.4: %v", err)
	}
	defer cancel()

	// Give the kernel some time, to track the session
	time.Sleep(3 * time.Second)

	nfct, err := Open(&Config{})
	if err != nil {
		t.Fatalf("Could not open socket: %v", err)
	}
	defer nfct.Close()

	conns, err := nfct.Dump(Ct, CtIPv4)
	if err != nil {
		t.Fatalf("Could not dump sessions: %v", err)
	}

	origSessID := []byte{}

	for _, c := range conns {
		if compare(c[AttrOrigIPv4Dst], []byte{127, 0, 0, 4}) == 0 && compare(c[AttrIcmpType], []byte{8}) == 0 {
			sess := []ConnAttr{
				{Type: AttrOrigIPv4Dst, Data: c[AttrOrigIPv4Dst]},
				{Type: AttrOrigIPv4Src, Data: c[AttrOrigIPv4Src]},
				{Type: AttrOrigL4Proto, Data: c[AttrOrigL4Proto]},
				{Type: AttrIcmpType, Data: []byte{8}},
				{Type: AttrIcmpCode, Data: []byte{0}},
				{Type: AttrIcmpID, Data: c[AttrIcmpID]},
			}
			origSessID = c[AttrID]
			if err := nfct.Delete(Ct, CtIPv4, sess); err != nil {
				t.Fatalf("Could not delete session: %v", err)
			}
			break
		}
	}

	// there will be a session for the ping, as it is still running.
	// But as we deleted the original session, there has to be a new AttrID
	conns2, err2 := nfct.Dump(Ct, CtIPv4)
	if err2 != nil {
		t.Fatalf("Could not dump sessions: %v", err)
	}

	for _, c := range conns2 {
		if compare(c[AttrOrigIPv4Dst], []byte{127, 0, 0, 4}) == 0 {
			if compare(c[AttrID], origSessID) == 0 {
				t.Fatalf("Original ping session was not deleted")
			}
		}
	}
}
