//+build integration,linux

package conntrack

import (
	"context"
	"net"
	"os/exec"
	"testing"
	"time"
)

func TestLinuxConntrackUpdatePing(t *testing.T) {
	// ping is needed to create a session, we can work with
	_, err := exec.LookPath("ping")
	if err != nil {
		t.Fatalf("could not find ping binary")
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Create a session
	cmd := exec.CommandContext(ctx, "ping", "127.0.0.2")
	if err := cmd.Start(); err != nil {
		t.Fatalf("could not start ping to 127.0.0.2: %v", err)
	}
	defer cancel()

	// Give the kernel some time, to track the session
	time.Sleep(2 * time.Second)

	nfct, err := Open(&Config{})
	if err != nil {
		t.Fatalf("could not open socket: %v", err)
	}
	defer nfct.Close()

	cons, err := nfct.Dump(Conntrack, IPv4)
	if err != nil {
		t.Fatalf("could not dump sessions: %v", err)
	}

	var pingSession Con
	for _, c := range cons {
		if c.Origin == nil || c.Origin.Proto == nil || c.Origin.Proto.Number == nil || *c.Origin.Proto.Number != 1 {
			continue
		}
		if (*c.Origin.Src).Equal(net.ParseIP("127.0.0.1")) && (*c.Origin.Dst).Equal(net.ParseIP("127.0.0.2")) {
			pingSession = c
			break
		}
	}

	origMark := *pingSession.Mark

	*pingSession.Mark = 0xFF00AA11

	// Update the conntrack entry
	if err := nfct.Update(Conntrack, IPv4, pingSession); err != nil {
		t.Fatalf("could not update conntrack entry: %v", err)
	}

	c, err := nfct.Get(Conntrack, IPv4, pingSession)
	if err != nil {
		t.Fatalf("could not get session: %v", err)
	}

	if len(c) != 1 {
		t.Fatalf("could not get updated session")
	}

	if origMark == *c[0].Mark {
		t.Fatalf("could not update mark of the session")
	}
	t.Logf("original mark 0x%x vs modified mark 0x%x\n", origMark, *c[0].Mark)
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

	conns, err := nfct.Dump(Conntrack, IPv4)
	if err != nil {
		t.Fatalf("Could not dump sessions: %v", err)
	}

	var origConntrackID uint32

	for _, c := range conns {
		if c.Origin == nil || c.Origin.Proto == nil || c.Origin.Proto.Number == nil || *c.Origin.Proto.Number != 1 {
			continue
		}
		if (*c.Origin.Src).Equal(net.ParseIP("127.0.0.1")) && (*c.Origin.Dst).Equal(net.ParseIP("127.0.0.4")) {
			origConntrackID = *c.ID
			if err := nfct.Delete(Conntrack, IPv4, c); err != nil {
				t.Fatalf("could not delete session: %v", err)
			}
			break
		}
	}

	// there will be a session for the ping, as it is still running.
	// But as we deleted the original session, there has to be a new AttrID
	conns2, err2 := nfct.Dump(Conntrack, IPv4)
	if err2 != nil {
		t.Fatalf("could not dump sessions: %v", err)
	}

	for _, c := range conns2 {
		if (*c.Origin.Src).Equal(net.ParseIP("127.0.0.1")) && (*c.Origin.Dst).Equal(net.ParseIP("127.0.0.4")) {
			if *c.ID == origConntrackID {
				t.Fatalf("original ping session was not deleted")
			}
		}
	}
}
