//+build linux

package conntrack_test

import (
	"reflect"
	"testing"

	ct "github.com/florianl/go-conntrack"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
)

func TestFlush(t *testing.T) {

	wants := []netlink.Message{
		netlink.Message{
			Header: netlink.Header{
				Length: 20,
				// NFNL_SUBSYS_CTNETLINK<<8|IPCTNL_MSG_CT_DELETE
				Type: netlink.HeaderType(1<<8 | 2),
				// NLM_F_REQUEST|NLM_F_ACK
				Flags: netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge,
				// Can and will be ignored
				Sequence: 0,
				// Can and will be ignored
				PID: nltest.PID,
			},
			// nfgen_family=AF_INET, version=NFNETLINK_V0, res_id=htons(0)
			Data: []byte{0x2, 0x0, 0x0, 0x0},
		},
	}

	// Fake a netfilter conntrack connection
	nfct := &ct.Nfct{}
	nfct.Con = nltest.Dial(func(reqs []netlink.Message) ([]netlink.Message, error) {
		if len(reqs) == 0 {
			return nil, nil
		}
		if len(reqs) != 1 {
			t.Fatalf("Expected only one request, got %d", len(reqs))
		}

		// To ignore the Sequence number, we set it to the same value
		wants[0].Header.Sequence = reqs[0].Header.Sequence

		if want, got := reqs, wants; !reflect.DeepEqual(want, got) {
			t.Fatalf("unexpected replies:\n- want: %#v\n-  got: %#v",
				want, got)
		}

		return nil, nil
	})
	defer nfct.Con.Close()

	if err := nfct.Flush(ct.Ct, ct.CtIPv4); err != nil {
		t.Fatal(err)
	}
}
