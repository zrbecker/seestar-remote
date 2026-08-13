package kalay

import (
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// countConn is a net.PacketConn that counts and discards writes, so a Tunnel can exercise the
// send path without a real device.
type countConn struct{ writes int }

func (c *countConn) WriteTo(p []byte, _ net.Addr) (int, error) { c.writes++; return len(p), nil }
func (c *countConn) ReadFrom(p []byte) (int, net.Addr, error)  { return 0, nil, net.ErrClosed }
func (c *countConn) Close() error                              { return nil }
func (c *countConn) LocalAddr() net.Addr                       { return testAddr{} }
func (c *countConn) SetDeadline(time.Time) error               { return nil }
func (c *countConn) SetReadDeadline(time.Time) error           { return nil }
func (c *countConn) SetWriteDeadline(time.Time) error          { return nil }

type testAddr struct{}

func (testAddr) Network() string { return "test" }
func (testAddr) String() string  { return "test" }

func testTunnel() (*Tunnel, *countConn) {
	aead, _ := chacha20poly1305.New(make([]byte, 32))
	c := &countConn{}
	t := &Tunnel{
		cAEAD:    aead,
		clientIV: make([]byte, 12),
		sess:     &Session{token: make([]byte, 8), pc: c, dev: testAddr{}},
		txSeq:    3,
	}
	return t, c
}

func TestGoBackNAckAdvancesAndFrees(t *testing.T) {
	tn, c := testTunnel()
	tn.initGoBackN()
	base := tn.sendBase
	for i := 0; i < 5; i++ {
		tn.sendReliable(0x02, 0x01, 0, []byte{byte(i)})
	}
	if tn.txSeq != base+5 || len(tn.inflight) != 5 || c.writes != 5 {
		t.Fatalf("after 5 sends: txSeq=%d inflight=%d writes=%d", tn.txSeq, len(tn.inflight), c.writes)
	}
	// Device reports the highest contiguous seq it received is base+1: frees base and base+1.
	tn.ackOutbound(base + 1)
	if tn.sendBase != base+2 || len(tn.inflight) != 3 {
		t.Fatalf("after ack: sendBase=%d inflight=%d", tn.sendBase, len(tn.inflight))
	}
	if tn.srtt == 0 {
		t.Error("RTT was not sampled on ack")
	}
	// Full ack empties the window.
	tn.ackOutbound(tn.txSeq - 1)
	if tn.sendBase != tn.txSeq || len(tn.inflight) != 0 {
		t.Fatalf("after full ack: sendBase=%d txSeq=%d inflight=%d", tn.sendBase, tn.txSeq, len(tn.inflight))
	}
	if err := tn.outboundTick(); err != nil {
		t.Errorf("tick with nothing in flight: %v", err)
	}
}

func TestGoBackNFastRetransmitOnDupAck(t *testing.T) {
	tn, c := testTunnel()
	tn.initGoBackN()
	base := tn.sendBase
	for i := 0; i < 4; i++ {
		tn.sendReliable(0x02, 0x01, 0, []byte{byte(i)})
	}
	tn.ackOutbound(base) // advance once; frees base, sets lastAckSeq
	sent := c.writes
	tn.ackOutbound(base) // dup 1
	tn.ackOutbound(base) // dup 2
	if c.writes != sent {
		t.Fatal("retransmitted before 3 dup acks")
	}
	tn.ackOutbound(base) // dup 3 -> resend the single oldest unacked frame
	if c.writes != sent+1 {
		t.Fatalf("fast retransmit sent %d frames, want 1 (oldest only)", c.writes-sent)
	}
}

func TestGoBackNRTORetransmitAndGiveUp(t *testing.T) {
	tn, c := testTunnel()
	tn.initGoBackN()
	tn.sendReliable(0x02, 0x01, 0, []byte{1})
	sent := c.writes
	// No ACK: force the RTO to have elapsed and tick.
	tn.lastReTx = time.Now().Add(-time.Second)
	if err := tn.outboundTick(); err != nil {
		t.Fatalf("unexpected give-up: %v", err)
	}
	if c.writes != sent+1 || tn.retxRun != 1 {
		t.Fatalf("RTO retransmit: writes=%d retxRun=%d", c.writes-sent, tn.retxRun)
	}
	// No progress for longer than the give-up deadline -> error.
	tn.lastProg = time.Now().Add(-gbnGiveUp - time.Second)
	if err := tn.outboundTick(); err == nil {
		t.Fatal("expected give-up error after no ACK progress")
	}
}
