package kalay

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Outbound reliability. The device retransmits its own stream when we signal a gap, but
// nothing resends OUR client->device frames, so a single dropped frame in a large transfer
// (an upload, or any bulk write over proxy) would stall the stream forever. Go-back-N buffers
// every reliable frame, advances a send base on the device's cumulative 0x46 ACKs, retransmits
// the unacked window on ACK timeout or duplicate ACKs, and gives up if the stream makes no
// progress — so a dead tunnel errors instead of looping. All of this runs on the pump
// goroutine (pump and route), so the state needs no locking.

const (
	gbnGiveUp = 30 * time.Second       // no ACK progress this long means the outbound stream is dead
	rtoMin    = 250 * time.Millisecond // clamp so a bad RTT estimate cannot go haywire
	rtoMax    = 3 * time.Second
	cwndMin   = 4                       // never shrink the congestion window below this many frames
	cwndInit  = 8                       // start conservative and let AIMD grow into the path
)

// maxFrame caps each RDT payload so a DTLS record fits one UDP datagram; sendWindow is the hard
// ceiling on in-flight reliable frames — the AIMD congestion window (cwnd) floats below it. The
// ceiling also bounds the retransmit burst so it cannot flood the relay, and the outbound byte
// buffer. Both are overridable via KALAY_MAX_FRAME / KALAY_SEND_WINDOW; the default ceiling leaves
// AIMD room to find the device's receive-buffer limit, past which throughput collapses.
var (
	maxFrame   = envInt("KALAY_MAX_FRAME", 1024)
	sendWindow = envInt("KALAY_SEND_WINDOW", 256)
)

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// outFrame is one reliable client->device frame kept for possible retransmission.
type outFrame struct {
	typ, b16, conn byte
	payload        []byte
	sentAt         time.Time
	retx           bool
}

// initGoBackN prepares the outbound state at pump start, after setup has advanced txSeq past
// the handshake frames.
func (t *Tunnel) initGoBackN() {
	t.inflight = map[uint64]*outFrame{}
	t.sendBase = t.txSeq
	t.rto = 400 * time.Millisecond
	t.lastReTx = time.Now()
	t.lastProg = time.Now()
	t.cwnd = cwndInit
}

// cwndFrames is the current send window in frames: the AIMD estimate, clamped to [cwndMin,
// sendWindow]. The framing loop sends only while fewer than this many frames are unacked.
func (t *Tunnel) cwndFrames() uint64 {
	w := int(t.cwnd)
	if w < cwndMin {
		w = cwndMin
	}
	if w > sendWindow {
		w = sendWindow
	}
	return uint64(w)
}

// cwndCutHalf halves the congestion window on loss or stall, but only once per RTT so a burst of
// retransmits does not collapse it. Additive-increase/multiplicative-decrease keeps the window near
// the device's receive-buffer limit without the sustained overshoot that stalls the stream.
func (t *Tunnel) cwndCutHalf() {
	if time.Since(t.cwndCut) < t.rto {
		return
	}
	t.cwnd /= 2
	if t.cwnd < cwndMin {
		t.cwnd = cwndMin
	}
	t.cwndCut = time.Now()
}

// sendReliable sends one reliable frame, buffers it, and advances txSeq.
func (t *Tunnel) sendReliable(typ, b16, conn byte, payload []byte) {
	seq := t.txSeq
	t.sendRDT(typ, b16, conn, seq, payload)
	t.inflight[seq] = &outFrame{typ, b16, conn, append([]byte(nil), payload...), time.Now(), false}
	t.txSeq++
	t.lastReTx = time.Now()
}

// ackOutbound processes the device's cumulative ACK of our stream: it frees acknowledged
// frames and, on a repeated ACK that does not advance, fast-retransmits the window.
func (t *Tunnel) ackOutbound(ack uint64) {
	if newBase := ack + 1; newBase > t.sendBase && newBase <= t.txSeq {
		if f := t.inflight[ack]; f != nil && !f.retx { // Karn: sample RTT only from unretransmitted frames
			t.sampleRTT(time.Since(f.sentAt))
		}
		acked := float64(newBase - t.sendBase)
		for s := t.sendBase; s < newBase; s++ {
			delete(t.inflight, s)
		}
		t.sendBase = newBase
		t.lastProg = time.Now()
		t.lastReTx = time.Now()
		t.dupAcks, t.retxRun = 0, 0
		t.cwnd += acked / t.cwnd // additive increase: ~+1 frame per RTT of clean ACKs
	} else if t.sendBase < t.txSeq && ack == t.lastAckSeq {
		if t.dupAcks++; t.dupAcks >= 3 {
			if tunDebug {
				fmt.Fprintf(os.Stderr, "[gbn] dupACK x%d @%d -> fast retransmit [%d,%d)\n", t.dupAcks, ack, t.sendBase, t.txSeq)
			}
			t.resendOldest()
			t.dupAcks = 0
		}
	}
	t.lastAckSeq = ack
}

// sampleRTT folds a round-trip sample into the smoothed estimate (Jacobson/Karels) and
// recomputes the retransmit timeout, clamped to a sane range.
func (t *Tunnel) sampleRTT(s time.Duration) {
	if t.srtt == 0 {
		t.srtt, t.rttvar = s, s/2
	} else {
		d := t.srtt - s
		if d < 0 {
			d = -d
		}
		t.rttvar += (d - t.rttvar) / 4
		t.srtt += (s - t.srtt) / 8
	}
	t.rto = t.srtt + 4*t.rttvar
	if t.rto < rtoMin {
		t.rto = rtoMin
	} else if t.rto > rtoMax {
		t.rto = rtoMax
	}
}

// resendOldest retransmits only the oldest unacked frame — the one blocking the device's
// cumulative ACK. Resending the whole window at once floods the relay, which drops the burst
// and stalls the stream permanently; one frame per timeout lets the device advance without a
// flood. Frames past it may already be buffered at the device.
func (t *Tunnel) resendOldest() {
	if f := t.inflight[t.sendBase]; f != nil {
		t.sendRDT(f.typ, f.b16, f.conn, t.sendBase, f.payload)
		f.retx = true
	}
	t.lastReTx = time.Now()
	t.cwndCutHalf() // a retransmit signals loss or the device's buffer filling: back off
}

// outboundTick retransmits the window on RTO with exponential backoff, and returns an error
// once the stream has made no progress for gbnGiveUp.
func (t *Tunnel) outboundTick() error {
	if t.sendBase >= t.txSeq {
		return nil
	}
	if time.Since(t.lastReTx) > t.rto<<min(t.retxRun, 4) {
		if tunDebug {
			fmt.Fprintf(os.Stderr, "[gbn] RTO resend oldest seq=%d (unacked [%d,%d)) run=%d rto=%s\n", t.sendBase, t.sendBase, t.txSeq, t.retxRun, t.rto)
		}
		t.resendOldest()
		t.retxRun++
	}
	if time.Since(t.lastProg) > gbnGiveUp {
		return fmt.Errorf("kalay: outbound stalled, no ACK progress in %s", gbnGiveUp)
	}
	return nil
}
