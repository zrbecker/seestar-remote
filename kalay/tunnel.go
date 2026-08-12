package kalay

import "encoding/binary"

// RDT wire frame (20-byte header):
//   5a 97 c2 f1 | type:1 | 05 | paylen:2 LE | seq:8 LE | b16:1 | connId:1 | 00 00 | payload
// Types: 0x01 keepalive, 0x41 SYN, 0x46 ACK, 0x02 data. b16: 0=control, 1=data.

// RDTHdrLen is the fixed RDT frame header length.
const RDTHdrLen = 20

var rdtMagic = [4]byte{0x5a, 0x97, 0xc2, 0xf1}

// RDT frame types.
const (
	RDTKeepalive = 0x01
	RDTSyn       = 0x41
	RDTAck       = 0x46
	RDTData      = 0x02
)

// TunnelChunkMax is the maximum P2PTunnel data-chunk payload size.
const TunnelChunkMax = 0x2000

// RDTPacket is one reliable-transport frame.
type RDTPacket struct {
	Type    byte
	Seq     uint64
	B16     byte
	ConnID  byte
	Payload []byte
}

// AppendRDT appends the wire encoding of p to dst and returns the extended slice.
func AppendRDT(dst []byte, p RDTPacket) []byte {
	var h [RDTHdrLen]byte
	copy(h[0:4], rdtMagic[:])
	h[4] = p.Type
	h[5] = 0x05
	binary.LittleEndian.PutUint16(h[6:8], uint16(len(p.Payload)))
	binary.LittleEndian.PutUint64(h[8:16], p.Seq)
	h[16] = p.B16
	h[17] = p.ConnID
	dst = append(dst, h[:]...)
	return append(dst, p.Payload...)
}

// ParseRDTStream splits a decrypted DTLS app-data payload into its coalesced RDT frames,
// stopping at the first malformed or truncated frame.
func ParseRDTStream(pt []byte) []RDTPacket {
	var out []RDTPacket
	for off := 0; off+RDTHdrLen <= len(pt); {
		if pt[off] != rdtMagic[0] || pt[off+1] != rdtMagic[1] || pt[off+2] != rdtMagic[2] || pt[off+3] != rdtMagic[3] {
			break
		}
		paylen := int(binary.LittleEndian.Uint16(pt[off+6 : off+8]))
		if off+RDTHdrLen+paylen > len(pt) {
			break
		}
		out = append(out, RDTPacket{
			Type:    pt[off+4],
			Seq:     binary.LittleEndian.Uint64(pt[off+8 : off+16]),
			B16:     pt[off+16],
			ConnID:  pt[off+17],
			Payload: append([]byte(nil), pt[off+RDTHdrLen:off+RDTHdrLen+paylen]...),
		})
		off += RDTHdrLen + paylen
	}
	return out
}

// DeframeTunnel extracts the socket byte stream from repeated P2PTunnel data chunks
// (02 01 <len16 LE> <data>, length <= TunnelChunkMax). A byte that does not start a valid
// chunk header is emitted as-is and skipped, so a desynced stream loses only the missing bytes.
func DeframeTunnel(raw []byte) []byte {
	var sock []byte
	for p := 0; p+4 <= len(raw); {
		clen := int(raw[p+2]) | int(raw[p+3])<<8
		if raw[p] == 0x02 && raw[p+1] == 0x01 && clen > 0 && clen <= TunnelChunkMax {
			if p+4+clen > len(raw) {
				clen = len(raw) - p - 4
			}
			sock = append(sock, raw[p+4:p+4+clen]...)
			p += 4 + clen
		} else {
			sock = append(sock, raw[p])
			p++
		}
	}
	return sock
}

// FrameTunnel wraps a socket byte stream into P2PTunnel data chunks of at most chunk bytes,
// with chunk clamped to [1, TunnelChunkMax]. It is the inverse of DeframeTunnel.
func FrameTunnel(sock []byte, chunk int) []byte {
	if chunk <= 0 || chunk > TunnelChunkMax {
		chunk = TunnelChunkMax
	}
	var out []byte
	for i := 0; i < len(sock); i += chunk {
		end := min(i+chunk, len(sock))
		c := sock[i:end]
		out = append(out, 0x02, 0x01, byte(len(c)), byte(len(c)>>8))
		out = append(out, c...)
	}
	return out
}

// PTunMsg is one parsed P2PTunnel message.
type PTunMsg struct {
	Type byte   // 0x02 = data chunk, otherwise a control type
	Chan byte   // data chunks only: channel index
	Data []byte // socket bytes for data chunks, control body otherwise
}

// isPTunCtrl reports whether t is a known P2PTunnel control message type.
func isPTunCtrl(t byte) bool {
	switch t {
	case 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e:
		return true
	}
	return false
}

// PTunDemux parses a growing, ordered P2PTunnel byte stream into messages. Both framings share
// the shape <b0> <b1> <len16 LE> <payload>: a data chunk has b0=0x02 and b1=the channel index
// (nonzero), a control message has b1=0x00 and b0=the control type. Unrecognized bytes are
// skipped one at a time to resync. The consumed offset is retained, so the caller re-feeds the
// same contiguous prefix each call.
type PTunDemux struct{ off int }

// Parse returns the messages newly completed in raw since the last call.
func (d *PTunDemux) Parse(raw []byte) []PTunMsg {
	var out []PTunMsg
	for d.off+4 <= len(raw) {
		b0, b1 := raw[d.off], raw[d.off+1]
		ln := int(raw[d.off+2]) | int(raw[d.off+3])<<8
		switch {
		case b0 == 0x02 && b1 != 0x00 && ln > 0 && ln <= TunnelChunkMax:
			if d.off+4+ln > len(raw) {
				return out // incomplete
			}
			out = append(out, PTunMsg{Type: 0x02, Chan: b1, Data: append([]byte(nil), raw[d.off+4:d.off+4+ln]...)})
			d.off += 4 + ln
		case b1 == 0x00 && isPTunCtrl(b0) && ln <= 0x1000:
			if d.off+4+ln > len(raw) {
				return out
			}
			out = append(out, PTunMsg{Type: b0, Data: append([]byte(nil), raw[d.off+4:d.off+4+ln]...)})
			d.off += 4 + ln
		default:
			d.off++ // resync
		}
	}
	return out
}

// Reassembler reconstructs the ordered byte stream for one connId from RDT data frames supplied
// in any order, tolerating duplicates and gaps, and tracks the highest contiguous sequence for
// cumulative acknowledgement.
type Reassembler struct {
	frames  map[uint64][]byte
	base    uint64 // lowest seq seen (stream start)
	cum     uint64 // highest seq S with all of [base..S] present
	maxSeq  uint64 // highest seq seen
	baseSet bool

	consumed    uint64 // highest seq removed via Take
	consumedSet bool
}

// NewReassembler returns an empty reassembler.
func NewReassembler() *Reassembler { return &Reassembler{frames: map[uint64][]byte{}} }

// Add ingests a data frame and reports whether the sequence number was new.
func (r *Reassembler) Add(seq uint64, payload []byte) bool {
	if r.consumedSet && seq <= r.consumed {
		return false // stale retransmit
	}
	if _, ok := r.frames[seq]; ok {
		return false
	}
	r.frames[seq] = append([]byte(nil), payload...)
	if !r.baseSet {
		r.base, r.maxSeq, r.baseSet = seq, seq, true
	}
	if seq < r.base {
		r.base = seq
	}
	if seq > r.maxSeq {
		r.maxSeq = seq
	}
	c := r.base
	for r.frames[c+1] != nil {
		c++
	}
	r.cum = c
	return true
}

// Take removes and returns the payload for seq, advancing the consumed watermark so later Adds of
// seq or lower are rejected as stale. Reports false if seq is not present.
func (r *Reassembler) Take(seq uint64) ([]byte, bool) {
	p, ok := r.frames[seq]
	if !ok {
		return nil, false
	}
	delete(r.frames, seq)
	if !r.consumedSet || seq > r.consumed {
		r.consumed, r.consumedSet = seq, true
	}
	return p, true
}

// Started reports whether any frame has been received.
func (r *Reassembler) Started() bool { return r.baseSet }

// CumAck returns the highest contiguous sequence (the cumulative-ACK target), or 0 before the
// first frame.
func (r *Reassembler) CumAck() uint64 { return r.cum }

// Base returns the lowest sequence seen.
func (r *Reassembler) Base() uint64 { return r.base }

// MaxSeq returns the highest sequence seen.
func (r *Reassembler) MaxSeq() uint64 { return r.maxSeq }

// Missing returns the sequence numbers absent from the range [base..maxSeq], in order.
func (r *Reassembler) Missing() []uint64 {
	if !r.baseSet {
		return nil
	}
	var out []uint64
	for s := r.base; s <= r.maxSeq; s++ {
		if r.frames[s] == nil {
			out = append(out, s)
		}
	}
	return out
}

// Gapless reports whether every sequence in [base..maxSeq] has been received.
func (r *Reassembler) Gapless() bool { return r.baseSet && r.cum == r.maxSeq }

// Raw returns the concatenated payloads of the contiguous prefix [base..cum], i.e. the tunnel
// byte stream up to the first gap.
func (r *Reassembler) Raw() []byte {
	if !r.baseSet {
		return nil
	}
	var raw []byte
	for s := r.base; s <= r.cum; s++ {
		raw = append(raw, r.frames[s]...)
	}
	return raw
}

// Stream returns the de-framed socket byte stream from the contiguous prefix.
func (r *Reassembler) Stream() []byte { return DeframeTunnel(r.Raw()) }
