package kalay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// DTLS 1.2 primitives for the ECDHE_PSK_WITH_CHACHA20_POLY1305 suite (RFC 5489, RFC 7905):
// the TLS 1.2 PRF, record framing, and AEAD nonce/AAD construction.

// PHash is the TLS 1.2 P_hash(secret, seed) expansion (HMAC-SHA256) to n bytes.
func PHash(secret, seed []byte, n int) []byte {
	out := []byte{}
	a := seed
	for len(out) < n {
		h := hmac.New(sha256.New, secret)
		h.Write(a)
		a = h.Sum(nil)
		h = hmac.New(sha256.New, secret)
		h.Write(a)
		h.Write(seed)
		out = append(out, h.Sum(nil)...)
	}
	return out[:n]
}

// PRF is the TLS 1.2 PRF: P_hash(secret, label||seed) to n bytes.
func PRF(secret []byte, label string, seed []byte, n int) []byte {
	return PHash(secret, append([]byte(label), seed...), n)
}

// DTLSRecord is a parsed DTLS record header + body.
type DTLSRecord struct {
	CT    byte
	Epoch uint16
	Seq   uint64 // 48-bit sequence number
	Body  []byte
}

// ParseDTLSRecords splits a datagram into its concatenated DTLS records, stopping at the first
// truncated record.
func ParseDTLSRecords(b []byte) []DTLSRecord {
	var out []DTLSRecord
	for len(b) >= 13 {
		ct := b[0]
		epoch := binary.BigEndian.Uint16(b[3:5])
		seq := uint64(b[5])<<40 | uint64(b[6])<<32 | uint64(b[7])<<24 | uint64(b[8])<<16 | uint64(b[9])<<8 | uint64(b[10])
		l := int(binary.BigEndian.Uint16(b[11:13]))
		if 13+l > len(b) {
			break
		}
		out = append(out, DTLSRecord{ct, epoch, seq, b[13 : 13+l]})
		b = b[13+l:]
	}
	return out
}

// DTLSRecordRaw builds a DTLS 1.2 record (version fe fd) with the given content type, epoch,
// 48-bit sequence and payload.
func DTLSRecordRaw(ct byte, epoch uint16, seq uint64, payload []byte) []byte {
	h := make([]byte, 13)
	h[0] = ct
	h[1], h[2] = 0xfe, 0xfd
	binary.BigEndian.PutUint16(h[3:5], epoch)
	h[5], h[6], h[7], h[8], h[9], h[10] = byte(seq>>40), byte(seq>>32), byte(seq>>24), byte(seq>>16), byte(seq>>8), byte(seq)
	binary.BigEndian.PutUint16(h[11:13], uint16(len(payload)))
	return append(h, payload...)
}

// DTLSHandshakeMsg wraps a handshake body in the DTLS handshake header: type, 24-bit length,
// message_seq, 24-bit fragment offset (always 0), 24-bit fragment length (always the full body).
func DTLSHandshakeMsg(typ byte, msgseq uint16, body []byte) []byte {
	l := len(body)
	m := []byte{typ, byte(l >> 16), byte(l >> 8), byte(l), byte(msgseq >> 8), byte(msgseq), 0, 0, 0, byte(l >> 16), byte(l >> 8), byte(l)}
	return append(m, body...)
}

// PutDTLSSeq overwrites the 48-bit sequence field (bytes 5..10) of a DTLS record header in place.
func PutDTLSSeq(rec []byte, seq uint64) {
	rec[5], rec[6], rec[7] = byte(seq>>40), byte(seq>>32), byte(seq>>24)
	rec[8], rec[9], rec[10] = byte(seq>>16), byte(seq>>8), byte(seq)
}

// AEADNonce builds the 12-byte TLS 1.2 AEAD nonce (RFC 7905 / ChaCha20-Poly1305): the write IV
// XOR the 64-bit record sequence number (epoch<<48 | seq), right-aligned.
func AEADNonce(iv []byte, epoch uint16, seq uint64) []byte {
	n := make([]byte, 12)
	copy(n, iv)
	sn := uint64(epoch)<<48 | seq
	for i := range 8 {
		n[11-i] ^= byte(sn >> (8 * i))
	}
	return n
}

// AEADAAD builds the TLS 1.2 additional-authenticated-data (seq_num||type||version||length).
func AEADAAD(epoch uint16, seq uint64, ct byte, ln int) []byte {
	a := make([]byte, 13)
	binary.BigEndian.PutUint16(a[0:2], epoch)
	a[2], a[3], a[4], a[5], a[6], a[7] = byte(seq>>40), byte(seq>>32), byte(seq>>24), byte(seq>>16), byte(seq>>8), byte(seq)
	a[8] = ct
	a[9], a[10] = 0xfe, 0xfd
	binary.BigEndian.PutUint16(a[11:13], uint16(ln))
	return a
}

// AEADSealer is the sealing subset of cipher.AEAD.
type AEADSealer interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
}

// AEADOpener is the opening subset of cipher.AEAD.
type AEADOpener interface {
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// Seal encrypts a DTLS record payload, deriving the nonce and AAD from iv, epoch, seq and ct.
func Seal(a AEADSealer, iv []byte, epoch uint16, seq uint64, ct byte, pt []byte) []byte {
	return a.Seal(nil, AEADNonce(iv, epoch, seq), pt, AEADAAD(epoch, seq, ct, len(pt)))
}

// Open decrypts a DTLS record payload (ciphertext includes the 16-byte tag).
func Open(a AEADOpener, iv []byte, epoch uint16, seq uint64, ct byte, ctxt []byte) ([]byte, error) {
	return a.Open(nil, AEADNonce(iv, epoch, seq), ctxt, AEADAAD(epoch, seq, ct, len(ctxt)-16))
}
