package tnauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// 51cc relay coordination against the relay endpoints from the 0201 reply (ParseReply):
// a 0202 handshake answered by 0203, then 0x000c/0x1001/0x1002 setup messages over 0204.
// The relay answers with 0d02/0d03 carrying the device's address, authorizing the subsequent
// direct hole-punch and DTLS to the device.
//
// All 51cc channel messages are AES-128-GCM keyed by ECDH_P256(ephemeral, relay_pub)[:16],
// with the channel nonce from the 0202 and the packet header as AAD (0202: hdr||nonce||SPKI||0x00;
// 0204: the 16-byte header).

// 26-byte DER SubjectPublicKeyInfo prefix for prime256v1, ending at `03 42 00`; followed by the
// 65-byte uncompressed point (04||X||Y) to form the 91-byte SPKI.
var relaySPKIPrefix = mustHex("3059301306072a8648ce3d020106082a8648ce3d030107034200")

// RelayChannel is an established (or in-progress) 51cc relay channel to one relay master.
type RelayChannel struct {
	Z     []byte // ECDH shared secret[:16]
	Nonce []byte // 12-byte channel nonce, sent in the 0202
	Addr  *net.UDPAddr
	Hello []byte // the 0202 handshake packet (re-sent to keep the channel alive)
	seq   uint32
	uid   []byte
}

// Rehandshake re-sends the 0202 to keep the relay channel alive; it must be repeated.
func (c *RelayChannel) Rehandshake(pc net.PacketConn) {
	if c.Hello != nil {
		pc.WriteTo(c.Hello, c.Addr)
	}
}

func gcm(z []byte) cipher.AEAD {
	blk, err := aes.NewCipher(z)
	if err != nil {
		panic(fmt.Sprintf("tnauth: bad AES key (%d bytes): %v", len(z), err))
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		panic(fmt.Sprintf("tnauth: GCM init: %v", err))
	}
	return g
}

// build0202 returns the handshake packet for a fresh ephemeral key against relay pub.
func build0202(relayPub, uid []byte) (*RelayChannel, []byte, error) {
	curve := ecdh.P256()
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	rp, err := curve.NewPublicKey(relayPub)
	if err != nil {
		return nil, nil, err
	}
	z, err := eph.ECDH(rp)
	if err != nil {
		return nil, nil, err
	}
	ch := &RelayChannel{Z: z[:16], Nonce: make([]byte, 12), uid: uid}
	rand.Read(ch.Nonce)
	spki := append(append([]byte(nil), relaySPKIPrefix...), eph.PublicKey().Bytes()...)
	pt := make([]byte, 52) // 0217 hello: 04021d00 24000000 1702 2400 00000000 <id> <UID> zeros
	copy(pt, []byte{0x04, 0x02, 0x1d, 0x00, 0x24, 0, 0, 0, 0x17, 0x02, 0x24, 0, 0, 0, 0, 0})
	rand.Read(pt[16:18])
	copy(pt[20:40], uid)
	pkt := make([]byte, 24+len(spki)+1)
	pkt[0], pkt[1] = 0x51, 0xcc
	pkt[4], pkt[5] = 0x02, 0x02
	binary.LittleEndian.PutUint16(pkt[6:8], uint16(12+len(spki)+1+68))
	copy(pkt[12:24], ch.Nonce)
	copy(pkt[24:], spki)
	pkt = append(pkt, gcm(ch.Z).Seal(nil, ch.Nonce, pt, pkt)...)
	return ch, pkt, nil
}

// Send0204 GCM-wraps an IOTC message as a 0204 data packet and sends it on pc.
func (c *RelayChannel) Send0204(pc net.PacketConn, pt []byte) {
	hdr := make([]byte, 16)
	hdr[0], hdr[1] = 0x51, 0xcc
	hdr[4], hdr[5] = 0x02, 0x04
	binary.LittleEndian.PutUint16(hdr[6:8], uint16(4+len(pt)+16))
	binary.LittleEndian.PutUint32(hdr[12:16], c.seq)
	c.seq++
	pc.WriteTo(append(hdr, gcm(c.Z).Seal(nil, c.Nonce, pt, hdr)...), c.Addr)
}

// Decode decrypts an incoming 0203/0204/0205 51cc packet with this channel's key/nonce.
func (c *RelayChannel) Decode(w []byte) []byte {
	if len(w) < 28 || w[0] != 0x51 {
		return nil
	}
	switch w[5] {
	case 0x03:
		if p, e := gcm(c.Z).Open(nil, c.Nonce, w[12:], w[:12]); e == nil {
			return p
		}
	case 0x04, 0x05:
		if len(w) >= 32 {
			if p, e := gcm(c.Z).Open(nil, c.Nonce, w[16:], w[:16]); e == nil {
				return p
			}
		}
	}
	return nil
}

// SetupMessages returns the 0x000c/0x1001/0x1002 setup messages with the given UID, local and
// reflexive endpoints, device address, and a session token substituted in.
func SetupMessages(uid []byte, token []byte, localIP net.IP, localPort int, reflIP net.IP, reflPort int, devIP net.IP, devPort int) [][]byte {
	local := coordAddr{Family: familyNone, Port: localPort, IP: localIP.To4()}
	var addrs [coordAddrSlots]coordAddr
	addrs[slotLocal] = local
	if r4 := reflIP.To4(); r4 != nil {
		addrs[slotReflex] = coordAddr{familyInet4, reflPort, r4}
	}
	if d4 := devIP.To4(); d4 != nil {
		addrs[slotDevPublc] = coordAddr{familyInet4, devPort, d4}
	}
	// The device's LAN address is not known here, so that slot is left empty; the captured
	// template carried a stale one.
	return [][]byte{
		build000c(uid, token),
		build1001(uid, token, local),
		build1002(uid, token, devPort, addrs),
	}
}

// Coordinate runs the 0202->0203 relay handshake against one relay endpoint on pc, returning the
// established channel. The caller then sends setup messages (SetupMessages) over it and keeps it
// alive.
func Coordinate(pc net.PacketConn, ep RelayEndpoint, uid []byte) (*RelayChannel, error) {
	ch, pkt, err := build0202(ep.ECDHPub, uid)
	if err != nil {
		return nil, err
	}
	ch.Addr = &net.UDPAddr{IP: ep.IP, Port: ep.Port}
	ch.Hello = pkt
	buf := make([]byte, 4096)
	got := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !got {
		pc.WriteTo(pkt, ch.Addr)
		pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		for {
			n, _, e := pc.ReadFrom(buf)
			if e != nil {
				break
			}
			if n > 20 && buf[0] == 0x51 && buf[5] == 0x03 {
				if p := ch.Decode(buf[:n]); p != nil {
					got = true
					break
				}
			}
		}
	}
	if !got {
		return nil, errFmt("relay 0202", nil)
	}
	return ch, nil
}

func errFmt(what string, err error) error {
	if err != nil {
		return &relayErr{what + ": " + err.Error()}
	}
	return &relayErr{what}
}

type relayErr struct{ s string }

func (e *relayErr) Error() string { return e.s }
