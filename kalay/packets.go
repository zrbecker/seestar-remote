package kalay

import (
	"encoding/binary"
	"net"
)

// IOTC session control packets, built field by field rather than patched into captured
// blobs. Every field below was recovered from captures; the ones whose meaning is still
// unknown are named unknownN and carry the observed constant, since the device rejects
// packets that deviate from what the app sends.

const (
	sessionMagic0 = 0x04
	sessionMagic1 = 0x02
	sessionMagic2 = 0x1d
	sessionMagic3 = 0x02

	sessionHeaderLen = 16
	uidLen           = 20
	tokenLen         = 8
	addrRecordLen    = 16
	knockAddrSlots   = 4
)

// sessionHeader prefixes every 4e6d/knock control packet.
type sessionHeader struct {
	BodyLen uint32 // bytes following this header
	State   byte   // client session state: 01, 02 or 04 on direct packets, 03 on the knock
	Kind    byte   // 0x04 direct, 0x02 knock
	unknown uint16 // 0x0033 direct, 0x0034 knock; purpose unknown, echoed as captured
}

func (h sessionHeader) appendTo(b []byte) []byte {
	b = append(b, sessionMagic0, sessionMagic1, sessionMagic2, sessionMagic3)
	b = binary.LittleEndian.AppendUint32(b, h.BodyLen)
	b = append(b, h.State, h.Kind)
	b = binary.LittleEndian.AppendUint16(b, h.unknown)
	return append(b, 0, 0, 0, 0)
}

// addrRecord is one client address candidate in a knock. The leading 4 bytes are constant
// across every captured record; whether they encode a family, a port or something else is
// unknown, so they are reproduced as observed. An all-zero record is an empty slot.
type addrRecord struct {
	prefix [4]byte // observed 00 00 ed e0
	ip     [4]byte
}

func (a addrRecord) appendTo(b []byte) []byte {
	if a == (addrRecord{}) {
		return append(b, make([]byte, addrRecordLen)...)
	}
	b = append(b, a.prefix[:]...)
	b = append(b, a.ip[:]...)
	return append(b, make([]byte, addrRecordLen-8)...) // trailing 8 bytes always zero
}

// directPacket is a 4e6d session packet: it advances and then holds the session state.
type directPacket struct {
	State byte
	UID   string // 20 chars; the rotating UID from the current online-link
	Token [tokenLen]byte
}

// unknownDirectTrailer closes every captured direct packet. It does not vary with the UID,
// token or state, so it is not a checksum over them, but its meaning is unknown.
var unknownDirectTrailer = [4]byte{0xc6, 0xbe, 0xa0, 0x92}

func (p directPacket) bytes() []byte {
	body := sessionHeaderLen + uidLen + tokenLen + 4 + 4
	out := make([]byte, 0, body)
	out = sessionHeader{
		BodyLen: uint32(body - sessionHeaderLen),
		State:   p.State,
		Kind:    0x04,
		unknown: 0x0033,
	}.appendTo(out)
	out = appendUID(out, p.UID)
	out = append(out, p.Token[:]...)
	out = append(out, 0, 0, 0, 0)
	return append(out, unknownDirectTrailer[:]...)
}

// knockPacket is the rendezvous packet sent to the master. Addrs advertises client address
// candidates; the master relays them to the device for hole-punching.
type knockPacket struct {
	UID   string
	Addrs [knockAddrSlots]addrRecord
	Token [tokenLen]byte
}

// unknownKnockTrailer closes every captured knock. Purpose unknown.
var unknownKnockTrailer = [4]byte{0x02, 0x00, 0x00, 0x00}

func (p knockPacket) bytes() []byte {
	body := sessionHeaderLen + uidLen + knockAddrSlots*addrRecordLen + tokenLen + 4
	out := make([]byte, 0, body)
	out = sessionHeader{
		BodyLen: uint32(body - sessionHeaderLen),
		State:   0x03,
		Kind:    0x02,
		unknown: 0x0034,
	}.appendTo(out)
	out = appendUID(out, p.UID)
	for _, a := range p.Addrs {
		out = a.appendTo(out)
	}
	out = append(out, p.Token[:]...)
	return append(out, unknownKnockTrailer[:]...)
}

// appendUID writes the 20-byte UID slot, zero-padding a short UID rather than truncating
// the packet.
func appendUID(b []byte, uid string) []byte {
	var slot [uidLen]byte
	copy(slot[:], uid)
	return append(b, slot[:]...)
}

// knockAddrPrefix leads every observed address record. Whether it encodes a family, a port
// or something else is unknown.
var knockAddrPrefix = [4]byte{0x00, 0x00, 0xed, 0xe0}

// localIPv4 reports the outbound IPv4 address, or nil. The UDP dial sends nothing; it only
// asks the routing table which source address would be used.
func localIPv4() net.IP {
	c, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.To4()
}
