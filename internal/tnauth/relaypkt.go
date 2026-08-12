package tnauth

import "encoding/binary"

// The three relay setup messages, built field by field. They share a 16-byte header and the
// address-record table used by the 0408; only their type codes, their unknown constants and
// their sizes differ. Unknown fields carry the constants observed in captures, since the
// relay rejects packets that deviate from what the app sends.

const (
	setupMagic3 = 0x00 // these use 04 02 1d 00, where session packets use 04 02 1d 02

	type000c = 0x020c
	type1001 = 0x0240
	type1002 = 0x0806

	len000c = 64
	len1001 = 288
	len1002 = 544
)

// Constants observed in every capture whose purpose is unknown.
var (
	unk000cA  = [2]byte{0x3c, 0x00} // at [44:46]
	unk000cB  = [2]byte{0x05, 0x00} // at [48:50]
	unk1001   = [2]byte{0x02, 0x00} // follows the token
	unk1002A  = [2]byte{0x01, 0x00} // at [36:38]
	unk1002B  = [6]byte{0xff, 0xff, 0x02, 0x02, 0x00, 0x03}
	unk1002C  = [8]byte{0x03, 0x06, 0x03, 0x04, 0x00, 0x08, 0x03, 0x04}
	trail1002 = [4]byte{0xfa, 0x01, 0x00, 0x00}
)

// setupHeader writes the 16-byte prefix common to the relay setup messages. The word after
// the type varies per message (0x0024 or 0x0034); its meaning is unknown.
func setupHeader(b []byte, typ, unknown uint16, total int) []byte {
	b = append(b, 0x04, 0x02, 0x1d, setupMagic3)
	b = binary.LittleEndian.AppendUint32(b, uint32(total-coordHeaderLen))
	b = binary.LittleEndian.AppendUint16(b, typ)
	b = binary.LittleEndian.AppendUint16(b, unknown)
	return append(b, 0, 0, 0, 0)
}

func appendUID20(b, uid []byte) []byte {
	var slot [coordUIDLen]byte
	copy(slot[:], uid)
	return append(b, slot[:]...)
}

func appendToken8(b, tok []byte) []byte {
	var slot [coordTokenLen]byte
	copy(slot[:], tok)
	return append(b, slot[:]...)
}

// build000c is the shortest setup message: identity and token only.
func build000c(uid, token []byte) []byte {
	out := setupHeader(make([]byte, 0, len000c), type000c, 0x0024, len000c)
	out = appendUID20(out, uid)
	out = appendToken8(out, token)
	out = append(out, unk000cA[:]...)
	out = append(out, 0, 0)
	out = append(out, unk000cB[:]...)
	return append(out, make([]byte, len000c-len(out))...)
}

// build1001 carries the client's local candidates.
func build1001(uid, token []byte, local coordAddr) []byte {
	out := setupHeader(make([]byte, 0, len1001), type1001, 0x0034, len1001)
	out = appendUID20(out, uid)
	var addrs [4]coordAddr
	addrs[0] = local
	for _, a := range addrs {
		out = a.appendTo(out)
	}
	out = appendToken8(out, token)
	out = append(out, unk1001[:]...)
	return append(out, make([]byte, len1001-len(out))...)
}

// build1002 carries the full candidate set: client local and reflexive, device LAN and
// public. It has the same shape as the 0408 ICE setup.
func build1002(uid, token []byte, devPort int, addrs [coordAddrSlots]coordAddr) []byte {
	out := setupHeader(make([]byte, 0, len1002), type1002, 0x0024, len1002)
	out = appendUID20(out, uid)
	out = append(out, unk1002A[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(devPort))
	out = append(out, make([]byte, 10)...)
	out = append(out, unk1002B[:]...)
	out = append(out, 0, 0, 0, 0)
	out = append(out, unk1002C[:]...)
	out = appendToken8(out, token)
	for _, a := range addrs {
		out = a.appendTo(out)
	}
	return append(out, trail1002[:]...)
}
