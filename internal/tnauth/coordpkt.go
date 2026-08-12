package tnauth

import (
	"encoding/binary"
	"net"
)

// The 0408 ICE setup, built field by field. Fields whose meaning is unknown are named and
// carry the constants observed in captures, since the relay rejects packets that deviate
// from what the app sends.

const (
	coordHeaderLen = 16
	coordUIDLen    = 20
	coordTokenLen  = 8
	coordAddrLen   = 16
	coordAddrSlots = 29 // the record table runs from the token to the trailer
	coordLen       = 544

	// Address record slots the app populates. The rest are left empty.
	slotLocal    = 0 // client LAN candidates occupy 0..2
	slotReflex   = 4 // client reflexive candidate
	slotDevLan   = 12
	slotDevPublc = 16

	familyNone  = 0x0000 // observed on the LAN candidates
	familyInet4 = 0x0002 // observed on the reflexive and device-public records
)

// Constants observed in every captured 0408 whose purpose is unknown.
var (
	coordUnknown36 = [2]byte{0x01, 0x00}
	coordUnknown50 = [6]byte{0xff, 0xff, 0x02, 0x02, 0x00, 0x02}
	coordUnknown60 = [8]byte{0x03, 0x06, 0x03, 0x04, 0x03, 0x06, 0x03, 0x04}
	coordTrailer   = [4]byte{0x2e, 0x03, 0x00, 0x00}
)

// coordAddr is one address candidate in the 0408 record table.
type coordAddr struct {
	Family uint16
	Port   int
	IP     net.IP
}

func (a coordAddr) appendTo(b []byte) []byte {
	if a.IP == nil {
		return append(b, make([]byte, coordAddrLen)...)
	}
	// The family is little-endian while the port that follows it is big-endian.
	b = binary.LittleEndian.AppendUint16(b, a.Family)
	b = binary.BigEndian.AppendUint16(b, uint16(a.Port))
	b = append(b, a.IP.To4()...)
	return append(b, make([]byte, coordAddrLen-8)...)
}

// coordSetup is the 0408 sent to the relay to authorize the direct punch.
type coordSetup struct {
	UID     []byte
	DevPort int // echoed at [38:40] as well as in the device records
	Token   []byte
	Addrs   [coordAddrSlots]coordAddr
}

func (c coordSetup) bytes() []byte {
	out := make([]byte, 0, coordLen)
	out = append(out, 0x04, 0x02, 0x1d, 0x02)
	out = binary.LittleEndian.AppendUint32(out, coordLen-coordHeaderLen)
	out = append(out, 0x04, 0x08, 0x24, 0x00, 0, 0, 0, 0)

	var uid [coordUIDLen]byte
	copy(uid[:], c.UID)
	out = append(out, uid[:]...)

	out = append(out, coordUnknown36[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(c.DevPort))
	out = append(out, make([]byte, 10)...) // [40:50] always zero
	out = append(out, coordUnknown50[:]...)
	out = append(out, 0, 0, 0, 0) // [56:60] always zero
	out = append(out, coordUnknown60[:]...)

	var tok [coordTokenLen]byte
	copy(tok[:], c.Token)
	out = append(out, tok[:]...)

	for _, a := range c.Addrs {
		out = a.appendTo(out)
	}
	return append(out, coordTrailer[:]...)
}
