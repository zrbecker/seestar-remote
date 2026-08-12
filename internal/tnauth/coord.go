package tnauth

import "net"

// Device coordination through the relay is IOTC-obfuscated plaintext, not the ECDH/GCM channel:
//
//	OUT 0302  client local candidates
//	IN  0103  device address plus an 8-byte session token
//	OUT 0408  ICE setup echoing that token, which authorizes the direct punch
//
// Callers IOTC-obfuscate (EncodePayload) these payloads before sending.

// Coord103 is the parsed device coordination from a 0103 reply.
type Coord103 struct {
	Token   []byte // 8-byte session token to echo in the 0408
	DevIP   net.IP // device public IP
	DevPort int    // device public port (the punch target)
	DevLan  net.IP // device LAN IP
}

// Parse0103 extracts the device address and session token from a de-obfuscated 0103 payload.
// Layout: [16:36]=UID, [36:38]=0200, [38:40]=port, [40:44]=device public IP; the 8-byte token
// ends 8 bytes before the payload end (…<token8> 02000000 <4B>).
func Parse0103(pt []byte) *Coord103 {
	if len(pt) < 44 || pt[8] != 0x01 || pt[9] != 0x03 {
		return nil
	}
	c := &Coord103{
		DevPort: int(pt[38])<<8 | int(pt[39]),
		DevIP:   net.IPv4(pt[40], pt[41], pt[42], pt[43]),
	}
	if len(pt) >= 16 {
		c.Token = append([]byte(nil), pt[len(pt)-16:len(pt)-8]...)
	}
	// The device LAN record repeats the same port with a private IP.
	pb := []byte{pt[38], pt[39]}
	for i := 44; i+6 <= len(pt); i++ {
		if pt[i] == pb[0] && pt[i+1] == pb[1] {
			ip := net.IPv4(pt[i+2], pt[i+3], pt[i+4], pt[i+5])
			if ip.IsPrivate() {
				c.DevLan = ip
				break
			}
		}
	}
	return c
}

// Build0408 returns the de-obfuscated 0408 ICE-setup echoing the 0103 token, with the caller's
// UID and endpoints substituted. The caller EncodePayload()s it before sending to the relay.
func Build0408(uid []byte, c *Coord103, localIP net.IP, localPort int, reflIP net.IP, reflPort int) []byte {
	s := coordSetup{UID: uid}
	if c != nil {
		s.Token = c.Token // the 0103 token must be echoed
		s.DevPort = c.DevPort
		if d4 := c.DevIP.To4(); d4 != nil {
			s.Addrs[slotDevPublc] = coordAddr{familyInet4, c.DevPort, d4}
		}
		if l4 := c.DevLan.To4(); l4 != nil {
			s.Addrs[slotDevLan] = coordAddr{familyNone, c.DevPort, l4}
		}
	}
	if l4 := localIP.To4(); l4 != nil {
		s.Addrs[slotLocal] = coordAddr{familyNone, localPort, l4}
	}
	if r4 := reflIP.To4(); r4 != nil {
		// The captured setup gave the reflexive candidate the local port, not reflPort.
		s.Addrs[slotReflex] = coordAddr{familyInet4, localPort, r4}
	}
	_ = reflPort
	return s.bytes()
}
