package kalay

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/zrbecker/seestar-remote/internal/tnauth"
)

const (
	directStateOff  = 8 // session state byte (client 01->02, device ->04)
	deviceConnState = 0x04
)

// buildDirect builds a 4e6d session packet with the given client state byte and token,
// stamped with P2PDeviceUID.
func buildDirect(state byte, token []byte, uid string) []byte {
	p := directPacket{State: state, UID: uid}
	copy(p.Token[:], token)
	// The state-04 CONNECTED ACK carries the token with its first byte incremented;
	// states 01/02 carry the raw token.
	if state == deviceConnState {
		p.Token[0]++
	}
	return EncodePayload(p.bytes())
}

// buildKnock builds the rendezvous packet for the master, advertising this host's address
// as a hole-punch candidate.
func buildKnock(token []byte, uid string) []byte {
	p := knockPacket{UID: uid}
	copy(p.Token[:], token)
	if ip := localIPv4(); ip != nil {
		p.Addrs[0] = addrRecord{prefix: knockAddrPrefix, ip: [4]byte(ip)}
	}
	return EncodePayload(p.bytes())
}

// buildRDTControl builds an IOTC RDT control packet on internal channel 0x0a, the reliable-data
// control channel distinct from the 0x0b data channel. The device accepts DTLS data only after
// this handshake: 1704 (SYN) then 2704 (data/ack), each carrying an 8-byte connection value that
// the device echoes in its 2804 ack. Flags 0x2100 mark TX (client->device). Returns the
// whole-obfuscated 24-byte wire packet.
func buildRDTControl(mtHi, mtLo byte, value []byte) []byte {
	d := []byte{0x04, 0x02, 0x1d, 0x0a, 0x08, 0x00, 0x00, 0x00, mtHi, mtLo, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00}
	d = append(d, value[:8]...)
	return EncodePayload(d)
}

// rdtValueBump returns value with its first byte incremented, the 1704->2704 transform.
func rdtValueBump(value []byte) []byte {
	v := append([]byte(nil), value[:8]...)
	v[0]++
	return v
}

// DeviceIdentity is the per-device P2P identity taken from an online-link response.
// It is passed per Dial rather than held globally so separate devices can be reached
// concurrently.
type DeviceIdentity struct {
	UID     string // rotates per online-link call; stamped into the rendezvous packets
	Sn      string // device serial
	ConID   string // online-link connection id; if set, its first 8 bytes seed the relay token
	AuthKey string // Kalay authkey derived from the licence (tnauth.DeriveAuthKey)
}

var (
	authMasters = []string{
		"139.162.174.232:10240", "47.107.189.8:10240", "34.131.220.207:10240",
		"34.80.133.17:10240", "45.79.40.130:10240",
	}
)

// deviceState reads the session-state byte from a decoded device 4e6d packet (or 0).
func deviceState(wire []byte) byte {
	c := DecodePayload(wire)
	if len(c) <= directStateOff {
		return 0
	}
	return c[directStateOff]
}

// Session is an established IOTC P2P session to a device, presented as a net.PacketConn.
// Each write frames one payload (RDT + IOTC obfuscation) to the device; each read returns
// one deframed DTLS record's worth of bytes.
type Session struct {
	pc     net.PacketConn
	dev    net.Addr
	master net.Addr
	token  []byte // 8-byte P2P session token

	stopKA     chan struct{}          // stops the keepalive loop
	txSeq      uint16                 // data sequence number (header offset 6-7)
	knockPkt   []byte                 // KNOCK, to the master
	directPkt  []byte                 // 4e6d state 01, to the device
	directPkt2 []byte                 // 4e6d state 02
	directPkt4 []byte                 // 4e6d state 04 (CONNECTED ACK)
	preWire    []byte                 // 51cc 0201 auth precheck
	preAddrs   []net.Addr             // the :10240 auth-masters
	relayChans []*tnauth.RelayChannel // established relay coordination channels
	relaySetup [][]byte               // setup messages resent on each relay channel
	stunWire   []byte                 // 0x8003 STUN binding sent to the relays
	stunAddrs  []net.Addr             // relay addresses to keep STUN-binding
	kaTick     int

	// Plaintext device-coordination state: each relay 0103 (device addr + session token) is
	// answered with a 0408 ICE setup echoing the token, which authorizes the direct DTLS.
	coordUID                      []byte
	coordLocalIP, coordReflIP     net.IP
	coordLocalPort, coordReflPort int
	coordSeen                     int

	rdtVal []byte // 8-byte RDT connection value; keepalive resends the 2704 ack with it

	lastRxNano int64 // UnixNano of the last packet received from the device; drives liveness detection

	// Trace, if set, is called with each framed DTLS record in each direction ("TX"/"RX").
	Trace func(dir string, data []byte)

	// OnRaw, if set, is called with every raw IOTC packet received from the device,
	// of all types, before filtering.
	OnRaw func(pkt []byte)
}

// keepalive keeps the P2P session and NAT mapping alive until Close. The device expects a
// steady stream of 4e6d session packets interleaved with data, and drops the session,
// ignoring subsequent data, if the client goes quiet.
func (s *Session) keepalive() {
	t := time.NewTicker(150 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-s.stopKA:
			return
		case <-t.C:
			// Post-connect the device requires state-04 (CONNECTED ACK) or it rejects data
			// with 15feff, so 04 is the primary keepalive; occasional 01/02 keep the NAT
			// mapping and session pinned.
			s.kaTick++
			pkt := s.directPkt4
			if pkt == nil {
				pkt = s.directPkt
			}
			switch {
			case s.kaTick%5 == 0 && s.directPkt2 != nil:
				pkt = s.directPkt2
			case s.kaTick%5 == 2:
				pkt = s.directPkt
			}
			s.pc.WriteTo(pkt, s.dev)
			// The RDT reliable-data channel must stay open, or the device rejects DTLS data
			// with 15feff.
			if s.rdtVal != nil {
				s.pc.WriteTo(buildRDTControl(0x27, 0x04, rdtValueBump(s.rdtVal)), s.dev)
			}
			if s.master != nil {
				s.pc.WriteTo(s.knockPkt, s.master) // keeps the master cueing the device
			}
			// The 0201 precheck keeps the authorization live for the whole session, at
			// roughly 1/sec rather than every tick.
			if s.kaTick%7 == 0 {
				for _, a := range s.preAddrs {
					s.pc.WriteTo(s.preWire, a)
				}
				// The relay bridges only while its STUN mapping stays alive.
				for _, a := range s.stunAddrs {
					s.pc.WriteTo(s.stunWire, a)
				}
				// The relay channel stays fresh only if the 0202 is re-handshaked and the
				// setup resent.
				for _, ch := range s.relayChans {
					ch.Rehandshake(s.pc)
					for _, m := range s.relaySetup {
						ch.Send0204(s.pc, m)
					}
				}
			}
		}
	}
}

// DialResult reports what Dial established.
type DialResult struct {
	Device net.Addr
	Token  []byte
}

// Dial performs rendezvous and NAT hole-punch against a Kalay master and returns an
// established Session. One socket is used throughout so the master learns the port the
// device must punch back to.
func Dial(master string, dev DeviceIdentity) (*Session, *DialResult, error) {
	masterAddr, err := net.ResolveUDPAddr("udp", master)
	if err != nil {
		return nil, nil, err
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, nil, err
	}
	buf := make([]byte, 4096)

	// A fresh session token makes the device build clean DTLS state; a reused one leaves
	// it with stale state.
	token := make([]byte, 8)
	rand.Read(token)
	knockPkt := buildKnock(token, dev.UID)
	direct1 := buildDirect(1, token, dev.UID) // hole-punch / initial state
	direct2 := buildDirect(2, token, dev.UID) // advances the device to the connected state (04)
	direct4 := buildDirect(4, token, dev.UID) // CONNECTED ACK, sent once the device is at 04

	directPkt := direct1

	// 0) AUTH: a 51cc type-0201 precheck, an RSA-2048-wrapped credential blob (UID + authkey)
	// built from the device serial, authorizes the connection with the :10240 auth-masters.
	// Without it the device rejects DTLS data with a constant 15-byte "not authorized" reply.
	// This is a raw 51cc message, not an IOTC 4e6d packet, so it is sent unobfuscated.
	preWire, preSessKey, preNonce, err := tnauth.BuildPrecheck0201Ex(dev.UID, dev.AuthKey)
	if err != nil {
		pc.Close()
		return nil, nil, errFmt("build precheck", err)
	}
	var preReply []byte // master's 0201 reply, AES-GCM under preSessKey/preNonce
	preAddrs := make([]net.Addr, 0, len(authMasters))
	for _, m := range authMasters {
		if a, e := net.ResolveUDPAddr("udp", m); e == nil {
			preAddrs = append(preAddrs, a)
		}
	}
	// Throttle: the rendezvous loops read one packet per iteration and the masters flood
	// replies, so an ungated sendPrecheck spins tens of thousands of times.
	var lastPre, lastKnock time.Time
	sendPrecheck := func() {
		if time.Since(lastPre) < 250*time.Millisecond {
			return
		}
		lastPre = time.Now()
		for _, a := range preAddrs {
			pc.WriteTo(preWire, a)
		}
	}
	sendKnock := func() {
		if time.Since(lastKnock) < 250*time.Millisecond {
			return
		}
		lastKnock = time.Now()
		pc.WriteTo(knockPkt, masterAddr)
	}
	sendPrecheck()

	// 1) Rendezvous: collect authorized device-address candidates. The precheck makes the
	// auth-masters reply PRECHECK1_R (4e26) with the device's authorized addresses, and the KNOCK
	// master replies with more. Only public, non-master addresses are usable; an unauthorized
	// address yields 15feff.
	masterIPs := map[string]bool{"43.130.61.154": true}
	if h, _, e := net.SplitHostPort(master); e == nil {
		masterIPs[h] = true
	}
	for _, m := range authMasters {
		if h, _, e := net.SplitHostPort(m); e == nil {
			masterIPs[h] = true
		}
	}
	candSet := map[string]bool{}
	collectUntil := time.Now().Add(3 * time.Second)
	for time.Now().Before(collectUntil) {
		sendPrecheck()
		sendKnock()
		pc.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		// The :10240 master's 0201 reply carries the relay endpoints.
		if n >= 300 && buf[0] == 0x51 && buf[4] == 0x02 && buf[5] == 0x01 && preReply == nil {
			preReply = append([]byte(nil), buf[:n]...)
		}
		dec := DecodePayload(buf[:n])
		if len(dec) < 36 || dec[0] != 0x04 || dec[1] != 0x02 {
			continue
		}
		for _, a := range ParseAddrRecords(dec[16:]) {
			ua, e := net.ResolveUDPAddr("udp", a.String())
			if e != nil || ua.Port == 0 || ua.IP.IsUnspecified() || ua.IP.IsPrivate() || masterIPs[ua.IP.String()] {
				continue
			}
			candSet[ua.String()] = true
		}
	}
	if len(candSet) == 0 {
		pc.Close()
		return nil, nil, errors.New("rendezvous: no authorized device candidates")
	}
	var cands []*net.UDPAddr
	for s := range candSet {
		if a, e := net.ResolveUDPAddr("udp", s); e == nil {
			cands = append(cands, a)
		}
	}
	fmt.Printf("  [authorized device candidates: %v]\n", cands)

	// 1b) Relay coordination: after the 0201 precheck, an ECDH-keyed 51cc channel to the relay
	// masters (0202->0203, then 0x000c/0x1001/0x1002 over 0204) coordinates the connection with
	// the device, which replies 0d02/0d03 with the device address. This authorizes the subsequent
	// direct DTLS; without it the device returns 15feff.
	var relayChans []*tnauth.RelayChannel
	var relaySetup [][]byte
	var stunWire []byte
	var stunAddrs []net.Addr
	// Hoisted so the hole-punch phase can complete the plaintext device coordination: a relay
	// 0103 (device address + session token) is answered with a 0408 setup echoing the token.
	var coordUID []byte
	var coordLocalIP, coordReflIP net.IP
	var coordLocalPort, coordReflPort int
	if preReply != nil {
		if rpt, e := tnauth.DecodeReply(preReply, preSessKey, preNonce); e == nil {
			eps := tnauth.ParseReply(rpt)
			uid := append([]byte(nil), rpt[20:40]...)
			local := pc.LocalAddr().(*net.UDPAddr)
			// pc may be bound to ::, so the real outbound IPv4 is needed for the local
			// address record.
			localIP := local.IP
			if localIP.To4() == nil {
				if c, e := net.Dial("udp", "8.8.8.8:80"); e == nil {
					localIP = c.LocalAddr().(*net.UDPAddr).IP
					c.Close()
				}
			}
			reflIP := net.IPv4(rpt[60], rpt[61], rpt[62], rpt[63])
			reflPort := int(rpt[58])<<8 | int(rpt[59])
			coordUID, coordLocalIP, coordLocalPort = uid, localIP, local.Port
			// A 0x8003 STUN bind to each relay before setup gives the relay a NAT mapping so it
			// will bridge. Its 0x8004 reply carries the reflexive address as the relay sees it,
			// which is what the setup must advertise.
			stunDec := append([]byte{0x04, 0x02, 0x1d, 0x02, 0x08, 0, 0, 0, 0x03, 0x80, 0x3f, 0x00, 0, 0, 0, 0},
				0xc5, 0xb8, 0xa3, 0x96, 0x05, 0x10, 0xc8, 0x2c)
			stunWire = EncodePayload(stunDec)
			stunAddrs = nil
			for _, ep := range eps {
				stunAddrs = append(stunAddrs, &net.UDPAddr{IP: ep.IP, Port: ep.Port})
			}
			sbuf := make([]byte, 1024)
			sdl := time.Now().Add(2 * time.Second)
			gotStun := false
			for time.Now().Before(sdl) && !gotStun {
				for _, a := range stunAddrs {
					pc.WriteTo(stunWire, a)
				}
				pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				for {
					n, _, e := pc.ReadFrom(sbuf)
					if e != nil {
						break
					}
					dd := DecodePayload(sbuf[:n])
					if len(dd) >= 24 && dd[0] == 0x04 && dd[8] == 0x04 && dd[9] == 0x80 { // 0x8004
						reflIP = net.IPv4(dd[20], dd[21], dd[22], dd[23])
						reflPort = int(dd[18])<<8 | int(dd[19])
						gotStun = true
						break
					}
				}
			}
			fmt.Printf("  [relay STUN reflexive: %v:%d (ok=%v)]\n", reflIP, reflPort, gotStun)
			coordReflIP, coordReflPort = reflIP, reflPort
			// The device's punched address is the first public candidate.
			var devIP net.IP
			var devPort int
			for _, c := range cands {
				if !c.IP.IsPrivate() {
					devIP, devPort = c.IP, c.Port
					break
				}
			}
			tok := make([]byte, 8)
			rand.Read(tok)
			if cb, e := hex.DecodeString(dev.ConID); e == nil && len(cb) >= 8 {
				copy(tok, cb[:8]) // seeds the relay token from the conId
			}
			relaySetup = tnauth.SetupMessages(uid, tok, localIP, local.Port, reflIP, reflPort, devIP, devPort)
			fmt.Printf("  [relay: refl=%v:%d dev=%v:%d eps=%d]\n", reflIP, reflPort, devIP, devPort, len(eps))
			for _, ep := range eps {
				fmt.Printf("    relay ep %v:%d pub=%x\n", ep.IP, ep.Port, ep.ECDHPub[:6])
				ch, e := tnauth.Coordinate(pc, ep, uid)
				if e != nil {
					continue
				}
				fmt.Printf("    ch Z=%x nonce=%x\n", ch.Z, ch.Nonce)
				for _, m := range relaySetup {
					ch.Send0204(pc, m)
				}
				relayChans = append(relayChans, ch)
			}
			fmt.Printf("  [relay coordination: %d/%d channels established]\n", len(relayChans), len(eps))
			// The 0103 device-address replies arrive during the hole-punch phase, triggered by
			// the 0302 knock that loop sends, and are handled there by handleRelay0103.
		}
	}

	// handleRelay0103 completes the plaintext device coordination: a relayed 0103 (device address
	// plus 8-byte session token, IOTC-obfuscated) is answered with a 0408 ICE setup echoing the
	// token, and the learned device endpoint becomes a punch candidate. This authorizes the device
	// to accept direct DTLS; without it the device replies 15feff.
	coord0103Seen := 0
	handleRelay0103 := func(pkt []byte, from net.Addr) {
		if len(pkt) < 10 || pkt[0] == 0x51 {
			return
		}
		p := DecodePayload(pkt)
		if len(p) < 44 || p[8] != 0x01 || p[9] != 0x03 {
			return
		}
		c := tnauth.Parse0103(p)
		if c == nil {
			return
		}
		coord0103Seen++
		if coord0103Seen <= 1 {
			fmt.Printf("    [0103 device=%v:%d lan=%v token=%x -> echoing 0408]\n", c.DevIP, c.DevPort, c.DevLan, c.Token)
		}
		setup0408 := EncodePayload(tnauth.Build0408(coordUID, c, coordLocalIP, coordLocalPort, coordReflIP, coordReflPort))
		pc.WriteTo(setup0408, from)
		if c.DevIP != nil && c.DevPort != 0 {
			cands = appendUnique(cands, &net.UDPAddr{IP: c.DevIP, Port: c.DevPort})
			if c.DevLan != nil {
				cands = appendUnique(cands, &net.UDPAddr{IP: c.DevLan, Port: c.DevPort})
			}
		}
	}

	// 2) Hole-punch: send DIRECT to every candidate while keeping the precheck live; the device's
	// actual source address comes from its 4e6d punch-back.
	gotDevice := false
	var devAddr *net.UDPAddr
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !gotDevice {
		for _, c := range cands {
			pc.WriteTo(direct1, c)
		}
		sendKnock()
		sendPrecheck()
		pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				break
			}
			if n <= IOTCHeaderLen {
				continue
			}
			// Relay 0103 coordination arrives obfuscated from :3478.
			if ua, ok := from.(*net.UDPAddr); ok && ua.Port == 3478 {
				handleRelay0103(buf[:n], from)
				continue
			}
			if buf[0] == 0x4e && buf[1] == 0x6d { // device P2P session packet
				if ua, ok := from.(*net.UDPAddr); ok {
					devAddr = ua
				}
				gotDevice = true
				break
			}
		}
	}
	if !gotDevice {
		pc.Close()
		return nil, nil, errors.New("hole-punch: no response from device")
	}
	fmt.Printf("  [P2P punch-back: session peer = %v (this is where all session data flows)]\n", devAddr)
	_ = directPkt

	// 3) Advance the session state machine: send state-02 4e6d until the device reports the
	// connected state (04). Only then does it accept data packets.
	connected := false
	advDeadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(advDeadline) && !connected {
		pc.WriteTo(direct2, devAddr)
		sendKnock()
		pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				break
			}
			if ua, ok := from.(*net.UDPAddr); ok && ua.Port == 3478 {
				handleRelay0103(buf[:n], from)
				continue
			}
			if !sameHost(from, devAddr) || n <= IOTCHeaderLen {
				continue
			}
			if buf[0] == 0x4e && buf[1] == 0x6d && deviceState(buf[:n]) == deviceConnState {
				connected = true
				break
			}
		}
	}
	if !connected {
		pc.Close()
		return nil, nil, errors.New("session: device did not reach connected state (04)")
	}
	fmt.Printf("  [session connected: device reached state 04]\n")

	// The connected state must be acked with a burst of state-04 before data flows, or the
	// device rejects DTLS data with 15feff. Keepalive continues sending 04 afterwards.
	for range 8 {
		pc.WriteTo(direct4, devAddr)
		sendKnock()
		time.Sleep(30 * time.Millisecond)
	}

	// 4) RDT control handshake on internal channel 0x0a: 1704 (SYN) then 2704 opens the
	// reliable-data channel, which the device requires before accepting DTLS data on the 0x0b
	// channel; otherwise it rejects data with 15feff. The 8-byte connection value is
	// client-chosen and echoed in the device's 2804 ack.
	rdtVal := append([]byte(nil), token...)
	rdtSyn := buildRDTControl(0x17, 0x04, rdtVal)
	rdtAck := buildRDTControl(0x27, 0x04, rdtValueBump(rdtVal))
	gotRDT := false
	rdtDeadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(rdtDeadline) && !gotRDT {
		pc.WriteTo(rdtSyn, devAddr)
		pc.WriteTo(rdtAck, devAddr)
		pc.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				break
			}
			if !sameHost(from, devAddr) || n < 12 {
				continue
			}
			// The device's 2804 ack, wire type 4c6f, confirms the RDT channel is open.
			if buf[0] == 0x4c && buf[1] == 0x6f {
				dec := DecodePayload(buf[:n])
				if len(dec) >= 10 && dec[8] == 0x28 && dec[9] == 0x04 {
					gotRDT = true
					break
				}
			}
		}
	}
	fmt.Printf("  [RDT handshake: dev acked 2804 = %v (val=%x)]\n", gotRDT, rdtVal[:8])

	s := &Session{pc: pc, dev: devAddr, master: masterAddr, token: token,
		rdtVal: rdtVal, lastRxNano: time.Now().UnixNano(),
		stopKA: make(chan struct{}), knockPkt: knockPkt, directPkt: direct1, directPkt2: direct2, directPkt4: direct4,
		preWire: preWire, preAddrs: preAddrs, relayChans: relayChans, relaySetup: relaySetup, stunWire: stunWire, stunAddrs: stunAddrs,
		coordUID: coordUID, coordLocalIP: coordLocalIP, coordReflIP: coordReflIP, coordLocalPort: coordLocalPort, coordReflPort: coordReflPort}
	go s.keepalive()
	return s, &DialResult{Device: devAddr, Token: token}, nil
}

// --- net.PacketConn ---

// WriteTo frames DTLS record bytes as an IOTC data packet and sends it to the device.
// The packet is [16-byte internal header][RDT(12)][DTLS], encoded together. The addr
// argument is ignored; the session is bound to one device.
func (s *Session) WriteTo(b []byte, _ net.Addr) (int, error) {
	// Only the ClientHello record carries version fe ff; later handshake records stay fe fd.
	// Handshake type 0x01 at offset 13 identifies the ClientHello, so the rewrite must not
	// reach records such as the ClientKeyExchange.
	if len(b) >= 14 && b[0] == 0x16 && b[1] == 0xfe && b[2] == 0xfd && b[3] == 0x00 && b[4] == 0x00 && b[13] == 0x01 {
		b = append([]byte(nil), b...)
		b[2] = 0xff
	}
	rdt := BuildRDT(0x0000000c, s.token, b)
	hdr := make([]byte, 16)
	hdr[0], hdr[1], hdr[2], hdr[3] = 0x04, 0x02, 0x1d, 0x0b // type 0x0204
	binary.LittleEndian.PutUint16(hdr[4:6], uint16(len(rdt)))
	binary.LittleEndian.PutUint16(hdr[6:8], s.txSeq)
	hdr[8], hdr[9], hdr[10], hdr[11] = 0x07, 0x04, 0x21, 0x00 // TX channel fields
	hdr[12], hdr[13] = s.token[0], s.token[1]
	hdr[14], hdr[15] = 0x00, 0x01

	// Data packets are obfuscated over only their first 64 bytes, in both directions. A
	// whole-packet encode leaves the device unable to parse the tail, and it rejects the
	// data with 15feff.
	wire := EncodePayloadData(append(hdr, rdt...))
	if s.Trace != nil {
		s.Trace("TX", b)
	}
	if _, err := s.pc.WriteTo(wire, s.dev); err != nil {
		return 0, err
	}
	s.txSeq++
	return len(b), nil
}

// handleRelay0103 completes the plaintext device coordination: a relayed 0103 (device address plus
// 8-byte session token, IOTC-obfuscated) is answered with a 0408 ICE setup echoing the token, which
// authorizes the device to accept direct DTLS; otherwise the device replies 15feff.
func (s *Session) handleRelay0103(pkt []byte, from net.Addr) {
	if len(pkt) < 10 || pkt[0] == 0x51 || s.coordUID == nil {
		return
	}
	p := DecodePayload(pkt)
	if len(p) < 44 || p[8] != 0x01 || p[9] != 0x03 {
		return
	}
	c := tnauth.Parse0103(p)
	if c == nil {
		return
	}
	s.coordSeen++
	if s.coordSeen <= 1 {
		fmt.Printf("    [0103 device=%v:%d lan=%v token=%x -> echoing 0408]\n", c.DevIP, c.DevPort, c.DevLan, c.Token)
	}
	setup := EncodePayload(tnauth.Build0408(s.coordUID, c, s.coordLocalIP, s.coordLocalPort, s.coordReflIP, s.coordReflPort))
	s.pc.WriteTo(setup, from)
}

// ReadFrom returns the DTLS bytes from the next IOTC data packet from the device.
func (s *Session) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, 65536) // the device sends datagrams larger than 4096; a short buffer truncates them
	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if sameHost(from, s.dev) {
			atomic.StoreInt64(&s.lastRxNano, time.Now().UnixNano()) // any device packet proves the link is alive
		}
		if ua, ok := from.(*net.UDPAddr); ok && ua.Port == 3478 {
			s.handleRelay0103(buf[:n], from) // coordination continues during DTLS
			continue
		}
		if !sameHost(from, s.dev) || n <= 28 {
			continue
		}
		if s.OnRaw != nil {
			s.OnRaw(buf[:n])
		}
		// Device data packets have wire type 4e6f; 4e6d is a session packet.
		if buf[0] != 0x4e || buf[1] != 0x6f {
			continue
		}
		// Data packets obfuscate only their first 64 bytes; the rest is verbatim.
		clear := DecodePayloadData(buf[:n])
		if len(clear) < 28 || clear[0] != 0x04 || clear[1] != 0x02 { // internal type 0x0204 = data
			continue
		}
		dtls := clear[28:]
		if s.Trace != nil {
			s.Trace("RX", dtls)
		}
		return copy(b, dtls), s.dev, nil
	}
}

func (s *Session) Close() error {
	if s.stopKA != nil {
		select {
		case <-s.stopKA:
		default:
			close(s.stopKA)
		}
	}
	return s.pc.Close()
}

// SinceLastRx reports how long ago the last packet from the device arrived.
func (s *Session) SinceLastRx() time.Duration {
	return time.Since(time.Unix(0, atomic.LoadInt64(&s.lastRxNano)))
}

func (s *Session) LocalAddr() net.Addr           { return s.pc.LocalAddr() }
func (s *Session) SetDeadline(t time.Time) error { return s.pc.SetDeadline(t) }
func (s *Session) SetWriteDeadline(t time.Time) error {
	return s.pc.SetWriteDeadline(t)
}
func (s *Session) SetReadDeadline(t time.Time) error { return s.pc.SetReadDeadline(t) }

// SetReadBuffer enlarges the OS UDP receive buffer to avoid drops during fast bursts.
func (s *Session) SetReadBuffer(n int) error {
	if uc, ok := s.pc.(*net.UDPConn); ok {
		return uc.SetReadBuffer(n)
	}
	return nil
}

// sameHost matches by IP only: the device's NAT may map its packets to source ports other
// than the one the master advertised.
func sameHost(a net.Addr, b net.Addr) bool {
	ua, ok1 := a.(*net.UDPAddr)
	ub, ok2 := b.(*net.UDPAddr)
	return ok1 && ok2 && ua.IP.Equal(ub.IP)
}

func errFmt(what string, err error) error { return errors.New(what + ": " + err.Error()) }

func appendUnique(cands []*net.UDPAddr, addr *net.UDPAddr) []*net.UDPAddr {
	for _, c := range cands {
		if c.IP.Equal(addr.IP) && c.Port == addr.Port {
			return cands
		}
	}
	return append(cands, addr)
}
