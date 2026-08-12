package kalay

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Tunnel is a reliable byte stream to a device-local TCP port, carried over the Kalay stack
// (IOTC session -> DTLS 1.2 ECDHE_PSK_CHACHA20 -> RDT -> P2PTunnel). A single background goroutine
// owns the underlying session's I/O; Read/Write are safe for concurrent use.
type Tunnel struct {
	sess *Session

	cAEAD, sAEAD interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
	clientIV, serverIV []byte
	appSeq             uint64 // DTLS epoch-1 record sequence (send)

	devConn byte
	txSeq   uint64 // RDT reliable-stream sequence (client->device data/control)

	writeCh chan writeReq
	ctrlCh  chan []byte // raw P2PTunnel control payloads to send (e.g. channel-close frames)
	closed  chan struct{}
	closeMu sync.Once

	rmu   sync.Mutex
	rcond *sync.Cond
	rbuf  bytes.Buffer
	rerr  error
	recv  *Reassembler

	ctrlIdx byte // P2PTunnel channel index routed to rbuf

	pbuf        []byte // trailing partial P2PTunnel message carried across pump iterations
	pumpNext    uint64 // next reliable-stream seq to consume from recv
	pumpStarted bool
	lastAdvance time.Time // when pumpNext last moved; drives stall detection
	vmu         sync.Mutex
	vcond       *sync.Cond
	chans       map[byte]*bytes.Buffer // extra channels by index, each with its own inbound bytes

	povmu    sync.Mutex
	pendingV *vOpen // non-nil while a channel open is in flight; opens are serialised
	lastIdx  byte   // index of the most recently opened extra channel
	nextIdx  byte   // next channel index to propose

	statsMu   sync.Mutex
	chanBytes map[byte]int // bytes of socket data received per channel index
}

// ChannelByteStats returns a snapshot of bytes of socket data received per P2PTunnel channel index.
func (t *Tunnel) ChannelByteStats() map[byte]int {
	t.statsMu.Lock()
	defer t.statsMu.Unlock()
	out := map[byte]int{}
	maps.Copy(out, t.chanBytes)
	return out
}

// vOpen coordinates an OpenChannel call with the pump goroutine.
type vOpen struct {
	port         int
	idx          byte
	sentPortConn bool
	done         chan error
}

// writeReq is one queued outbound write, tagged with its P2PTunnel channel index.
type writeReq struct {
	idx  byte
	data []byte
}

// TunnelConfig configures OpenTunnel.
type TunnelConfig struct {
	Master            string // rendezvous master "host:port"
	PSK               []byte // DTLS pre-shared key (SHA-256 of the online-link password)
	Identity          []byte // PSK identity (online-link username)
	ClientHelloRecord []byte // ClientHello DTLS record replayed verbatim (13-byte hdr + msg)
	Port              int    // device-local TCP port to reach (e.g. 4700 for JSON-RPC)
	Device            DeviceIdentity
	ReadBufferBytes   int // OS UDP recv buffer (default 16MB)
}

// OpenTunnel establishes the full stack and returns a ready byte stream to the device port.
func OpenTunnel(cfg TunnelConfig) (*Tunnel, error) {
	if cfg.ReadBufferBytes == 0 {
		cfg.ReadBufferBytes = 16 << 20
	}
	chRecord := cfg.ClientHelloRecord
	if len(chRecord) < 13+13+2+32 {
		return nil, fmt.Errorf("kalay: ClientHelloRecord too short")
	}
	chMsg := chRecord[13:]
	clientRandom := chMsg[12+2 : 12+2+32]

	sess, _, err := Dial(cfg.Master, cfg.Device)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	sess.SetReadBuffer(cfg.ReadBufferBytes)
	ok := false
	defer func() {
		if !ok {
			sess.Close()
		}
	}()

	buf := make([]byte, 65536)

	// flight 1: replay ClientHello, collect ServerHello / SKE / ServerHelloDone
	var shMsg, skeMsg, shdMsg []byte
	deadline := time.Now().Add(10 * time.Second)
	for sends := uint64(0); time.Now().Before(deadline) && (shMsg == nil || skeMsg == nil || shdMsg == nil); sends++ {
		if sends == 0 || sends%8 == 0 {
			ch := append([]byte(nil), chRecord...)
			PutDTLSSeq(ch, sends)
			sess.WriteTo(ch, nil)
		}
		sess.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n, _, e := sess.ReadFrom(buf)
		if e != nil {
			continue
		}
		for _, r := range ParseDTLSRecords(buf[:n]) {
			if r.CT != 0x16 || len(r.Body) < 1 {
				continue
			}
			switch r.Body[0] {
			case 2:
				shMsg = append([]byte(nil), r.Body...)
			case 12:
				skeMsg = append([]byte(nil), r.Body...)
			case 14:
				shdMsg = append([]byte(nil), r.Body...)
			}
		}
	}
	if shMsg == nil || skeMsg == nil || shdMsg == nil {
		return nil, fmt.Errorf("handshake: incomplete server flight (SH=%v SKE=%v SHD=%v)", shMsg != nil, skeMsg != nil, shdMsg != nil)
	}
	serverRandom := shMsg[12+2 : 12+2+32]

	// parse SKE for the server's X25519 public key
	sb := skeMsg[12:]
	hintLen := int(binary.BigEndian.Uint16(sb))
	p := 2 + hintLen
	if p+4 > len(sb) {
		return nil, fmt.Errorf("handshake: malformed SKE")
	}
	pkLen := int(sb[p+3])
	if p+4+pkLen > len(sb) {
		return nil, fmt.Errorf("handshake: malformed SKE pubkey")
	}
	serverPub := sb[p+4 : p+4+pkLen]

	curve := ecdh.X25519()
	myPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("handshake: generate X25519 key: %w", err)
	}
	srvKey, err := curve.NewPublicKey(serverPub)
	if err != nil {
		return nil, fmt.Errorf("handshake: bad server pubkey: %w", err)
	}
	Z, err := myPriv.ECDH(srvKey)
	if err != nil {
		return nil, fmt.Errorf("handshake: ECDH: %w", err)
	}

	// premaster = len(Z)||Z||len(psk)||psk (RFC 4279 ECDHE_PSK)
	pms := []byte{byte(len(Z) >> 8), byte(len(Z))}
	pms = append(pms, Z...)
	pms = append(pms, byte(len(cfg.PSK)>>8), byte(len(cfg.PSK)))
	pms = append(pms, cfg.PSK...)

	myPub := myPriv.PublicKey().Bytes()
	ckeBody := []byte{byte(len(cfg.Identity) >> 8), byte(len(cfg.Identity))}
	ckeBody = append(ckeBody, cfg.Identity...)
	ckeBody = append(ckeBody, byte(len(myPub)))
	ckeBody = append(ckeBody, myPub...)
	ckeMsg := DTLSHandshakeMsg(16, 1, ckeBody)

	th := sha256.New()
	th.Write(chMsg)
	th.Write(shMsg)
	th.Write(skeMsg)
	th.Write(shdMsg)
	th.Write(ckeMsg)
	sessionHash := th.Sum(nil)

	var masterSecret []byte
	if serverHelloHasExt(shMsg[12:], 0x0017) {
		masterSecret = PRF(pms, "extended master secret", sessionHash, 48)
	} else {
		masterSecret = PRF(pms, "master secret", append(append([]byte{}, clientRandom...), serverRandom...), 48)
	}
	keyBlock := PRF(masterSecret, "key expansion", append(append([]byte{}, serverRandom...), clientRandom...), 32+32+12+12)
	cAEAD, err := chacha20poly1305.New(keyBlock[0:32])
	if err != nil {
		return nil, fmt.Errorf("handshake: client AEAD: %w", err)
	}
	sAEAD, err := chacha20poly1305.New(keyBlock[32:64])
	if err != nil {
		return nil, fmt.Errorf("handshake: server AEAD: %w", err)
	}
	clientIV := keyBlock[64:76]
	serverIV := keyBlock[76:88]

	finishedMsg := DTLSHandshakeMsg(20, 2, PRF(masterSecret, "client finished", sessionHash, 12))
	encFin := Seal(cAEAD, clientIV, 1, 0, 0x16, finishedMsg)
	flight := append(DTLSRecordRaw(0x16, 0, 1, ckeMsg), DTLSRecordRaw(0x14, 0, 2, []byte{0x01})...)
	flight = append(flight, DTLSRecordRaw(0x16, 1, 0, encFin)...)
	sess.WriteTo(flight, nil)

	end := time.Now().Add(6 * time.Second)
	got := false
	for time.Now().Before(end) && !got {
		sess.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, e := sess.ReadFrom(buf)
		if e != nil {
			continue
		}
		for _, r := range ParseDTLSRecords(buf[:n]) {
			if r.Epoch == 1 && r.CT == 0x16 {
				if _, e := Open(sAEAD, serverIV, r.Epoch, r.Seq, r.CT, r.Body); e == nil {
					got = true
				}
			}
		}
	}
	if !got {
		return nil, fmt.Errorf("handshake: no server Finished")
	}

	t := &Tunnel{
		sess: sess, cAEAD: cAEAD, sAEAD: sAEAD,
		clientIV: clientIV, serverIV: serverIV, appSeq: 2,
		writeCh: make(chan writeReq, 64), ctrlCh: make(chan []byte, 16), closed: make(chan struct{}),
		recv: NewReassembler(), ctrlIdx: 0x01,
	}
	t.rcond = sync.NewCond(&t.rmu)
	t.vcond = sync.NewCond(&t.vmu)
	t.chans = map[byte]*bytes.Buffer{}

	if err := t.setup(buf, cfg.Port); err != nil {
		return nil, err
	}
	ok = true
	go t.pump(make([]byte, 65536))
	return t, nil
}

const tunMyConn = 0x01

var tunDebug = os.Getenv("KALAY_TUN_DEBUG") != ""
var ackLogCount int // caps debug logging of inbound device control frames

func (t *Tunnel) sendRDT(typ, b16, connID byte, seq uint64, payload []byte) {
	f := AppendRDT(nil, RDTPacket{Type: typ, Seq: seq, B16: b16, ConnID: connID, Payload: payload})
	t.sess.WriteTo(DTLSRecordRaw(0x17, 1, t.appSeq, Seal(t.cAEAD, t.clientIV, 1, t.appSeq, 0x17, f)), nil)
	t.appSeq++
}

func (t *Tunnel) readRDT(buf []byte, dur time.Duration) []RDTPacket {
	var out []RDTPacket
	d := dur
	for {
		t.sess.SetReadDeadline(time.Now().Add(d))
		n, _, err := t.sess.ReadFrom(buf)
		if err != nil {
			break
		}
		d = 15 * time.Millisecond
		for _, r := range ParseDTLSRecords(buf[:n]) {
			if r.Epoch != 1 || r.CT != 0x17 {
				continue
			}
			pt, e := Open(t.sAEAD, t.serverIV, r.Epoch, r.Seq, r.CT, r.Body)
			if e != nil {
				continue
			}
			out = append(out, ParseRDTStream(pt)...)
		}
	}
	return out
}

// setup drives the RDT SYN plus P2PTunnel session/channel/connect handshake until the channel to
// port is connected, consuming reliable-stream seqs 0=session, 1=channel-create, 2=connect.
func (t *Tunnel) setup(buf []byte, port int) error {
	p2pSession := []byte{0x07, 0x00, 0x08, 0x00, 0x00, 0x08, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00}
	portConnect := []byte{0x0c, 0x00, 0x06, 0x00, 0xc7, 0x01, byte(port), byte(port >> 8), 0x00, 0x00}
	connectAddr := append([]byte{0x01, 0x01, 0x34, 0x00, 0x02, 0x00, byte(port >> 8), byte(port), 0x7f, 0x00, 0x00, 0x01}, make([]byte, 44)...)

	synAcked, sessionOpen, ready := false, false, false
	lastKA := time.Now().Add(-time.Second)
	deadline := time.Now().Add(20 * time.Second)
	for !ready && time.Now().Before(deadline) {
		if time.Since(lastKA) > 300*time.Millisecond {
			t.sendRDT(0x01, 0x00, tunMyConn, 0, nil)
			if t.devConn != 0 && !ready {
				t.sendRDT(0x41, 0x00, t.devConn, 0, nil)
			}
			lastKA = time.Now()
		}
		for _, f := range t.readRDT(buf, 300*time.Millisecond) {
			switch f.Type {
			case 0x01:
				if t.devConn == 0 {
					t.devConn = f.ConnID
				}
			case 0x41:
				if !synAcked {
					synAcked = true
					t.sendRDT(0x02, 0x01, t.devConn, 0, p2pSession)
				}
			case 0x02:
				t.sendRDT(0x46, 0x01, t.devConn, f.Seq, nil) // ACK
				switch {
				case len(f.Payload) >= 2 && f.Payload[0] == 0x08 && f.Payload[1] == 0x00:
					if !sessionOpen {
						sessionOpen = true
						t.sendRDT(0x02, 0x01, t.devConn, 1, portConnect)
					}
				case len(f.Payload) >= 4 && f.Payload[0] == 0x0d:
					if !ready {
						ready = true
						t.sendRDT(0x02, 0x01, t.devConn, 2, connectAddr)
					}
				}
			}
		}
	}
	if !ready {
		return fmt.Errorf("tunnel: channel to port %d did not open", port)
	}
	t.txSeq = 3 // data writes continue the same reliable stream
	return nil
}

// p2pPortConnect and p2pConnectAddr build the two P2PTunnel messages that open channel idx to
// 127.0.0.1:port. Byte 1 of each is the channel index; portConnect's port is little-endian,
// connectAddr's is big-endian.
func p2pPortConnect(idx byte, port int) []byte {
	return []byte{0x0c, 0x00, 0x06, 0x00, 0xc7, idx, byte(port), byte(port >> 8), 0x00, 0x00}
}
func p2pConnectAddr(idx byte, port int) []byte {
	return append([]byte{0x01, idx, 0x34, 0x00, 0x02, 0x00, byte(port >> 8), byte(port), 0x7f, 0x00, 0x00, 0x01}, make([]byte, 44)...)
}

// pump is the sole owner of session I/O once the tunnel is ready: it keepalives, ACKs, demuxes and
// routes inbound P2PTunnel messages, and sends queued outbound writes. It runs until Close.
func (t *Tunnel) pump(buf []byte) {
	defer func() {
		t.rmu.Lock()
		if t.rerr == nil {
			t.rerr = fmt.Errorf("tunnel closed")
		}
		t.rcond.Broadcast()
		t.rmu.Unlock()
		t.vmu.Lock()
		t.vcond.Broadcast()
		t.vmu.Unlock()
	}()
	lastKA := time.Now()
	lastHB := time.Now()
	for {
		select {
		case <-t.closed:
			return
		default:
		}
		if tunDebug && time.Since(lastHB) > 2*time.Second {
			fmt.Fprintf(os.Stderr, "[tun] HB txSeq=%d appSeq=%d pumpNext=%d maxSeq=%d writeChLen=%d\n",
				t.txSeq, t.appSeq, t.pumpNext, t.recv.MaxSeq(), len(t.writeCh))
			lastHB = time.Now()
		}
		if time.Since(lastKA) > 400*time.Millisecond {
			t.sendRDT(0x01, 0x00, tunMyConn, 0, nil)
			// Re-send the cumulative ACK for the highest consumed in-order seq. ACKs can be dropped by
			// the relay; without repetition the device's send window fills and the transfer stalls.
			if t.pumpStarted && t.pumpNext > 0 {
				t.sendRDT(0x46, 0x01, t.devConn, t.pumpNext-1, nil)
			}
			lastKA = time.Now()
		}
		// Start a pending channel open: portConnect goes out once here; connectAddr follows in route
		// on the 0x0d reply.
		t.povmu.Lock()
		if pv := t.pendingV; pv != nil && !pv.sentPortConn {
			if tunDebug {
				fmt.Fprintf(os.Stderr, "[tun] send portConnect idx=%d port=%d seq=%d: %x\n", pv.idx, pv.port, t.txSeq, p2pPortConnect(pv.idx, pv.port))
			}
			t.sendRDT(0x02, 0x01, t.devConn, t.txSeq, p2pPortConnect(pv.idx, pv.port))
			t.txSeq++
			pv.sentPortConn = true
		}
		t.povmu.Unlock()
		// drain queued raw P2PTunnel control payloads
		for {
			select {
			case cb := <-t.ctrlCh:
				if tunDebug {
					fmt.Fprintf(os.Stderr, "[tun] send ctrl seq=%d: %x\n", t.txSeq, cb)
				}
				t.sendRDT(0x02, 0x01, t.devConn, t.txSeq, cb)
				t.txSeq++
				continue
			default:
			}
			break
		}
		// drain outbound writes
		for {
			select {
			case w := <-t.writeCh:
				// One P2PTunnel data chunk (02 <chan> <len16> <bytes>), split across MTU-safe RDT
				// frames so each DTLS record fits a single UDP datagram; oversized datagrams are
				// dropped by the relay. The device reassembles using the chunk length.
				p := w.data
				chunk := append([]byte{0x02, w.idx, byte(len(p)), byte(len(p) >> 8)}, p...)
				const maxFrame = 1024
				for off := 0; off < len(chunk); off += maxFrame {
					end := min(off+maxFrame, len(chunk))
					t.sendRDT(0x02, 0x01, t.devConn, t.txSeq, chunk[off:end])
					t.txSeq++
				}
				continue
			default:
			}
			break
		}
		// inbound
		for _, f := range t.readRDT(buf, 200*time.Millisecond) {
			if f.Type != 0x02 {
				if tunDebug && ackLogCount < 30 && (f.Type == 0x46 || f.Type == 0x41 || f.Type == 0x4e) {
					fmt.Fprintf(os.Stderr, "[rdt] dev ctrl type=%#x seq=%d b16=%d conn=%d paylen=%d pay=%x\n",
						f.Type, f.Seq, f.B16, f.ConnID, len(f.Payload), f.Payload)
					ackLogCount++
				}
				continue
			}
			// Never ACK a frame's own seq. ACKs are cumulative, so acking a seq that arrived after a
			// gap tells the device the missing seq was received, suppressing its retransmit and
			// stalling the stream permanently. Only the highest contiguous seq is acked, below.
			t.recv.Add(f.Seq, f.Payload)
		}
		// Consume the in-order prefix incrementally: Take frees each consumed frame, bounding memory
		// to the working set, and only the unparsed remainder is re-scanned. Rebuilding the whole
		// received buffer per iteration would be O(n^2) and starve the keepalives and ACKs above.
		if !t.pumpStarted && t.recv.Started() {
			t.pumpNext = t.recv.Base()
			t.pumpStarted = true
			t.lastAdvance = time.Now()
		}
		if t.pumpStarted {
			before := t.pumpNext
			for {
				p, ok := t.recv.Take(t.pumpNext)
				if !ok {
					break
				}
				t.pbuf = append(t.pbuf, p...)
				t.pumpNext++
			}
			if t.pumpNext != before {
				t.lastAdvance = time.Now()
				// cumulative ACK of the highest contiguous seq; post-gap seqs stay unacked
				t.sendRDT(0x46, 0x01, t.devConn, t.pumpNext-1, nil)
			}
			var d PTunDemux
			for _, m := range d.Parse(t.pbuf) {
				t.route(m)
			}
			if d.off > 0 {
				t.pbuf = append(t.pbuf[:0], t.pbuf[d.off:]...)
			}
			// Stall recovery. A stuck pumpNext with higher seqs already received means frame
			// pumpNext was dropped with no retransmit; duplicate ACKs of the last in-order seq
			// trigger a fast retransmit.
			if t.pumpStarted && time.Since(t.lastAdvance) > 2*time.Second {
				max := t.recv.MaxSeq()
				if max >= t.pumpNext { // frames past the hole exist
					if tunDebug {
						fmt.Fprintf(os.Stderr, "[tun] GAP-STALL pumpNext=%d maxSeq=%d pbuf=%d -> dupACK\n", t.pumpNext, max, len(t.pbuf))
					}
					if t.pumpNext > 0 {
						t.sendRDT(0x46, 0x01, t.devConn, t.pumpNext-1, nil)
						t.sendRDT(0x46, 0x01, t.devConn, t.pumpNext-1, nil)
					}
					t.lastAdvance = time.Now().Add(-1500 * time.Millisecond) // retry every ~0.5s
				} else {
					// Everything received has been consumed yet the device stopped sending: its send
					// window is likely full from lost ACKs, so re-ACK to reopen it.
					if tunDebug {
						fmt.Fprintf(os.Stderr, "[tun] INBOUND-DRY pumpNext=%d maxSeq=%d -> re-ACK window\n", t.pumpNext, max)
					}
					if t.pumpNext > 0 {
						t.sendRDT(0x46, 0x01, t.devConn, t.pumpNext-1, nil)
					}
					t.lastAdvance = time.Now().Add(-1500 * time.Millisecond)
				}
			}
		}
	}
}

// route dispatches one demuxed P2PTunnel message. Data chunks go to rbuf or an extra channel's
// a 0x0d channel-created reply completes a pending open by sending that channel's connectAddr.
// It runs on the pump goroutine.
func (t *Tunnel) route(m PTunMsg) {
	switch m.Type {
	case 0x02:
		t.statsMu.Lock()
		if t.chanBytes == nil {
			t.chanBytes = map[byte]int{}
		}
		first := t.chanBytes[m.Chan] == 0
		t.chanBytes[m.Chan] += len(m.Data)
		t.statsMu.Unlock()
		if tunDebug && first {
			fmt.Fprintf(os.Stderr, "[tun] first data on chan=%d len=%d (lastIdx=%d ctrlIdx=%d)\n", m.Chan, len(m.Data), t.lastIdx, t.ctrlIdx)
		}
		switch m.Chan {
		case t.ctrlIdx:
			t.rmu.Lock()
			t.rbuf.Write(m.Data)
			t.rcond.Broadcast()
			t.rmu.Unlock()
		default:
			t.vmu.Lock()
			if buf := t.chans[m.Chan]; buf != nil {
				buf.Write(m.Data)
				t.vcond.Broadcast()
			} // else: stale channel index; drop
			t.vmu.Unlock()
		}
	case 0x0d: // channel created
		t.povmu.Lock()
		if pv := t.pendingV; pv != nil && pv.sentPortConn {
			if tunDebug {
				fmt.Fprintf(os.Stderr, "[tun] 0d reply: %x -> send connectAddr idx=%d port=%d seq=%d: %x\n", m.Data, pv.idx, pv.port, t.txSeq, p2pConnectAddr(pv.idx, pv.port))
			}
			t.sendRDT(0x02, 0x01, t.devConn, t.txSeq, p2pConnectAddr(pv.idx, pv.port))
			t.txSeq++
			t.pendingV = nil
			select {
			case pv.done <- nil:
			default:
			}
		}
		t.povmu.Unlock()
	default:
		if tunDebug {
			fmt.Fprintf(os.Stderr, "[tun] ctrl msg type=%#x: %x\n", m.Type, m.Data)
		}
	}
}

// OpenChannel opens an extra P2PTunnel channel to port within this session and returns a
// bidirectional stream to that device-local socket. The device rejects a second concurrent Kalay
// session, so reaching another port requires sharing this tunnel. Any number of extra channels
// may be open at once; the opens themselves are serialised.
func (t *Tunnel) OpenChannel(port int) (io.ReadWriteCloser, error) {
	t.povmu.Lock()
	if t.pendingV != nil {
		t.povmu.Unlock()
		return nil, fmt.Errorf("kalay: a channel open is already in progress")
	}
	// The device holds one channel per client-proposed index and its HTTP server closes the socket
	// after each response, so every open must use a fresh index. Indices 0 and 1 are reserved for
	// the control channel and 0xff is excluded; wrapping is safe because the device has freed the
	// low indices by then. Registering the buffer here makes route accept this channel.
	if t.nextIdx < 0x02 {
		t.nextIdx = 0x02
	}
	idx := t.nextIdx
	t.nextIdx++
	if t.nextIdx == 0xff || t.nextIdx < 0x02 {
		t.nextIdx = 0x02
	}
	t.lastIdx = idx
	pv := &vOpen{port: port, idx: idx, done: make(chan error, 1)}
	t.pendingV = pv
	t.povmu.Unlock()
	t.vmu.Lock()
	t.chans[idx] = &bytes.Buffer{}
	t.vmu.Unlock()
	select {
	case err := <-pv.done:
		if err != nil {
			t.dropChan(idx)
			return nil, err
		}
		return &chanConn{t: t, idx: pv.idx}, nil
	case <-t.closed:
		t.dropChan(idx)
		return nil, fmt.Errorf("kalay: tunnel closed")
	case <-time.After(12 * time.Second):
		t.povmu.Lock()
		if t.pendingV == pv {
			t.pendingV = nil
		}
		t.povmu.Unlock()
		t.dropChan(idx)
		return nil, fmt.Errorf("kalay: open channel to %d: no channel-created reply in 12s", port)
	}
}

// OpenVideoChannel is OpenChannel narrowed to the read side.
func (t *Tunnel) OpenVideoChannel(port int) (io.Reader, error) { return t.OpenChannel(port) }

// SendTunnelCtrl queues a raw P2PTunnel control payload, such as a channel-close frame, for the
// pump to send on the reliable RDT stream.
func (t *Tunnel) SendTunnelCtrl(payload []byte) {
	select {
	case t.ctrlCh <- append([]byte(nil), payload...):
	case <-t.closed:
	}
}

// ActiveChannelIdx returns the index of the most-recently-opened extra channel.
func (t *Tunnel) ActiveChannelIdx() byte { return t.lastIdx }

// dropChan stops routing data to an extra channel and wakes its reader.
func (t *Tunnel) dropChan(idx byte) {
	t.vmu.Lock()
	delete(t.chans, idx)
	t.vcond.Broadcast()
	t.vmu.Unlock()
}

// chanConn is a bidirectional stream over one extra P2PTunnel channel.
type chanConn struct {
	t   *Tunnel
	idx byte
}

func (v *chanConn) Read(p []byte) (int, error) {
	t := v.t
	t.vmu.Lock()
	defer t.vmu.Unlock()
	for {
		buf := t.chans[v.idx]
		if buf == nil {
			return 0, fmt.Errorf("kalay: channel %d closed", v.idx)
		}
		if buf.Len() > 0 {
			return buf.Read(p)
		}
		select {
		case <-t.closed:
			return 0, fmt.Errorf("kalay: tunnel closed")
		default:
		}
		t.vcond.Wait()
	}
}

func (v *chanConn) Write(p []byte) (int, error) { return v.t.writeChan(v.idx, p) }
func (v *chanConn) Close() error {
	v.t.dropChan(v.idx)
	return nil
}

// Read returns bytes from the device socket, blocking until some are available or the tunnel closes.
func (t *Tunnel) Read(p []byte) (int, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()
	for t.rbuf.Len() == 0 {
		if t.rerr != nil {
			return 0, t.rerr
		}
		t.rcond.Wait()
	}
	return t.rbuf.Read(p)
}

// Write sends p to the control channel's device socket.
func (t *Tunnel) Write(p []byte) (int, error) {
	return t.writeChan(t.ctrlIdx, p)
}

// writeChan queues p as a data chunk on the given channel index.
func (t *Tunnel) writeChan(idx byte, p []byte) (int, error) {
	select {
	case <-t.closed:
		return 0, fmt.Errorf("tunnel closed")
	case t.writeCh <- writeReq{idx: idx, data: append([]byte(nil), p...)}:
		return len(p), nil
	}
}

// Close tears down the tunnel and its session.
func (t *Tunnel) Close() error {
	t.closeMu.Do(func() { close(t.closed) })
	t.rmu.Lock()
	if t.rerr == nil {
		t.rerr = fmt.Errorf("tunnel closed")
	}
	t.rcond.Broadcast()
	t.rmu.Unlock()
	t.vmu.Lock()
	t.vcond.Broadcast()
	t.vmu.Unlock()
	return t.sess.Close()
}

// serverHelloHasExt reports whether a ServerHello body (minus its 12-byte handshake header)
// advertises the given extension type.
func serverHelloHasExt(shBody []byte, want uint16) bool {
	if len(shBody) < 38 {
		return false
	}
	sid := int(shBody[34])
	p := 35 + sid + 3
	if p+2 > len(shBody) {
		return false
	}
	end := p + 2 + int(binary.BigEndian.Uint16(shBody[p:]))
	p += 2
	for p+4 <= end && p+4 <= len(shBody) {
		et := binary.BigEndian.Uint16(shBody[p:])
		el := int(binary.BigEndian.Uint16(shBody[p+2:]))
		if et == want {
			return true
		}
		p += 4 + el
	}
	return false
}
