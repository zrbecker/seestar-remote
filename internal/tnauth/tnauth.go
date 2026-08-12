// Package tnauth builds the ThroughTek `51cc` authorization precheck sent to the Kalay
// auth-masters on UDP :10240. Without it the device rejects data with a constant 15-byte
// "not authorized" reply.
//
// The precheck is message type `0201`, repeated to every auth-master: a 268-byte frame
// carrying an RSA-2048 ciphertext of an 88-byte credential blob. The master's `0201` reply is
// AES-128-GCM under the session key carried inside that blob (see DecodeReply); no app secret
// is involved. The decrypted reply carries the client's reflexive address and the relay
// masters' P-256 ECDH public keys for the relay path (`0202` ECDH + `0204` through :3478).
//
// Blob layout:
//
//	[0:16]  04021d00 48000000 0b10 1800 00000000   fixed header (msgtype 0x100b, body len 0x48=72)
//	[16:18] 2 random bytes                          per-session id
//	[18:20] 0000
//	[20:36] 16 random bytes                         session AES key (used by the relay path)
//	[36:48] 12 random bytes                         nonce
//	[48:88] <20B UID><12B authkey>"ln98"<06000000>  credential tail
//
// The authkey comes from DeriveAuthKey against the licence in the online-link response; it
// is a per-product value, not a per-device secret. The UID is the rotating one from the
// same response.
package tnauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
)

// rsaEncrypt encrypts for the Kalay master. The masters accept only textbook RSA with the
// plaintext left-aligned and zero-padded to the modulus, and reject PKCS#1 and OAEP padding,
// so crypto/rsa's padded encrypt functions cannot be used here.
func rsaEncrypt(msg []byte) ([]byte, error) {
	return rawRSA(msg, true)
}

// rawRSA does a textbook RSA public-key operation on msg zero-padded to the modulus size.
func rawRSA(msg []byte, leftAlign bool) ([]byte, error) {
	k := masterPub.Size()
	block := make([]byte, k)
	if leftAlign {
		copy(block, msg)
	} else {
		copy(block[k-len(msg):], msg)
	}
	m := new(big.Int).SetBytes(block)
	c := new(big.Int).Exp(m, big.NewInt(int64(masterPub.E)), masterPub.N)
	out := make([]byte, k)
	c.FillBytes(out)
	return out, nil
}

//go:embed master_rsa_pub.pem
var masterPubPEM []byte

var masterPub *rsa.PublicKey

func init() {
	block, _ := pem.Decode(masterPubPEM)
	if block == nil {
		panic("tnauth: could not PEM-decode embedded master public key")
	}
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("tnauth: parse master public key: " + err.Error())
	}
	rp, ok := pk.(*rsa.PublicKey)
	if !ok {
		panic("tnauth: embedded key is not RSA")
	}
	masterPub = rp
}

// tailSuffix follows the UID and authkey in the credential tail.
var tailSuffix = []byte{'l', 'n', '9', '8', 0x06, 0x00, 0x00, 0x00}

// credentialTail assembles the 40-byte tail from a device UID and the authkey derived from
// the licence (see DeriveAuthKey).
func credentialTail(deviceUID, authKey string) ([]byte, error) {
	if len(deviceUID) != 20 {
		return nil, fmt.Errorf("tnauth: device UID must be 20 chars, got %d", len(deviceUID))
	}
	if len(authKey) != 12 {
		return nil, fmt.Errorf("tnauth: authkey must be 12 chars, got %d", len(authKey))
	}
	tail := make([]byte, 0, 40)
	tail = append(tail, deviceUID...)
	tail = append(tail, authKey...)
	return append(tail, tailSuffix...), nil
}

// authBlobHeader is the fixed 16-byte prefix (msgtype 0x100b, body length 0x48).
var authBlobHeader = []byte{0x04, 0x02, 0x1d, 0x00, 0x48, 0x00, 0x00, 0x00, 0x0b, 0x10, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00}

// precheck0201Header frames the RSA ciphertext as a `51cc` type-0201 message.
var precheck0201Header = []byte{0x51, 0xcc, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}

// BuildAuthBlobFixed assembles the 88-byte credential blob from a 40-byte device tail and
// caller-supplied per-session fields.
func BuildAuthBlobFixed(tail []byte, sessID uint16, sessKey [16]byte, nonce [12]byte) ([]byte, error) {
	if len(tail) != 40 {
		return nil, fmt.Errorf("tnauth: tail must be 40 bytes, got %d", len(tail))
	}
	b := make([]byte, 88)
	copy(b[0:16], authBlobHeader)
	b[16] = byte(sessID)
	b[17] = byte(sessID >> 8)
	copy(b[20:36], sessKey[:])
	copy(b[36:48], nonce[:])
	copy(b[48:88], tail)
	return b, nil
}

// BuildPrecheck0201Fixed builds the `0201` precheck for a device UID with caller-supplied
// session fields.
func BuildPrecheck0201Fixed(deviceUID, authKey string, sessID uint16, sessKey [16]byte, nonce [12]byte) ([]byte, error) {
	tail, err := credentialTail(deviceUID, authKey)
	if err != nil {
		return nil, err
	}
	blob, err := BuildAuthBlobFixed(tail, sessID, sessKey, nonce)
	if err != nil {
		return nil, err
	}
	ct, err := rsaEncrypt(blob)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, len(precheck0201Header)+len(ct))
	copy(msg, precheck0201Header)
	copy(msg[len(precheck0201Header):], ct)
	return msg, nil
}

// BuildPrecheck0201Ex builds a precheck with random per-session fields and returns the wire
// message plus the session key and nonce needed to decode the master's reply (DecodeReply).
func BuildPrecheck0201Ex(deviceUID, authKey string) (msg []byte, sessKey [16]byte, nonce [12]byte, err error) {
	var sid [2]byte
	rand.Read(sid[:])
	rand.Read(sessKey[:])
	rand.Read(nonce[:])
	id := uint16(sid[0]) | uint16(sid[1])<<8
	msg, err = BuildPrecheck0201Fixed(deviceUID, authKey, id, sessKey, nonce)
	return
}

// DecodeReply decrypts a master's `51cc 0201` reply, which is AES-128-GCM under the material
// sent in the request blob: key = session key (blob[20:36]), nonce = blob[36:48], AAD = the
// 12-byte `51cc` header. The body is ciphertext with a trailing 16-byte GCM tag. reply is the
// full wire message (12-byte header + body).
func DecodeReply(reply []byte, sessKey [16]byte, nonce [12]byte) ([]byte, error) {
	if len(reply) < 12+16 {
		return nil, fmt.Errorf("tnauth: reply too short (%d)", len(reply))
	}
	blk, err := aes.NewCipher(sessKey[:])
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce[:], reply[12:], reply[:12])
}

// RelayEndpoint is a relay master offered in the decrypted `0201` reply: its address plus the
// static P-256 ECDH public key for the `0202`/`0204` relay channel.
type RelayEndpoint struct {
	IP      net.IP
	Port    int
	ECDHPub []byte // uncompressed P-256 point (65 bytes, 0x04||X||Y)
}

// p256SPKIPrefix is the DER SubjectPublicKeyInfo prefix for an uncompressed prime256v1 key.
var p256SPKIPrefix = mustHex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")

// ParseReply extracts the relay endpoints from a decrypted `0201` reply plaintext. Each relay
// is encoded as `<port BE:2><ip:4><8 zeros>` immediately followed by the 91-byte P-256 SPKI.
// The relay UDP port is 3478.
func ParseReply(pt []byte) []RelayEndpoint {
	var out []RelayEndpoint
	pfx := p256SPKIPrefix
	for i := 0; i+len(pfx)+64 <= len(pt); i++ {
		if !bytesEqual(pt[i:i+len(pfx)], pfx) {
			continue
		}
		pub := append([]byte(nil), pt[i+len(pfx)-1:i+len(pfx)+64]...) // 0x04||X||Y
		ep := RelayEndpoint{ECDHPub: pub, Port: 3478}
		if i >= 12 {
			ep.IP = net.IPv4(pt[i-12], pt[i-11], pt[i-10], pt[i-9])
		}
		out = append(out, ep)
		i += len(pfx) + 64
	}
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("tnauth: bad hex: " + err.Error())
	}
	return b
}
