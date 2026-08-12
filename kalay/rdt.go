package kalay

import "encoding/binary"

// RDTHeaderLen is the length of the reliable-transport header preceding DTLS records in a decoded
// IOTC data packet payload: a 4-byte word plus the 8-byte P2P session token.
const RDTHeaderLen = 12

// BuildRDT wraps DTLS record bytes in an RDT frame for the given session token.
func BuildRDT(word uint32, token, dtls []byte) []byte {
	out := make([]byte, RDTHeaderLen+len(dtls))
	binary.LittleEndian.PutUint32(out[0:4], word)
	copy(out[4:12], token)
	copy(out[12:], dtls)
	return out
}
