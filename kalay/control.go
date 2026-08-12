package kalay

// IOTCHeaderLen is the plaintext IOTC header size preceding the obfuscated payload.
const IOTCHeaderLen = 16

// controlMask is XORed over the payload, repeating every 16 bytes, on top of the
// TransCode bit-permutation.
var controlMask = [16]byte{
	0x86, 0xd0, 0xc2, 0xe4, 0x84, 0x2d, 0xad, 0x0c,
	0xe8, 0xd2, 0xe6, 0x40, 0x84, 0x0c, 0xad, 0x0c,
}

func xorMask(b []byte) []byte {
	out := make([]byte, len(b))
	for i, x := range b {
		out[i] = x ^ controlMask[i%16]
	}
	return out
}

// DecodePayload recovers the cleartext control payload from the on-wire bytes
// following the plaintext IOTC header.
func DecodePayload(wire []byte) []byte { return xorMask(ReverseTransCode(wire)) }

// EncodePayload produces the on-wire payload from a cleartext control payload.
func EncodePayload(clear []byte) []byte { return TransCode(xorMask(clear)) }

// dataTransLimit is the number of leading bytes DATA packets obfuscate; control
// packets obfuscate the whole payload.
const dataTransLimit = 64

// DecodePayloadData recovers a DATA-packet payload: the leading dataTransLimit bytes
// are obfuscated, the rest is verbatim.
func DecodePayloadData(wire []byte) []byte {
	if len(wire) <= dataTransLimit {
		return DecodePayload(wire)
	}
	out := make([]byte, len(wire))
	copy(out, xorMask(ReverseTransCode(wire[:dataTransLimit])))
	copy(out[dataTransLimit:], wire[dataTransLimit:])
	return out
}

// EncodePayloadData is the inverse of DecodePayloadData.
func EncodePayloadData(clear []byte) []byte {
	if len(clear) <= dataTransLimit {
		return EncodePayload(clear)
	}
	out := make([]byte, len(clear))
	copy(out, TransCode(xorMask(clear[:dataTransLimit])))
	copy(out[dataTransLimit:], clear[dataTransLimit:])
	return out
}
