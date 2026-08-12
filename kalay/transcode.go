// Package kalay reimplements ThroughTek Kalay/IOTC transport primitives in pure Go.
//
// TransCode and ReverseTransCode implement IOTC's keyless packet obfuscation: a fixed
// bit-permutation over 16-byte blocks, plus a separate permutation per remainder length
// for a trailing partial block.
package kalay

// applyBits writes into dst the bit-permutation of src given by perm, where perm[i] is
// the destination position of source bit i. Bits are indexed LSB-first within a byte;
// len(dst) must equal len(src) and perm must cover len(src)*8 bits.
func applyBits(dst, src []byte, perm []uint8) {
	for i := range dst {
		dst[i] = 0
	}
	for i := 0; i < len(src)*8; i++ {
		if src[i>>3]>>(uint(i)&7)&1 == 1 {
			j := int(perm[i])
			dst[j>>3] |= 1 << (uint(j) & 7)
		}
	}
}

func transcode(data []byte, blockPerm []uint8, remPerm map[int][]uint8) []byte {
	out := make([]byte, len(data))
	n := len(data)
	full := n &^ 0xf
	for k := 0; k < full; k += 16 {
		applyBits(out[k:k+16], data[k:k+16], blockPerm)
	}
	if r := n - full; r > 0 {
		applyBits(out[full:], data[full:], remPerm[r])
	}
	return out
}

// TransCode obfuscates a buffer (send direction).
func TransCode(data []byte) []byte { return transcode(data, fwdPermBits[:], fwdRemBits) }

// ReverseTransCode de-obfuscates a buffer (receive direction).
func ReverseTransCode(data []byte) []byte { return transcode(data, revPermBits[:], revRemBits) }
