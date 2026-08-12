package tnauth

import (
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
)

// licenseSignPub verifies the ZWO/ThroughTek licence blob. It is ThroughTek's public
// signing key, embedded in libTUTKGlobalAPIs.so; being public, it carries no secret.
//
//go:embed tutk_lic_pub.pem
var licenseSignPubPEM []byte

var licenseSignPub *rsa.PublicKey

func init() {
	block, _ := pem.Decode(licenseSignPubPEM)
	if block == nil {
		panic("tnauth: could not PEM-decode the licence signing key")
	}
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("tnauth: parse licence signing key: " + err.Error())
	}
	rp, ok := pk.(*rsa.PublicKey)
	if !ok {
		panic("tnauth: licence signing key is not RSA")
	}
	licenseSignPub = rp
}

// DeriveAuthKey recovers the Kalay authkey from a ZWO licence key. The licence (from the
// cloud online-link response) is a version-tagged, RSA-signed, XOR-obfuscated JSON blob;
// its "realm" field carries the authkey. Because the signing key is public and the licence
// comes from the caller's own account, no secret is embedded here.
//
// Layout: base64 -> [ver:4 LE == 1][sig:modBytes][xor:rest]. The signature is recovered by a
// raw RSA public operation (sig^e mod n, no padding), then XORed with the trailing bytes to
// yield the JSON. This matches SetLicenseKey/CheckLicenseKeyIsValid in the SDK.
func DeriveAuthKey(licenseKey string) (string, error) {
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(licenseKey))
	if err != nil {
		return "", fmt.Errorf("tnauth: licence not base64: %w", err)
	}
	modBytes := licenseSignPub.Size()
	if len(blob) < 4+modBytes {
		return "", fmt.Errorf("tnauth: licence too short (%d bytes)", len(blob))
	}
	if v := binary.LittleEndian.Uint32(blob[:4]); v != 1 {
		return "", fmt.Errorf("tnauth: unexpected licence version %d", v)
	}
	sig := new(big.Int).SetBytes(blob[4 : 4+modBytes])
	recovered := new(big.Int).Exp(sig, big.NewInt(int64(licenseSignPub.E)), licenseSignPub.N).Bytes()
	// left-pad to the modulus size so byte offsets line up
	if len(recovered) < modBytes {
		recovered = append(make([]byte, modBytes-len(recovered)), recovered...)
	}
	tail := blob[4+modBytes:]
	plain := make([]byte, len(tail))
	for i := range tail {
		plain[i] = tail[i] ^ recovered[i]
	}
	end := strings.IndexByte(string(plain), '}')
	if end < 0 {
		return "", fmt.Errorf("tnauth: licence plaintext not JSON")
	}
	var doc struct {
		Realm string `json:"realm"`
	}
	if err := json.Unmarshal(plain[:end+1], &doc); err != nil {
		return "", fmt.Errorf("tnauth: licence JSON: %w", err)
	}
	// The realm is <authkey>ln98<extra>; the credential tail uses everything up to "ln98".
	authkey := doc.Realm
	if i := strings.Index(authkey, "ln98"); i >= 0 {
		authkey = authkey[:i]
	}
	if authkey == "" {
		return "", fmt.Errorf("tnauth: empty authkey in realm %q", doc.Realm)
	}
	return authkey, nil
}
