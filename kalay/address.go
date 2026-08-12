package kalay

import (
	"fmt"
	"net"
	"strconv"
)

// AddrRecord is one device address candidate from a rendezvous response. Each record
// is 16 bytes in the decoded payload:
//
//	[family 02 00][port big-endian, 2B][IPv4, 4B][8B zero padding]
type AddrRecord struct {
	IP   net.IP
	Port int
}

func (a AddrRecord) String() string { return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port)) }

// ParseAddrRecords scans a decoded rendezvous payload at every byte offset for records
// with family 0x0002 and returns de-duplicated candidates in wire order.
func ParseAddrRecords(clear []byte) []AddrRecord {
	seen := map[string]bool{}
	var out []AddrRecord
	for i := 0; i+8 <= len(clear); i++ {
		if clear[i] != 0x02 || clear[i+1] != 0x00 {
			continue
		}
		port := int(clear[i+2])<<8 | int(clear[i+3])
		ip := net.IPv4(clear[i+4], clear[i+5], clear[i+6], clear[i+7]).To4()
		if port == 0 || ip == nil || ip[0] == 0 || ip[0] == 255 {
			continue
		}
		key := fmt.Sprintf("%s:%d", ip, port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, AddrRecord{IP: ip, Port: port})
	}
	return out
}
